using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BKE.Licensing.Client;

internal sealed record AgentServerEvidence(
    int ProcessId,
    long StartedUtcTicks,
    string ImagePath,
    string UserSid);

internal sealed record AgentServerTrustResult(
    bool IsTrusted,
    string Reason,
    AgentServerEvidence? Evidence = null)
{
    public static AgentServerTrustResult Trusted(AgentServerEvidence evidence) =>
        new(true, "trusted", evidence);

    public static AgentServerTrustResult Untrusted(string reason) =>
        new(false, reason, null);
}

internal interface IAgentServerTrustValidator
{
    AgentServerTrustResult ValidateConnectedServer(SafePipeHandle pipeHandle, string pipeName);
    AgentServerTrustResult ValidateLiveServer(SafePipeHandle pipeHandle, AgentServerEvidence initialEvidence);
}

/// <summary>
/// Production fail-closed Windows kernel and service trust validator for BKE Licensing Agent.
/// Verifies connected named pipe server process ID, executable provenance under Program Files,
/// privileged service identity (LocalSystem or Builtin Administrators), and protects against
/// PID reuse / TOCTOU replacement.
/// </summary>
internal sealed class WindowsAgentServerTrustValidator : IAgentServerTrustValidator
{
    public static readonly WindowsAgentServerTrustValidator Instance = new();

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenUser = 1;

    private const string LocalSystemSid = "S-1-5-18";
    private const string BuiltinAdministratorsSid = "S-1-5-32-544";

    private WindowsAgentServerTrustValidator() { }

    public AgentServerTrustResult ValidateConnectedServer(SafePipeHandle pipeHandle, string pipeName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return AgentServerTrustResult.Untrusted("platform_not_supported");
        }

        if (pipeHandle.IsInvalid || pipeHandle.IsClosed)
        {
            return AgentServerTrustResult.Untrusted("invalid_pipe_handle");
        }

        // 1. Enforce canonical pipe name
        if (!string.Equals(pipeName, ProductStartupOptions.DefaultPipeName, StringComparison.Ordinal))
        {
            return AgentServerTrustResult.Untrusted("untrusted_pipe_name");
        }

        // 2. Retrieve connected server process ID from kernel
        if (!GetNamedPipeServerProcessId(pipeHandle, out uint serverPid) || serverPid == 0 || serverPid > int.MaxValue)
        {
            return AgentServerTrustResult.Untrusted("server_pid_unavailable");
        }

        var pid = (int)serverPid;
        if (pid == Environment.ProcessId)
        {
            return AgentServerTrustResult.Untrusted("server_is_self");
        }

        // 3. Inspect server process
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            return AgentServerTrustResult.Untrusted("server_process_open_denied");
        }

        try
        {
            // 4. Capture process start timestamp (anti-PID reuse)
            if (!GetProcessTimes(hProcess, out long creationTicks, out _, out _, out _))
            {
                return AgentServerTrustResult.Untrusted("server_times_unavailable");
            }

            // 5. Query full server image path
            var sb = new StringBuilder(2048);
            int size = sb.Capacity;
            if (!QueryFullProcessImageName(hProcess, 0, sb, ref size))
            {
                return AgentServerTrustResult.Untrusted("server_image_path_unavailable");
            }

            var imagePath = Path.GetFullPath(sb.ToString());

            // 6. Query process token user SID
            var userSid = GetProcessUserSid(hProcess);
            if (string.IsNullOrWhiteSpace(userSid))
            {
                return AgentServerTrustResult.Untrusted("server_user_sid_unavailable");
            }

            // 7. Verify executable provenance: must reside within Program Files Agent directory
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var expectedRoot = Path.Combine(programFiles, "BKE Digital Solutions", "Licensing Agent");
            var expectedRootX86 = !string.IsNullOrWhiteSpace(programFilesX86)
                ? Path.Combine(programFilesX86, "BKE Digital Solutions", "Licensing Agent")
                : null;

            bool inProgramFiles = IsSubpathOf(imagePath, expectedRoot) ||
                (expectedRootX86 is not null && IsSubpathOf(imagePath, expectedRootX86));

            if (!inProgramFiles)
            {
                return AgentServerTrustResult.Untrusted("server_outside_trusted_program_files");
            }

            // Verify executable filename against genuine Agent components:
            // 1. bke-licensing-agent-service.exe: production Windows Service binary
            // 2. bke-licensing-agent-runtime.exe: runtime-bridge host hosting the named pipe service
            // 3. bke-licensing-agent.exe: monolithic Agent executable
            // 4. BKE.LicensingAgent.Host.exe: nonproduction/certification Agent Host bootstrap
            var exeName = Path.GetFileName(imagePath);
            var isPermittedExe = string.Equals(exeName, "bke-licensing-agent-runtime.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(exeName, "bke-licensing-agent-service.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(exeName, "bke-licensing-agent.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(exeName, "BKE.LicensingAgent.Host.exe", StringComparison.OrdinalIgnoreCase);

            if (!isPermittedExe)
            {
                return AgentServerTrustResult.Untrusted("server_untrusted_executable_name");
            }

            // Anti-reparse point check on server binary to reject symlinks and junctions
            try
            {
                var fileInfo = new FileInfo(imagePath);
                if ((fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return AgentServerTrustResult.Untrusted("server_image_is_reparse_point");
                }
            }
            catch
            {
                return AgentServerTrustResult.Untrusted("server_image_attributes_inaccessible");
            }

            // 8. Verify privileged service identity
            if (!string.Equals(userSid, LocalSystemSid, StringComparison.Ordinal) &&
                !string.Equals(userSid, BuiltinAdministratorsSid, StringComparison.Ordinal))
            {
                return AgentServerTrustResult.Untrusted("server_untrusted_identity_sid");
            }

            return AgentServerTrustResult.Trusted(new AgentServerEvidence(pid, creationTicks, imagePath, userSid));
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    public AgentServerTrustResult ValidateLiveServer(SafePipeHandle pipeHandle, AgentServerEvidence initialEvidence)
    {
        if (!OperatingSystem.IsWindows() || pipeHandle.IsInvalid || pipeHandle.IsClosed)
        {
            return AgentServerTrustResult.Untrusted("pipe_closed");
        }

        // Re-query server PID
        if (!GetNamedPipeServerProcessId(pipeHandle, out uint currentPid) || (int)currentPid != initialEvidence.ProcessId)
        {
            return AgentServerTrustResult.Untrusted("server_pid_changed_mid_flight");
        }

        // Verify server process is still alive and has not been replaced (TOCTOU protection)
        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, initialEvidence.ProcessId);
        if (hProcess == IntPtr.Zero)
        {
            return AgentServerTrustResult.Untrusted("server_process_terminated");
        }

        try
        {
            if (!GetProcessTimes(hProcess, out long creationTicks, out _, out _, out _) ||
                creationTicks != initialEvidence.StartedUtcTicks)
            {
                return AgentServerTrustResult.Untrusted("server_process_reused");
            }

            return AgentServerTrustResult.Trusted(initialEvidence);
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    private static bool IsSubpathOf(string candidatePath, string parentDir)
    {
        var normParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parentDir)) + Path.DirectorySeparatorChar;
        var normCandidate = Path.GetFullPath(candidatePath);
        return normCandidate.StartsWith(normParent, StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetProcessUserSid(IntPtr hProcess)
    {
        if (!OpenProcessToken(hProcess, TOKEN_QUERY, out IntPtr hToken))
        {
            return null;
        }

        try
        {
            GetTokenInformation(hToken, TokenUser, IntPtr.Zero, 0, out uint reqLen);
            if (reqLen == 0) return null;

            var buf = Marshal.AllocHGlobal((int)reqLen);
            try
            {
                if (!GetTokenInformation(hToken, TokenUser, buf, reqLen, out _))
                {
                    return null;
                }

                IntPtr pSid = Marshal.ReadIntPtr(buf);
                if (!ConvertSidToStringSid(pSid, out IntPtr pStringSid))
                {
                    return null;
                }

                try
                {
                    return Marshal.PtrToStringAuto(pStringSid);
                }
                finally
                {
                    LocalFree(pStringSid);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        finally
        {
            CloseHandle(hToken);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle hPipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr hProcess, out long lpCreationTime, out long lpExitTime, out long lpKernelTime, out long lpUserTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr ptrSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}

/// <summary>
/// Strictly internal test-only server trust validator.
/// Verifies OS-observed server PID, creation ticks, and live status to guard against TOCTOU,
/// while allowing test runners to designate an attested server process.
/// </summary>
internal sealed class TestAgentServerTrustValidator : IAgentServerTrustValidator
{
    private readonly Func<int, string, bool> _processPredicate;

    public TestAgentServerTrustValidator(Func<int, string, bool>? processPredicate = null)
    {
        _processPredicate = processPredicate ?? ((_, _) => true);
    }

    public static TestAgentServerTrustValidator AllowAnyAttestedLiveProcess() =>
        new((_, _) => true);

    public static TestAgentServerTrustValidator AllowProcessId(int allowedPid) =>
        new((pid, _) => pid == allowedPid);

    public AgentServerTrustResult ValidateConnectedServer(SafePipeHandle pipeHandle, string pipeName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return AgentServerTrustResult.Untrusted("platform_not_supported");
        }

        if (pipeHandle.IsInvalid || pipeHandle.IsClosed)
        {
            return AgentServerTrustResult.Untrusted("invalid_pipe_handle");
        }

        if (!GetNamedPipeServerProcessId(pipeHandle, out uint serverPid) || serverPid == 0 || serverPid > int.MaxValue)
        {
            return AgentServerTrustResult.Untrusted("server_pid_unavailable");
        }

        var pid = (int)serverPid;
        var hProcess = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (hProcess == IntPtr.Zero)
        {
            return AgentServerTrustResult.Untrusted("server_process_open_denied");
        }

        try
        {
            if (!GetProcessTimes(hProcess, out long creationTicks, out _, out _, out _))
            {
                return AgentServerTrustResult.Untrusted("server_times_unavailable");
            }

            var sb = new StringBuilder(2048);
            int size = sb.Capacity;
            var imagePath = QueryFullProcessImageName(hProcess, 0, sb, ref size)
                ? sb.ToString()
                : "unknown";

            if (!_processPredicate(pid, imagePath))
            {
                return AgentServerTrustResult.Untrusted("server_process_predicate_rejected");
            }

            return AgentServerTrustResult.Trusted(new AgentServerEvidence(pid, creationTicks, imagePath, "test-sid"));
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    public AgentServerTrustResult ValidateLiveServer(SafePipeHandle pipeHandle, AgentServerEvidence initialEvidence)
    {
        if (!OperatingSystem.IsWindows() || pipeHandle.IsInvalid || pipeHandle.IsClosed)
        {
            return AgentServerTrustResult.Untrusted("pipe_closed");
        }

        if (!GetNamedPipeServerProcessId(pipeHandle, out uint currentPid) || (int)currentPid != initialEvidence.ProcessId)
        {
            return AgentServerTrustResult.Untrusted("server_pid_changed_mid_flight");
        }

        var hProcess = OpenProcess(0x1000, false, initialEvidence.ProcessId);
        if (hProcess == IntPtr.Zero)
        {
            return AgentServerTrustResult.Untrusted("server_process_terminated");
        }

        try
        {
            if (!GetProcessTimes(hProcess, out long creationTicks, out _, out _, out _) ||
                creationTicks != initialEvidence.StartedUtcTicks)
            {
                return AgentServerTrustResult.Untrusted("server_process_reused");
            }

            return AgentServerTrustResult.Trusted(initialEvidence);
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle hPipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr hProcess, out long lpCreationTime, out long lpExitTime, out long lpKernelTime, out long lpUserTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
