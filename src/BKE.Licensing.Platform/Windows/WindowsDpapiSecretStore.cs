using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BKE.Licensing.Contracts;

namespace BKE.Licensing.Platform.Windows;

[SupportedOSPlatform("windows")]
public sealed partial class WindowsDpapiSecretStore : ISecureSecretStore
{
    private const int CryptProtectUiForbidden = 0x1;
    private readonly string _storeDirectory;
    private readonly byte[] _entropy;

    public WindowsDpapiSecretStore(string storeDirectory, string scopeName)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("WindowsDpapiSecretStore requires Windows DPAPI.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(storeDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeName);

        _storeDirectory = Path.GetFullPath(storeDirectory);
        _entropy = SHA256.HashData(Encoding.UTF8.GetBytes($"bke.licensing.dpapi.v1:{scopeName}"));
        Directory.CreateDirectory(_storeDirectory);
    }

    public void WriteSecret(string name, ReadOnlySpan<byte> secret)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("WindowsDpapiSecretStore requires Windows DPAPI.");
        }

        var path = ResolveSafePath(name);
        Directory.CreateDirectory(_storeDirectory);
        var plaintext = secret.ToArray();
        byte[]? protectedBlob = null;
        try
        {
            protectedBlob = Protect(plaintext, _entropy);
            var tmpPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllBytes(tmpPath, protectedBlob);
            File.Move(tmpPath, path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBlob is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBlob);
            }
        }
    }

    public byte[]? ReadSecret(string name)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("WindowsDpapiSecretStore requires Windows DPAPI.");
        }

        var path = ResolveSafePath(name);
        if (!File.Exists(path))
        {
            return null;
        }

        var cipherBytes = File.ReadAllBytes(path);
        if (cipherBytes.Length == 0)
        {
            throw new SecureSecretStorageException("DPAPI secret file is empty.");
        }

        try
        {
            return Unprotect(cipherBytes, _entropy);
        }
        catch (Win32Exception ex)
        {
            throw new SecureSecretStorageException("Failed to decrypt Windows DPAPI secret.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cipherBytes);
        }
    }

    public void DeleteSecret(string name)
    {
        var path = ResolveSafePath(name);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private string ResolveSafePath(string name)
    {
        if (string.IsNullOrEmpty(name) || !SafeSecretName().IsMatch(name))
        {
            throw new ArgumentException("Secret name contains unsupported characters.", nameof(name));
        }

        return Path.Combine(_storeDirectory, name + ".dpapi.bin");
    }

    private static byte[] Protect(byte[] plaintext, byte[] entropy)
    {
        var inBlob = default(DataBlob);
        var entropyBlob = default(DataBlob);
        var outBlob = default(DataBlob);

        try
        {
            inBlob = AllocBlob(plaintext);
            entropyBlob = AllocBlob(entropy);
            if (!NativeMethods.CryptProtectData(
                    ref inBlob,
                    null,
                    ref entropyBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    ref outBlob))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            return result;
        }
        finally
        {
            FreeInputBlob(ref inBlob);
            FreeInputBlob(ref entropyBlob);
            if (outBlob.pbData != IntPtr.Zero)
            {
                NativeMethods.LocalFree(outBlob.pbData);
            }
        }
    }

    private static byte[] Unprotect(byte[] cipherBytes, byte[] entropy)
    {
        var inBlob = default(DataBlob);
        var entropyBlob = default(DataBlob);
        var outBlob = default(DataBlob);

        try
        {
            inBlob = AllocBlob(cipherBytes);
            entropyBlob = AllocBlob(entropy);
            if (!NativeMethods.CryptUnprotectData(
                    ref inBlob,
                    IntPtr.Zero,
                    ref entropyBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    ref outBlob))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            ZeroUnmanaged(outBlob.pbData, outBlob.cbData);
            return result;
        }
        finally
        {
            FreeInputBlob(ref inBlob);
            FreeInputBlob(ref entropyBlob);
            if (outBlob.pbData != IntPtr.Zero)
            {
                NativeMethods.LocalFree(outBlob.pbData);
            }
        }
    }

    private static DataBlob AllocBlob(byte[] bytes)
    {
        var ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return new DataBlob { cbData = bytes.Length, pbData = ptr };
    }

    private static void FreeInputBlob(ref DataBlob blob)
    {
        if (blob.pbData != IntPtr.Zero)
        {
            ZeroUnmanaged(blob.pbData, blob.cbData);
            Marshal.FreeHGlobal(blob.pbData);
            blob.pbData = IntPtr.Zero;
            blob.cbData = 0;
        }
    }

    private static void ZeroUnmanaged(IntPtr ptr, int length)
    {
        if (ptr == IntPtr.Zero || length <= 0)
        {
            return;
        }

        for (var i = 0; i < length; i++)
        {
            Marshal.WriteByte(ptr, i, 0);
        }
    }

    [GeneratedRegex("^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeSecretName();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    private static class NativeMethods
    {
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptProtectData(
            ref DataBlob pDataIn,
            string? szDataDescr,
            ref DataBlob pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            int dwFlags,
            ref DataBlob pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptUnprotectData(
            ref DataBlob pDataIn,
            IntPtr ppszDataDescr,
            ref DataBlob pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            int dwFlags,
            ref DataBlob pDataOut);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern IntPtr LocalFree(IntPtr hMem);
    }
}
