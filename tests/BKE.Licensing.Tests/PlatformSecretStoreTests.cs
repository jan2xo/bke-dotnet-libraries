using System.Diagnostics;
using System.Text;
using BKE.Licensing.Contracts;
using BKE.Licensing.Platform;
using BKE.Licensing.Platform.MacOS;
using BKE.Licensing.Platform.Windows;

namespace BKE.Licensing.Tests;

public sealed class PlatformSecretStoreTests
{
    [Fact]
    public void NonNativeStores_ThrowPlatformNotSupported()
    {
#pragma warning disable CA1416 // Intentionally verifies runtime off-platform fail-closed guards.
        if (!OperatingSystem.IsWindows())
        {
            Assert.Throws<PlatformNotSupportedException>(() =>
                new WindowsDpapiSecretStore(Path.GetTempPath(), "test.scope"));
        }

        if (!OperatingSystem.IsMacOS())
        {
            Assert.Throws<PlatformNotSupportedException>(() =>
                new MacOsKeychainSecretStore(Path.GetTempPath(), "bke.test.scope"));
        }
#pragma warning restore CA1416
    }

    [Fact]
    public void MacOsKeychainSecretStore_RoundTrips_DetectsTamper_And_EnforcesFileMode()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return;
        }

        var tempDir = Directory.CreateTempSubdirectory("bke-kc-test-").FullName;
        var keychainPath = Path.Combine(tempDir, "test.keychain-db");
        try
        {
            RunSecurity("create-keychain", "-p", "ephemeral-ci-pass", keychainPath);
            RunSecurity("unlock-keychain", "-p", "ephemeral-ci-pass", keychainPath);

            ISecureSecretStore store = PlatformSecretStoreFactory.CreateForCurrentPlatform(
                Path.Combine(tempDir, "secrets"),
                "bke.licensing.test." + Guid.NewGuid().ToString("N"),
                keychainPath);

            var payload = Encoding.UTF8.GetBytes("refresh_token=bke_secret_001");
            store.WriteSecret("agent-session", payload);

            var roundTripped = store.ReadSecret("agent-session");
            Assert.NotNull(roundTripped);
            Assert.Equal("refresh_token=bke_secret_001", Encoding.UTF8.GetString(roundTripped!));

            var binPath = Path.Combine(tempDir, "secrets", "agent-session.kc.bin");
            var mode = File.GetUnixFileMode(binPath);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);

            // Tamper with ciphertext/tag byte and ensure decryption fails closed.
            var bytes = File.ReadAllBytes(binPath);
            bytes[^1] ^= 0xFF;
            File.WriteAllBytes(binPath, bytes);
            Assert.Throws<SecureSecretStorageException>(() => store.ReadSecret("agent-session"));

            // Reject traversal names.
            Assert.Throws<ArgumentException>(() => store.ReadSecret("../escape"));

            store.DeleteSecret("agent-session");
            Assert.Null(store.ReadSecret("agent-session"));
        }
        finally
        {
            TryRunSecurity("delete-keychain", keychainPath);
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void WindowsDpapiSecretStore_RoundTrips_And_DetectsTamper()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var tempDir = Directory.CreateTempSubdirectory("bke-dpapi-test-").FullName;
        try
        {
            var store = PlatformSecretStoreFactory.CreateForCurrentPlatform(
                tempDir,
                "bke.licensing.test." + Guid.NewGuid().ToString("N"));
            var payload = Encoding.UTF8.GetBytes("dpapi_secret=bke_win_001");
            store.WriteSecret("agent-session", payload);

            var decrypted = store.ReadSecret("agent-session");
            Assert.NotNull(decrypted);
            Assert.Equal("dpapi_secret=bke_win_001", Encoding.UTF8.GetString(decrypted!));

            var binPath = Path.Combine(tempDir, "agent-session.dpapi.bin");
            var raw = File.ReadAllBytes(binPath);
            raw[^1] ^= 0x5A;
            File.WriteAllBytes(binPath, raw);
            Assert.Throws<SecureSecretStorageException>(() => store.ReadSecret("agent-session"));

            Assert.Throws<ArgumentException>(() => store.WriteSecret("bad/name", payload));

            store.DeleteSecret("agent-session");
            Assert.Null(store.ReadSecret("agent-session"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    private static void RunSecurity(params string[] args)
    {
        var psi = new ProcessStartInfo("/usr/bin/security")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var proc = Process.Start(psi)!;
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException($"security exited {proc.ExitCode}: {stderr}");
        }
    }

    private static void TryRunSecurity(params string[] args)
    {
        try
        {
            RunSecurity(args);
        }
        catch (Exception)
        {
        }
    }
}
