using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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

            var secretsDir = Path.Combine(tempDir, "secrets");
            var serviceName = "bke.licensing.test." + Guid.NewGuid().ToString("N");
            var concreteStore = new MacOsKeychainSecretStore(secretsDir, serviceName, keychainPath);
            ISecureSecretStore store = concreteStore;

            var payload = Encoding.UTF8.GetBytes("refresh_token=bke_secret_001");
            store.WriteSecret("agent-session", payload);

            // Re-open with a separate store instance to prove persistent Keychain-backed round-trip.
            ISecureSecretStore readerStore = new MacOsKeychainSecretStore(secretsDir, serviceName, keychainPath);
            var roundTripped = readerStore.ReadSecret("agent-session");
            Assert.NotNull(roundTripped);
            Assert.Equal("refresh_token=bke_secret_001", Encoding.UTF8.GetString(roundTripped!));

            // Confirm Keychain stores raw 32-byte binary key material, not ASCII hex, and collect key bytes for leak checks.
            var storedKeyItem = ReadRawKeychainItem(keychainPath, serviceName, "bke.licensing.wrapping-key.v1");
            Assert.Equal(32, storedKeyItem.Length);

            var binPath = Path.Combine(secretsDir, "agent-session.kc.bin");
            var mode = File.GetUnixFileMode(binPath);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);

            // Tamper with ciphertext/tag byte and ensure decryption fails closed without leaking key material.
            var bytes = File.ReadAllBytes(binPath);
            bytes[^1] ^= 0xFF;
            File.WriteAllBytes(binPath, bytes);
            var tamperEx = Assert.Throws<SecureSecretStorageException>(() => readerStore.ReadSecret("agent-session"));
            AssertNoKeyLeak(tamperEx.ToString(), storedKeyItem);

            // Re-write valid secret, then delete Keychain wrapping key while .kc.bin still exists: must fail closed.
            store.WriteSecret("agent-session", payload);
            concreteStore.DeleteWrappingKeyFromKeychain();
            var missingKeyEx = Assert.Throws<SecureSecretStorageException>(() => readerStore.ReadSecret("agent-session"));
            AssertNoKeyLeak(missingKeyEx.ToString(), storedKeyItem);

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
    public void MacOsKeychainSecretStore_ReadsLegacyHexKeychainStorage_WithoutMigrationLoss()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return;
        }

        var tempDir = Directory.CreateTempSubdirectory("bke-kc-legacy-").FullName;
        var keychainPath = Path.Combine(tempDir, "legacy.keychain-db");
        try
        {
            RunSecurity("create-keychain", "-p", "ephemeral-ci-pass", keychainPath);
            RunSecurity("unlock-keychain", "-p", "ephemeral-ci-pass", keychainPath);

            var secretsDir = Path.Combine(tempDir, "secrets");
            Directory.CreateDirectory(secretsDir);
            var serviceName = "bke.licensing.legacy." + Guid.NewGuid().ToString("N");

            // Seed a legacy 64-byte ASCII hex wrapping key directly into Keychain Services and seal a BKEKC1 envelope.
            var legacyKey = RandomNumberGenerator.GetBytes(32);
            var legacyHexBytes = Encoding.ASCII.GetBytes(Convert.ToHexStringLower(legacyKey));
            WriteRawKeychainItem(keychainPath, serviceName, "bke.licensing.wrapping-key.v1", legacyHexBytes);

            var plaintext = "legacy_refresh_token=bke_compat_001"u8.ToArray();
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var ciphertext = new byte[plaintext.Length];
            var aad = Encoding.UTF8.GetBytes($"{serviceName}\nagent-session");
            using (var aes = new AesGcm(legacyKey, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            }

            var sealedBlob = new byte[6 + 12 + 16 + ciphertext.Length];
            "BKEKC1"u8.CopyTo(sealedBlob);
            nonce.CopyTo(sealedBlob, 6);
            tag.CopyTo(sealedBlob, 18);
            ciphertext.CopyTo(sealedBlob, 34);
            var binPath = Path.Combine(secretsDir, "agent-session.kc.bin");
            File.WriteAllBytes(binPath, sealedBlob);
            File.SetUnixFileMode(binPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var store = new MacOsKeychainSecretStore(secretsDir, serviceName, keychainPath);
            var readBack = store.ReadSecret("agent-session");
            Assert.NotNull(readBack);
            Assert.Equal("legacy_refresh_token=bke_compat_001", Encoding.UTF8.GetString(readBack!));

            // Subsequent writes under the same legacy Keychain entry also round-trip cleanly.
            store.WriteSecret("rotated-session", "rotated_value=002"u8);
            Assert.Equal("rotated_value=002", Encoding.UTF8.GetString(store.ReadSecret("rotated-session")!));
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
    public void MacOsKeychainSecretStore_DoesNotReferenceProcessSubprocessApis()
    {
        var assemblyPath = typeof(MacOsKeychainSecretStore).Assembly.Location;
        Assert.False(string.IsNullOrEmpty(assemblyPath));

        using var stream = File.OpenRead(assemblyPath);
        using var peReader = new PEReader(stream);
        var metadata = peReader.GetMetadataReader();

        foreach (var handle in metadata.TypeReferences)
        {
            var typeRef = metadata.GetTypeReference(handle);
            var ns = metadata.GetString(typeRef.Namespace);
            var name = metadata.GetString(typeRef.Name);
            Assert.False(
                ns == "System.Diagnostics" && (name == "Process" || name == "ProcessStartInfo"),
                "BKE.Licensing.Platform must not spawn external subprocesses for secret storage.");
        }

        var assemblyBytes = File.ReadAllBytes(assemblyPath);
        Assert.Equal(-1, assemblyBytes.AsSpan().IndexOf("/usr/bin/security"u8));
        Assert.Equal(-1, assemblyBytes.AsSpan().IndexOf(Encoding.Unicode.GetBytes("/usr/bin/security")));
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

    private static void AssertNoKeyLeak(string diagnosticOutput, byte[] keyBytes)
    {
        Assert.DoesNotContain(Convert.ToHexStringLower(keyBytes), diagnosticOutput, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(keyBytes), diagnosticOutput, StringComparison.Ordinal);
    }

    private static byte[] ReadRawKeychainItem(string keychainPath, string service, string account)
    {
        var serviceBytes = Encoding.UTF8.GetBytes(service);
        var accountBytes = Encoding.UTF8.GetBytes(account);
        Assert.Equal(0, TestSecKeychainOpen(keychainPath, out var keychainRef));
        var itemRef = IntPtr.Zero;
        var dataPtr = IntPtr.Zero;
        try
        {
            var status = TestSecKeychainFindGenericPassword(
                keychainRef,
                (uint)serviceBytes.Length,
                serviceBytes,
                (uint)accountBytes.Length,
                accountBytes,
                out var length,
                out dataPtr,
                out itemRef);
            Assert.Equal(0, status);
            var result = new byte[length];
            Marshal.Copy(dataPtr, result, 0, result.Length);
            return result;
        }
        finally
        {
            if (dataPtr != IntPtr.Zero)
            {
                _ = TestSecKeychainItemFreeContent(IntPtr.Zero, dataPtr);
            }

            if (itemRef != IntPtr.Zero)
            {
                TestCFRelease(itemRef);
            }

            if (keychainRef != IntPtr.Zero)
            {
                TestCFRelease(keychainRef);
            }
        }
    }

    private static void WriteRawKeychainItem(string keychainPath, string service, string account, byte[] data)
    {
        var serviceBytes = Encoding.UTF8.GetBytes(service);
        var accountBytes = Encoding.UTF8.GetBytes(account);
        Assert.Equal(0, TestSecKeychainOpen(keychainPath, out var keychainRef));
        var itemRef = IntPtr.Zero;
        try
        {
            var status = TestSecKeychainAddGenericPassword(
                keychainRef,
                (uint)serviceBytes.Length,
                serviceBytes,
                (uint)accountBytes.Length,
                accountBytes,
                (uint)data.Length,
                data,
                out itemRef);
            Assert.Equal(0, status);
        }
        finally
        {
            if (itemRef != IntPtr.Zero)
            {
                TestCFRelease(itemRef);
            }

            if (keychainRef != IntPtr.Zero)
            {
                TestCFRelease(keychainRef);
            }
        }
    }

    [DllImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecKeychainOpen", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int TestSecKeychainOpen(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string pathName,
        out IntPtr keychain);

    [DllImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecKeychainAddGenericPassword", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int TestSecKeychainAddGenericPassword(
        IntPtr keychain,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        uint passwordLength,
        byte[] passwordData,
        out IntPtr itemRef);

    [DllImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecKeychainFindGenericPassword", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int TestSecKeychainFindGenericPassword(
        IntPtr keychainOrArray,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        out uint passwordLength,
        out IntPtr passwordData,
        out IntPtr itemRef);

    [DllImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecKeychainItemFreeContent", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int TestSecKeychainItemFreeContent(IntPtr attrList, IntPtr data);

    [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFRelease", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern void TestCFRelease(IntPtr cf);
}
