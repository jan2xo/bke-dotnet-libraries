using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BKE.Licensing.Contracts;

namespace BKE.Licensing.Platform.MacOS;

[SupportedOSPlatform("macos")]
public sealed partial class MacOsKeychainSecretStore : ISecureSecretStore
{
    private const string SecurityFramework = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundationFramework = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const int ErrSecSuccess = 0;
    private const int ErrSecDuplicateItem = -25299;
    private const int ErrSecItemNotFound = -25300;

    private const string KeychainMasterAccount = "bke.licensing.wrapping-key.v1";
    private const int MasterKeySizeBytes = 32;
    private const int MagicLength = 6;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private static readonly byte[] EnvelopeMagic = "BKEKC1"u8.ToArray();

    private readonly string _storeDirectory;
    private readonly string _serviceName;
    private readonly string? _keychainPath;

    public MacOsKeychainSecretStore(
        string storeDirectory,
        string serviceName,
        string? keychainPath = null)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("MacOsKeychainSecretStore requires macOS Keychain Services.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(storeDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        if (!SafeIdentifier().IsMatch(serviceName))
        {
            throw new ArgumentException("Service name contains unsupported characters.", nameof(serviceName));
        }

        _storeDirectory = Path.GetFullPath(storeDirectory);
        _serviceName = serviceName;
        _keychainPath = string.IsNullOrWhiteSpace(keychainPath) ? null : Path.GetFullPath(keychainPath);
        Directory.CreateDirectory(_storeDirectory);
        File.SetUnixFileMode(
            _storeDirectory,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    public void WriteSecret(string name, ReadOnlySpan<byte> secret)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("MacOsKeychainSecretStore requires macOS Keychain Services.");
        }

        var path = ResolveSafePath(name);
        var masterKey = GetOrCreateMasterKey();
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var tag = new byte[TagLength];
        var ciphertext = new byte[secret.Length];
        var aad = Encoding.UTF8.GetBytes($"{_serviceName}\n{name}");
        var sealedBlob = new byte[MagicLength + NonceLength + TagLength + ciphertext.Length];

        try
        {
            using (var aes = new AesGcm(masterKey, TagLength))
            {
                aes.Encrypt(nonce, secret, ciphertext, tag, aad);
            }

            EnvelopeMagic.CopyTo(sealedBlob, 0);
            nonce.CopyTo(sealedBlob, MagicLength);
            tag.CopyTo(sealedBlob, MagicLength + NonceLength);
            ciphertext.CopyTo(sealedBlob, MagicLength + NonceLength + TagLength);

            var tmpPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllBytes(tmpPath, sealedBlob);
            File.SetUnixFileMode(tmpPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(tmpPath, path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(sealedBlob);
        }
    }

    public byte[]? ReadSecret(string name)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("MacOsKeychainSecretStore requires macOS Keychain Services.");
        }

        var path = ResolveSafePath(name);
        if (!File.Exists(path))
        {
            return null;
        }

        var sealedBlob = File.ReadAllBytes(path);
        if (sealedBlob.Length < MagicLength + NonceLength + TagLength ||
            !sealedBlob.AsSpan(0, MagicLength).SequenceEqual(EnvelopeMagic))
        {
            throw new SecureSecretStorageException("Corrupted sealed secret envelope.");
        }

        var masterKey = TryReadMasterKey()
            ?? throw new SecureSecretStorageException("macOS Keychain wrapping key is unavailable.");

        var nonce = sealedBlob.AsSpan(MagicLength, NonceLength);
        var tag = sealedBlob.AsSpan(MagicLength + NonceLength, TagLength);
        var ciphertext = sealedBlob.AsSpan(MagicLength + NonceLength + TagLength);
        var plaintext = new byte[ciphertext.Length];
        var aad = Encoding.UTF8.GetBytes($"{_serviceName}\n{name}");

        try
        {
            using var aes = new AesGcm(masterKey, TagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new SecureSecretStorageException("Failed to authenticate sealed macOS Keychain secret.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(sealedBlob);
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

    public void DeleteWrappingKeyFromKeychain()
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("MacOsKeychainSecretStore requires macOS Keychain Services.");
        }

        var serviceBytes = Encoding.UTF8.GetBytes(_serviceName);
        var accountBytes = Encoding.UTF8.GetBytes(KeychainMasterAccount);

        var keychainRef = OpenKeychainOrDefault();
        var itemRef = IntPtr.Zero;
        var passwordData = IntPtr.Zero;
        uint passwordLength = 0;
        try
        {
            var findStatus = SecKeychainFindGenericPassword(
                keychainRef,
                (uint)serviceBytes.Length,
                serviceBytes,
                (uint)accountBytes.Length,
                accountBytes,
                out passwordLength,
                out passwordData,
                out itemRef);

            if (findStatus == ErrSecItemNotFound)
            {
                return;
            }

            if (findStatus != ErrSecSuccess)
            {
                throw new SecureSecretStorageException($"macOS Keychain delete lookup failed with OSStatus {findStatus}.");
            }

            var deleteStatus = SecKeychainItemDelete(itemRef);
            if (deleteStatus != ErrSecSuccess && deleteStatus != ErrSecItemNotFound)
            {
                throw new SecureSecretStorageException($"macOS Keychain wrapping-key delete failed with OSStatus {deleteStatus}.");
            }
        }
        finally
        {
            ZeroAndFreeKeychainBuffer(passwordData, passwordLength);
            ReleaseCf(itemRef);
            ReleaseCf(keychainRef);
        }
    }

    private byte[] GetOrCreateMasterKey()
    {
        var existing = TryReadMasterKey();
        if (existing is not null)
        {
            return existing;
        }

        var generated = RandomNumberGenerator.GetBytes(MasterKeySizeBytes);
        var serviceBytes = Encoding.UTF8.GetBytes(_serviceName);
        var accountBytes = Encoding.UTF8.GetBytes(KeychainMasterAccount);

        var keychainRef = IntPtr.Zero;
        var addedItemRef = IntPtr.Zero;
        var keyTransferred = false;

        try
        {
            keychainRef = OpenKeychainOrDefault();
            var addStatus = SecKeychainAddGenericPassword(
                keychainRef,
                (uint)serviceBytes.Length,
                serviceBytes,
                (uint)accountBytes.Length,
                accountBytes,
                (uint)generated.Length,
                generated,
                out addedItemRef);

            if (addStatus == ErrSecDuplicateItem)
            {
                return TryReadMasterKey()
                    ?? throw new SecureSecretStorageException("macOS Keychain wrapping key was unavailable after duplicate-item response.");
            }

            if (addStatus != ErrSecSuccess)
            {
                throw new SecureSecretStorageException($"macOS Keychain wrapping-key store failed with OSStatus {addStatus}.");
            }

            keyTransferred = true;
            return generated;
        }
        finally
        {
            if (!keyTransferred)
            {
                CryptographicOperations.ZeroMemory(generated);
            }

            ReleaseCf(addedItemRef);
            ReleaseCf(keychainRef);
        }
    }

    private byte[]? TryReadMasterKey()
    {
        var serviceBytes = Encoding.UTF8.GetBytes(_serviceName);
        var accountBytes = Encoding.UTF8.GetBytes(KeychainMasterAccount);

        var keychainRef = OpenKeychainOrDefault();
        var itemRef = IntPtr.Zero;
        var passwordData = IntPtr.Zero;
        uint passwordLength = 0;

        try
        {
            var status = SecKeychainFindGenericPassword(
                keychainRef,
                (uint)serviceBytes.Length,
                serviceBytes,
                (uint)accountBytes.Length,
                accountBytes,
                out passwordLength,
                out passwordData,
                out itemRef);

            if (status == ErrSecItemNotFound)
            {
                return null;
            }

            if (status != ErrSecSuccess)
            {
                throw new SecureSecretStorageException($"macOS Keychain lookup failed with OSStatus {status}.");
            }

            if (passwordData == IntPtr.Zero ||
                (passwordLength != MasterKeySizeBytes && passwordLength != MasterKeySizeBytes * 2))
            {
                throw new SecureSecretStorageException("macOS Keychain wrapping key has invalid length.");
            }

            var rawBytes = new byte[passwordLength];
            try
            {
                Marshal.Copy(passwordData, rawBytes, 0, rawBytes.Length);
                if (rawBytes.Length == MasterKeySizeBytes)
                {
                    var key = new byte[MasterKeySizeBytes];
                    rawBytes.CopyTo(key, 0);
                    return key;
                }

                // Preserve read compatibility for existing 64-byte ASCII hex entries created by prior releases
                // without allocating a managed string.
                return DecodeAsciiHexKey(rawBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rawBytes);
            }
        }
        finally
        {
            ZeroAndFreeKeychainBuffer(passwordData, passwordLength);
            ReleaseCf(itemRef);
            ReleaseCf(keychainRef);
        }
    }

    private static byte[] DecodeAsciiHexKey(ReadOnlySpan<byte> hexBytes)
    {
        var decoded = new byte[MasterKeySizeBytes];
        for (var i = 0; i < MasterKeySizeBytes; i++)
        {
            var hi = ParseHexNibble(hexBytes[i * 2]);
            var lo = ParseHexNibble(hexBytes[(i * 2) + 1]);
            if (hi < 0 || lo < 0)
            {
                CryptographicOperations.ZeroMemory(decoded);
                throw new SecureSecretStorageException("macOS Keychain wrapping key format is invalid.");
            }

            decoded[i] = (byte)((hi << 4) | lo);
        }

        return decoded;
    }

    private static int ParseHexNibble(byte ascii) => ascii switch
    {
        >= (byte)'0' and <= (byte)'9' => ascii - '0',
        >= (byte)'a' and <= (byte)'f' => ascii - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => ascii - 'A' + 10,
        _ => -1,
    };

    private IntPtr OpenKeychainOrDefault()
    {
        if (_keychainPath is null)
        {
            return IntPtr.Zero;
        }

        var status = SecKeychainOpen(_keychainPath, out var keychainRef);
        if (status != ErrSecSuccess || keychainRef == IntPtr.Zero)
        {
            ReleaseCf(keychainRef);
            throw new SecureSecretStorageException($"macOS Keychain open failed with OSStatus {status}.");
        }

        return keychainRef;
    }

    private static void ZeroAndFreeKeychainBuffer(IntPtr data, uint length)
    {
        if (data == IntPtr.Zero)
        {
            return;
        }

        for (var i = 0; i < (int)length; i++)
        {
            Marshal.WriteByte(data, i, 0);
        }

        _ = SecKeychainItemFreeContent(IntPtr.Zero, data);
    }

    private static void ReleaseCf(IntPtr cf)
    {
        if (cf != IntPtr.Zero)
        {
            CFRelease(cf);
        }
    }

    [DllImport(SecurityFramework, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int SecKeychainOpen(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string pathName,
        out IntPtr keychain);

    [DllImport(SecurityFramework, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int SecKeychainAddGenericPassword(
        IntPtr keychain,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        uint passwordLength,
        byte[] passwordData,
        out IntPtr itemRef);

    [DllImport(SecurityFramework, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int SecKeychainFindGenericPassword(
        IntPtr keychainOrArray,
        uint serviceNameLength,
        byte[] serviceName,
        uint accountNameLength,
        byte[] accountName,
        out uint passwordLength,
        out IntPtr passwordData,
        out IntPtr itemRef);

    [DllImport(SecurityFramework, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int SecKeychainItemDelete(IntPtr itemRef);

    [DllImport(SecurityFramework, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern int SecKeychainItemFreeContent(IntPtr attrList, IntPtr data);

    [DllImport(CoreFoundationFramework, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static extern void CFRelease(IntPtr cf);

    private string ResolveSafePath(string name)
    {
        if (string.IsNullOrEmpty(name) || !SafeIdentifier().IsMatch(name))
        {
            throw new ArgumentException("Secret name contains unsupported characters.", nameof(name));
        }

        return Path.Combine(_storeDirectory, name + ".kc.bin");
    }

    [GeneratedRegex("^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdentifier();
}
