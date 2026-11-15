using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BKE.Licensing.Contracts;

namespace BKE.Licensing.Platform.MacOS;

[SupportedOSPlatform("macos")]
public sealed partial class MacOsKeychainSecretStore : ISecureSecretStore
{
    private const string KeychainMasterAccount = "bke.licensing.wrapping-key.v1";
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

        var args = new List<string>
        {
            "delete-generic-password",
            "-s", _serviceName,
            "-a", KeychainMasterAccount,
        };
        if (_keychainPath is not null)
        {
            args.Add(_keychainPath);
        }

        RunSecurityCli(args, allowNotFound: true);
    }

    private byte[] GetOrCreateMasterKey()
    {
        var existing = TryReadMasterKey();
        if (existing is not null)
        {
            return existing;
        }

        var generated = RandomNumberGenerator.GetBytes(32);
        var hex = Convert.ToHexStringLower(generated);
        var args = new List<string>
        {
            "add-generic-password",
            "-U",
            "-s", _serviceName,
            "-a", KeychainMasterAccount,
            "-w", hex,
        };
        if (_keychainPath is not null)
        {
            args.Add(_keychainPath);
        }

        RunSecurityCli(args, allowNotFound: false);
        return generated;
    }

    private byte[]? TryReadMasterKey()
    {
        var args = new List<string>
        {
            "find-generic-password",
            "-s", _serviceName,
            "-a", KeychainMasterAccount,
            "-w",
        };
        if (_keychainPath is not null)
        {
            args.Add(_keychainPath);
        }

        var (exitCode, stdout, _) = RunSecurityCli(args, allowNotFound: true);
        if (exitCode == 44)
        {
            return null;
        }
        if (exitCode != 0)
        {
            throw new SecureSecretStorageException($"macOS Keychain lookup failed with exit code {exitCode}.");
        }

        var trimmed = stdout.Trim();
        try
        {
            var key = Convert.FromHexString(trimmed);
            if (key.Length != 32)
            {
                CryptographicOperations.ZeroMemory(key);
                throw new SecureSecretStorageException("macOS Keychain wrapping key has invalid length.");
            }
            return key;
        }
        catch (FormatException ex)
        {
            throw new SecureSecretStorageException("macOS Keychain wrapping key format is invalid.", ex);
        }
    }

    private static (int ExitCode, string Stdout, string Stderr) RunSecurityCli(
        IReadOnlyList<string> args,
        bool allowNotFound)
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

        using var process = Process.Start(psi)
            ?? throw new SecureSecretStorageException("Unable to invoke /usr/bin/security.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0 && !(allowNotFound && process.ExitCode == 44))
        {
            throw new SecureSecretStorageException(
                $"macOS /usr/bin/security exited with code {process.ExitCode}: {stderr.Trim()}");
        }

        return (process.ExitCode, stdout, stderr);
    }

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
