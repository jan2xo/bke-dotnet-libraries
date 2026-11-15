using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace BKE.Licensing.Verification;

public static partial class Ed25519KeyUtilities
{
    private static readonly Lazy<string> LazyPublicTestThumbprint = new(() =>
    {
        var seed = new byte[32];
        Array.Fill(seed, (byte)0x42);
        var priv = new Ed25519PrivateKeyParameters(seed, 0);
        return ComputeSpkiThumbprint(priv.GeneratePublicKey());
    });

    public static string PublicTestFixtureEd25519Thumbprint => LazyPublicTestThumbprint.Value;

    public static string EncodeBase64Url(ReadOnlySpan<byte> bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static byte[]? DecodeCanonicalBase64Url(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maxLength || !Base64UrlPattern().IsMatch(value))
        {
            return null;
        }

        var padded = value.Replace('-', '+').Replace('_', '/');
        var mod = padded.Length % 4;
        if (mod == 1)
        {
            return null;
        }
        if (mod == 2)
        {
            padded += "==";
        }
        else if (mod == 3)
        {
            padded += "=";
        }

        try
        {
            var bytes = Convert.FromBase64String(padded);
            return EncodeBase64Url(bytes) == value ? bytes : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public static byte[]? DecodeCanonicalBase64(string? value, int exactByteLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length > exactByteLength * 2 + 8 || !Base64Pattern().IsMatch(value))
        {
            return null;
        }

        try
        {
            var bytes = Convert.FromBase64String(value);
            return bytes.Length == exactByteLength && Convert.ToBase64String(bytes) == value
                ? bytes
                : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public static bool TryParsePublicKey(string? pemOrBase64, out Ed25519PublicKeyParameters? publicKey)
    {
        publicKey = null;
        if (string.IsNullOrWhiteSpace(pemOrBase64))
        {
            return false;
        }

        try
        {
            byte[] der;
            if (pemOrBase64.Contains("BEGIN", StringComparison.Ordinal))
            {
                using var reader = new StringReader(pemOrBase64);
                var pemReader = new PemReader(reader);
                var pemObject = pemReader.ReadPemObject();
                if (pemObject is null || pemObject.Type != "PUBLIC KEY")
                {
                    return false;
                }
                der = pemObject.Content;
            }
            else
            {
                der = Convert.FromBase64String(pemOrBase64.Trim());
            }

            var parsed = PublicKeyFactory.CreateKey(der);
            if (parsed is not Ed25519PublicKeyParameters ed25519)
            {
                return false;
            }

            publicKey = ed25519;
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static string ComputeSpkiThumbprint(Ed25519PublicKeyParameters publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetDerEncoded();
        var hash = SHA256.HashData(spki);
        return EncodeBase64Url(hash);
    }

    public static bool VerifyEd25519Signature(
        Ed25519PublicKeyParameters publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (signature.Length != 64)
        {
            return false;
        }

        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        var messageBytes = message.ToArray();
        verifier.BlockUpdate(messageBytes, 0, messageBytes.Length);
        return verifier.VerifySignature(signature.ToArray());
    }

    public static bool IsPublicTestFixtureKey(string keyMaterial, string? kid)
    {
        if (!string.IsNullOrEmpty(kid) &&
            (kid.StartsWith("test-", StringComparison.Ordinal) ||
             kid.StartsWith("fixture-", StringComparison.Ordinal)))
        {
            return true;
        }

        return TryParsePublicKey(keyMaterial, out var parsed) &&
               parsed is not null &&
               ComputeSpkiThumbprint(parsed) == PublicTestFixtureEd25519Thumbprint;
    }

    public static bool IsProductionEnvironment() =>
        string.Equals(
            Environment.GetEnvironmentVariable("DEPLOYMENT_ENV"),
            "production",
            StringComparison.Ordinal);

    public static bool IsBoundedNonWhitespaceText(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maxLength || value.Trim() != value)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (char.IsControl(ch))
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsValidKeyId(string? kid) =>
        !string.IsNullOrEmpty(kid) && KeyIdPattern().IsMatch(kid);

    public static bool IsValidThumbprint(string? thumbprint) =>
        !string.IsNullOrEmpty(thumbprint) && ThumbprintPattern().IsMatch(thumbprint);

    public static bool TryParseStrictIsoUtc(string? value, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (string.IsNullOrEmpty(value) || !IsoUtcPattern().IsMatch(value))
        {
            return false;
        }

        if (!DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            return false;
        }

        if (parsed.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture) != value)
        {
            return false;
        }

        timestamp = parsed;
        return true;
    }

    [GeneratedRegex("^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex Base64UrlPattern();

    [GeneratedRegex("^[A-Za-z0-9+/]+=*$", RegexOptions.CultureInvariant)]
    private static partial Regex Base64Pattern();

    [GeneratedRegex("^[A-Za-z0-9._-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyIdPattern();

    [GeneratedRegex("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex ThumbprintPattern();

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", RegexOptions.CultureInvariant)]
    private static partial Regex IsoUtcPattern();
}
