using System.Text;
using System.Text.Json;
using BKE.Licensing.Contracts;

namespace BKE.Licensing.Verification;

public static class CommercialLeaseVerifier
{
    private const int MaxPayloadLength = 16384;

    private static readonly string[] RequiredPayloadFields =
    [
        "license_id", "lease_id", "generation", "server_revision", "product_id",
        "installation_id", "device_id", "version", "issuer", "issued_at",
        "not_before", "expires_at", "key_id", "algorithm", "revoked", "superseded_by",
    ];

    public static CommercialLeaseVerificationResult Verify(
        CommercialLeaseEnvelope? envelope,
        IReadOnlyDictionary<string, CommercialLeaseTrustedKey> trustedKeys,
        CommercialLeaseVerificationContext expected)
    {
        ArgumentNullException.ThrowIfNull(trustedKeys);
        ArgumentNullException.ThrowIfNull(expected);

        if (envelope is null ||
            envelope.Algorithm != CommercialLeaseConstants.Algorithm ||
            string.IsNullOrEmpty(envelope.Payload) ||
            envelope.Payload.Length > MaxPayloadLength ||
            !Ed25519KeyUtilities.IsValidKeyId(envelope.KeyId))
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.MalformedEnvelope);
        }

        var signature = Ed25519KeyUtilities.DecodeCanonicalBase64(envelope.Signature, 64);
        if (signature is null)
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.MalformedEnvelope);
        }

        if (!trustedKeys.TryGetValue(envelope.KeyId, out var trusted) ||
            trusted.Status == CommercialLeaseKeyStatuses.Revoked ||
            (trusted.Status != CommercialLeaseKeyStatuses.Active &&
             trusted.Status != CommercialLeaseKeyStatuses.VerifyOnly &&
             trusted.Status != CommercialLeaseKeyStatuses.Retired))
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.UntrustedKeyId);
        }

        if ((expected.DisallowPublicTestKeys || Ed25519KeyUtilities.IsProductionEnvironment()) &&
            Ed25519KeyUtilities.IsPublicTestFixtureKey(trusted.PublicKey, envelope.KeyId))
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.UntrustedKeyId);
        }

        if (!Ed25519KeyUtilities.TryParsePublicKey(trusted.PublicKey, out var publicKey) ||
            publicKey is null)
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.InvalidSignature);
        }

        var payloadUtf8 = Encoding.UTF8.GetBytes(envelope.Payload);
        if (!Ed25519KeyUtilities.VerifyEd25519Signature(publicKey, payloadUtf8, signature))
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.InvalidSignature);
        }

        using var doc = StrictJsonParser.TryParseUnambiguous(payloadUtf8, out var parsedDoc)
            ? parsedDoc
            : null;
        if (doc is null ||
            !TryParsePayload(doc.RootElement, out var payload, out var issuedAt, out var notBefore, out var expiresAt) ||
            payload is null ||
            payload.KeyId != envelope.KeyId)
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.InvalidPayload);
        }

        if (payload.Revoked)
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.LeaseRevoked);
        }

        if (payload.SupersededBy is not null)
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.LeaseSuperseded);
        }

        if (payload.Issuer != expected.Issuer ||
            payload.ProductId != expected.ProductId ||
            payload.InstallationId != expected.InstallationId ||
            payload.DeviceId != expected.DeviceId ||
            payload.Version != expected.Version)
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.ScopeMismatch);
        }

        if (expected.AllowedFutureSkewMs < 0 || expected.AllowedFutureSkewMs > CommercialLeaseConstants.MaxFutureSkewMs)
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.InvalidPayload);
        }

        var nowMs = expected.Now.ToUnixTimeMilliseconds();
        if (issuedAt.ToUnixTimeMilliseconds() > nowMs + expected.AllowedFutureSkewMs)
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.FutureIssuedAt);
        }

        if (nowMs + expected.AllowedFutureSkewMs < notBefore.ToUnixTimeMilliseconds())
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.NotYetValid);
        }

        if (nowMs >= expiresAt.ToUnixTimeMilliseconds())
        {
            return CommercialLeaseVerificationResult.Fail(CommercialLeaseFailureReasons.Expired);
        }

        return CommercialLeaseVerificationResult.Success(payload, envelope.KeyId);
    }

    private static bool TryParsePayload(
        JsonElement root,
        out CommercialLeasePayload? payload,
        out DateTimeOffset issuedAt,
        out DateTimeOffset notBefore,
        out DateTimeOffset expiresAt)
    {
        payload = null;
        issuedAt = default;
        notBefore = default;
        expiresAt = default;

        if (!AccountProductLeaseVerifier.HasExactObjectKeys(root, RequiredPayloadFields))
        {
            return false;
        }

        if (!AccountProductLeaseVerifier.TryGetBoundedText(root, "license_id", 128, out var licenseId) ||
            !AccountProductLeaseVerifier.TryGetBoundedText(root, "lease_id", 128, out var leaseId) ||
            !AccountProductLeaseVerifier.TryGetBoundedText(root, "product_id", 128, out var productId) ||
            !AccountProductLeaseVerifier.TryGetBoundedText(root, "installation_id", 128, out var installationId) ||
            !AccountProductLeaseVerifier.TryGetBoundedText(root, "device_id", 256, out var deviceId) ||
            !AccountProductLeaseVerifier.TryGetBoundedText(root, "version", 128, out var version) ||
            !AccountProductLeaseVerifier.TryGetBoundedText(root, "issuer", 256, out var issuer) ||
            !AccountProductLeaseVerifier.TryGetStringProperty(root, "key_id", out var keyId) ||
            !Ed25519KeyUtilities.IsValidKeyId(keyId) ||
            !AccountProductLeaseVerifier.TryGetStringProperty(root, "algorithm", out var algorithm) ||
            algorithm != CommercialLeaseConstants.Algorithm)
        {
            return false;
        }

        if (!root.TryGetProperty("generation", out var genElem) ||
            genElem.ValueKind != JsonValueKind.Number ||
            !genElem.TryGetInt32(out var generation) ||
            generation < 1)
        {
            return false;
        }

        if (!root.TryGetProperty("server_revision", out var revElem) ||
            revElem.ValueKind != JsonValueKind.Number ||
            !revElem.TryGetInt32(out var serverRevision) ||
            serverRevision < 1)
        {
            return false;
        }

        if (!root.TryGetProperty("revoked", out var revokedElem) ||
            (revokedElem.ValueKind != JsonValueKind.True && revokedElem.ValueKind != JsonValueKind.False))
        {
            return false;
        }
        var revoked = revokedElem.GetBoolean();

        string? supersededBy;
        if (!root.TryGetProperty("superseded_by", out var supElem))
        {
            return false;
        }
        if (supElem.ValueKind == JsonValueKind.Null)
        {
            supersededBy = null;
        }
        else if (supElem.ValueKind == JsonValueKind.String)
        {
            supersededBy = supElem.GetString();
            if (!Ed25519KeyUtilities.IsBoundedNonWhitespaceText(supersededBy, 128))
            {
                return false;
            }
        }
        else
        {
            return false;
        }

        if (!AccountProductLeaseVerifier.TryGetStringProperty(root, "issued_at", out var issuedAtStr) ||
            !AccountProductLeaseVerifier.TryGetStringProperty(root, "not_before", out var notBeforeStr) ||
            !AccountProductLeaseVerifier.TryGetStringProperty(root, "expires_at", out var expiresAtStr) ||
            !Ed25519KeyUtilities.TryParseStrictIsoUtc(issuedAtStr, out issuedAt) ||
            !Ed25519KeyUtilities.TryParseStrictIsoUtc(notBeforeStr, out notBefore) ||
            !Ed25519KeyUtilities.TryParseStrictIsoUtc(expiresAtStr, out expiresAt))
        {
            return false;
        }

        if (issuedAt > expiresAt || notBefore > expiresAt)
        {
            return false;
        }

        payload = new CommercialLeasePayload(
            licenseId!,
            leaseId!,
            generation,
            serverRevision,
            productId!,
            installationId!,
            deviceId!,
            version!,
            issuer!,
            issuedAtStr!,
            notBeforeStr!,
            expiresAtStr!,
            keyId!,
            algorithm!,
            revoked,
            supersededBy);
        return true;
    }
}
