namespace BKE.Licensing.Contracts;

public static class CommercialLeaseConstants
{
    public const string Algorithm = "Ed25519";
    public const long MaxFutureSkewMs = 300_000;
}

public static class CommercialLeaseKeyStatuses
{
    public const string Active = "ACTIVE";
    public const string VerifyOnly = "VERIFY_ONLY";
    public const string Retired = "RETIRED";
    public const string Revoked = "REVOKED";
}

public static class CommercialLeaseFailureReasons
{
    public const string MalformedEnvelope = "MALFORMED_ENVELOPE";
    public const string UntrustedKeyId = "UNTRUSTED_KEY_ID";
    public const string InvalidSignature = "INVALID_SIGNATURE";
    public const string InvalidPayload = "INVALID_PAYLOAD";
    public const string LeaseRevoked = "LEASE_REVOKED";
    public const string LeaseSuperseded = "LEASE_SUPERSEDED";
    public const string ScopeMismatch = "SCOPE_MISMATCH";
    public const string FutureIssuedAt = "FUTURE_ISSUED_AT";
    public const string NotYetValid = "NOT_YET_VALID";
    public const string Expired = "EXPIRED";
}

public sealed record CommercialLeasePayload(
    string LicenseId,
    string LeaseId,
    int Generation,
    int ServerRevision,
    string ProductId,
    string InstallationId,
    string DeviceId,
    string Version,
    string Issuer,
    string IssuedAt,
    string NotBefore,
    string ExpiresAt,
    string KeyId,
    string Algorithm,
    bool Revoked,
    string? SupersededBy);

public sealed record CommercialLeaseEnvelope(
    string Payload,
    string Signature,
    string KeyId,
    string Algorithm);

public sealed record CommercialLeaseTrustedKey(string PublicKey, string Status);

public sealed record CommercialLeaseVerificationContext(
    string Issuer,
    string ProductId,
    string InstallationId,
    string DeviceId,
    string Version,
    DateTimeOffset Now,
    long AllowedFutureSkewMs = CommercialLeaseConstants.MaxFutureSkewMs,
    bool DisallowPublicTestKeys = false);

public sealed record CommercialLeaseVerificationResult
{
    public bool Ok { get; init; }
    public CommercialLeasePayload? Payload { get; init; }
    public string? KeyId { get; init; }
    public string? Reason { get; init; }

    public static CommercialLeaseVerificationResult Success(CommercialLeasePayload payload, string keyId) =>
        new() { Ok = true, Payload = payload, KeyId = keyId };

    public static CommercialLeaseVerificationResult Fail(string reason) =>
        new() { Ok = false, Reason = reason };
}
