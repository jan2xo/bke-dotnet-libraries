namespace BKE.Licensing.Contracts;

public static class AccountProductLeaseConstants
{
    public const string Schema = "bke.product-lease.v1";
    public const string JwsTyp = "bke.product-lease.v1+jws";
    public const string Algorithm = "EdDSA";
    public const long MaxFutureSkewMs = 300_000;
    public static readonly IReadOnlyList<string> AllowedActions = ["OPEN", "USE"];
}

public static class AccountProductLeaseKeyStates
{
    public const string Active = "ACTIVE";
    public const string VerifyOnly = "VERIFY_ONLY";
    public const string Revoked = "REVOKED";
}

public static class AccountProductLeaseFailureReasons
{
    public const string MalformedJws = "MALFORMED_JWS";
    public const string UntrustedKid = "UNTRUSTED_KID";
    public const string InvalidSignature = "INVALID_SIGNATURE";
    public const string InvalidClaims = "INVALID_CLAIMS";
    public const string ClaimMismatch = "CLAIM_MISMATCH";
    public const string FutureIssuedAt = "FUTURE_ISSUED_AT";
    public const string Expired = "EXPIRED";
}

public sealed record AccountProductLeaseTrustedKey(string PublicKeyPem, string State);

public sealed record AccountProductLeaseClaims(
    string Schema,
    string Issuer,
    string Audience,
    string LeaseId,
    string AccountId,
    string UserId,
    string ProductId,
    string AgentSessionId,
    string AgentKeyThumbprint,
    string KeyProtection,
    string Plan,
    IReadOnlyList<string> AllowedActions,
    string IssuedAt,
    string RefreshAfter,
    string ExpiresAt);

public sealed record AccountProductLeaseVerificationContext(
    string Issuer,
    string Audience,
    string AccountId,
    string UserId,
    string ProductId,
    string AgentSessionId,
    string AgentKeyThumbprint,
    string Action,
    DateTimeOffset Now,
    long AllowedFutureSkewMs = AccountProductLeaseConstants.MaxFutureSkewMs,
    bool DisallowPublicTestKeys = false);

public sealed record AccountProductLeaseVerificationResult
{
    public bool Ok { get; init; }
    public string? Kid { get; init; }
    public AccountProductLeaseClaims? Claims { get; init; }
    public string? Reason { get; init; }

    public static AccountProductLeaseVerificationResult Success(string kid, AccountProductLeaseClaims claims) =>
        new() { Ok = true, Kid = kid, Claims = claims };

    public static AccountProductLeaseVerificationResult Fail(string reason) =>
        new() { Ok = false, Reason = reason };
}
