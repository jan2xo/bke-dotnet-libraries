namespace BKE.Licensing.Contracts;

public static class ActivationModes
{
    public const string Account = "ACCOUNT";
    public const string LicenseKey = "LICENSE_KEY";
    public const string Either = "EITHER";
}

public static class ActivationCredentials
{
    public const string Account = "ACCOUNT";
    public const string LicenseKey = "LICENSE_KEY";
    public const string ClaimCode = "CLAIM_CODE";
}

public static class ActivationModeFailureReasons
{
    public const string InvalidActivationMode = "INVALID_ACTIVATION_MODE";
    public const string ClaimCodeNotActivationCredential = "CLAIM_CODE_NOT_ACTIVATION_CREDENTIAL";
    public const string InvalidCredentialType = "INVALID_CREDENTIAL_TYPE";
    public const string ActivationModeMismatch = "ACTIVATION_MODE_MISMATCH";
}

public sealed record ActivationModeEvaluationResult
{
    public bool Ok { get; init; }
    public string? Mode { get; init; }
    public string? Credential { get; init; }
    public string? Reason { get; init; }

    public static ActivationModeEvaluationResult Success(string mode, string credential) =>
        new() { Ok = true, Mode = mode, Credential = credential };

    public static ActivationModeEvaluationResult Fail(string reason) =>
        new() { Ok = false, Reason = reason };
}
