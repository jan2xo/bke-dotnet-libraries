using BKE.Licensing.Contracts;

namespace BKE.Licensing.Policy;

public static class ActivationModePolicy
{
    public static bool IsValidMode(string? mode) =>
        mode is ActivationModes.Account or ActivationModes.LicenseKey or ActivationModes.Either;

    public static bool IsValidCredential(string? credential) =>
        credential is ActivationCredentials.Account or ActivationCredentials.LicenseKey;

    public static bool AllowsActivation(string? mode, string? credential)
    {
        if (!IsValidMode(mode) || !IsValidCredential(credential))
        {
            return false;
        }

        return credential == ActivationCredentials.Account
            ? mode is ActivationModes.Account or ActivationModes.Either
            : mode is ActivationModes.LicenseKey or ActivationModes.Either;
    }

    public static ActivationModeEvaluationResult Evaluate(string? mode, string? credential)
    {
        if (!IsValidMode(mode))
        {
            return ActivationModeEvaluationResult.Fail(ActivationModeFailureReasons.InvalidActivationMode);
        }

        if (credential == ActivationCredentials.ClaimCode)
        {
            return ActivationModeEvaluationResult.Fail(ActivationModeFailureReasons.ClaimCodeNotActivationCredential);
        }

        if (!IsValidCredential(credential))
        {
            return ActivationModeEvaluationResult.Fail(ActivationModeFailureReasons.InvalidCredentialType);
        }

        if (!AllowsActivation(mode, credential))
        {
            return ActivationModeEvaluationResult.Fail(ActivationModeFailureReasons.ActivationModeMismatch);
        }

        return ActivationModeEvaluationResult.Success(mode!, credential!);
    }
}
