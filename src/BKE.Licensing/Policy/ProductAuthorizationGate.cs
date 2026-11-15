using BKE.Licensing.Contracts;
using BKE.Licensing.Verification;

namespace BKE.Licensing.Policy;

public static class AuthorizationFailureReasons
{
    public const string AuthorityUnavailable = "AUTHORITY_UNAVAILABLE";
    public const string MissingAuthorizationProof = "MISSING_AUTHORIZATION_PROOF";
    public const string ScopeMismatch = "SCOPE_MISMATCH";
}

public sealed record ProductAuthorizationDecision(
    bool Authorized,
    string Reason,
    string? CredentialUsed = null,
    string? LeaseId = null,
    string? ExpiresAt = null);

public sealed record ProductAuthorizationRequest
{
    public required string ProductId { get; init; }
    public required string RequiredActivationMode { get; init; }
    public required string PresentedCredential { get; init; }
    public bool AuthorityAvailable { get; init; } = true;
    public bool DisallowPublicTestKeys { get; init; } = true;

    public string? AccountJws { get; init; }
    public IReadOnlyDictionary<string, AccountProductLeaseTrustedKey>? AccountTrustedKeys { get; init; }
    public AccountProductLeaseVerificationContext? AccountExpected { get; init; }

    public CommercialLeaseEnvelope? CommercialEnvelope { get; init; }
    public IReadOnlyDictionary<string, CommercialLeaseTrustedKey>? CommercialTrustedKeys { get; init; }
    public CommercialLeaseVerificationContext? CommercialExpected { get; init; }
}

public static class ProductAuthorizationGate
{
    public static ProductAuthorizationDecision Authorize(ProductAuthorizationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.AuthorityAvailable ||
            string.IsNullOrWhiteSpace(request.ProductId))
        {
            return new ProductAuthorizationDecision(false, AuthorizationFailureReasons.AuthorityUnavailable);
        }

        var modeCheck = ActivationModePolicy.Evaluate(
            request.RequiredActivationMode,
            request.PresentedCredential);
        if (!modeCheck.Ok)
        {
            return new ProductAuthorizationDecision(false, modeCheck.Reason ?? ActivationModeFailureReasons.ActivationModeMismatch);
        }

        if (request.PresentedCredential == ActivationCredentials.Account)
        {
            if (request.AccountTrustedKeys is null || request.AccountTrustedKeys.Count == 0)
            {
                return new ProductAuthorizationDecision(false, AuthorizationFailureReasons.AuthorityUnavailable);
            }

            if (string.IsNullOrEmpty(request.AccountJws) || request.AccountExpected is null)
            {
                return new ProductAuthorizationDecision(false, AuthorizationFailureReasons.MissingAuthorizationProof);
            }

            if (request.AccountExpected.ProductId != request.ProductId)
            {
                return new ProductAuthorizationDecision(false, AuthorizationFailureReasons.ScopeMismatch);
            }

            var expected = request.AccountExpected with
            {
                DisallowPublicTestKeys = request.AccountExpected.DisallowPublicTestKeys || request.DisallowPublicTestKeys,
            };

            var accountResult = AccountProductLeaseVerifier.Verify(
                request.AccountJws,
                request.AccountTrustedKeys,
                expected);
            return accountResult.Ok && accountResult.Claims is not null
                ? new ProductAuthorizationDecision(
                    true,
                    "AUTHORIZED",
                    ActivationCredentials.Account,
                    accountResult.Claims.LeaseId,
                    accountResult.Claims.ExpiresAt)
                : new ProductAuthorizationDecision(
                    false,
                    accountResult.Reason ?? AccountProductLeaseFailureReasons.InvalidClaims);
        }

        if (request.PresentedCredential == ActivationCredentials.LicenseKey)
        {
            if (request.CommercialTrustedKeys is null || request.CommercialTrustedKeys.Count == 0)
            {
                return new ProductAuthorizationDecision(false, AuthorizationFailureReasons.AuthorityUnavailable);
            }

            if (request.CommercialEnvelope is null || request.CommercialExpected is null)
            {
                return new ProductAuthorizationDecision(false, AuthorizationFailureReasons.MissingAuthorizationProof);
            }

            if (request.CommercialExpected.ProductId != request.ProductId)
            {
                return new ProductAuthorizationDecision(false, AuthorizationFailureReasons.ScopeMismatch);
            }

            var expected = request.CommercialExpected with
            {
                DisallowPublicTestKeys = request.CommercialExpected.DisallowPublicTestKeys || request.DisallowPublicTestKeys,
            };

            var commercialResult = CommercialLeaseVerifier.Verify(
                request.CommercialEnvelope,
                request.CommercialTrustedKeys,
                expected);
            return commercialResult.Ok && commercialResult.Payload is not null
                ? new ProductAuthorizationDecision(
                    true,
                    "AUTHORIZED",
                    ActivationCredentials.LicenseKey,
                    commercialResult.Payload.LeaseId,
                    commercialResult.Payload.ExpiresAt)
                : new ProductAuthorizationDecision(
                    false,
                    commercialResult.Reason ?? CommercialLeaseFailureReasons.InvalidPayload);
        }

        return new ProductAuthorizationDecision(false, ActivationModeFailureReasons.InvalidCredentialType);
    }
}
