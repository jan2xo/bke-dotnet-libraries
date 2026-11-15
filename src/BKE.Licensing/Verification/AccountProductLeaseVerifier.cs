using System.Text;
using System.Text.Json;
using BKE.Licensing.Contracts;

namespace BKE.Licensing.Verification;

public static class AccountProductLeaseVerifier
{
    private const int MaxCompactJwsLength = 16384;
    private const int MaxSegmentBytes = 16384;

    private static readonly string[] RequiredHeaderFields = ["alg", "kid", "typ"];
    private static readonly string[] RequiredClaimFields =
    [
        "schema", "issuer", "audience", "leaseId", "accountId", "userId",
        "productId", "agentSessionId", "agentKeyThumbprint", "keyProtection",
        "plan", "allowedActions", "issuedAt", "refreshAfter", "expiresAt",
    ];

    public static AccountProductLeaseVerificationResult Verify(
        string? jws,
        IReadOnlyDictionary<string, AccountProductLeaseTrustedKey> keys,
        AccountProductLeaseVerificationContext expected)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(expected);

        if (string.IsNullOrEmpty(jws) || jws.Length > MaxCompactJwsLength)
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.MalformedJws);
        }

        var parts = jws.Split('.');
        if (parts.Length != 3 || parts.Any(static p => p.Length == 0))
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.MalformedJws);
        }

        var protectedBytes = Ed25519KeyUtilities.DecodeCanonicalBase64Url(parts[0], MaxSegmentBytes);
        var payloadBytes = Ed25519KeyUtilities.DecodeCanonicalBase64Url(parts[1], MaxSegmentBytes);
        var signature = Ed25519KeyUtilities.DecodeCanonicalBase64Url(parts[2], 256);
        if (protectedBytes is null || payloadBytes is null || signature is null || signature.Length != 64)
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.MalformedJws);
        }

        using var headerDoc = StrictJsonParser.TryParseUnambiguous(protectedBytes, out var parsedHeaderDoc)
            ? parsedHeaderDoc
            : null;
        if (headerDoc is null || !HasExactObjectKeys(headerDoc.RootElement, RequiredHeaderFields))
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.MalformedJws);
        }

        var headerRoot = headerDoc.RootElement;
        if (!TryGetStringProperty(headerRoot, "alg", out var alg) ||
            alg != AccountProductLeaseConstants.Algorithm ||
            !TryGetStringProperty(headerRoot, "typ", out var typ) ||
            typ != AccountProductLeaseConstants.JwsTyp ||
            !TryGetStringProperty(headerRoot, "kid", out var kid) ||
            !Ed25519KeyUtilities.IsValidKeyId(kid))
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.MalformedJws);
        }

        if (!keys.TryGetValue(kid!, out var trustedKey) ||
            trustedKey.State == AccountProductLeaseKeyStates.Revoked ||
            (trustedKey.State != AccountProductLeaseKeyStates.Active &&
             trustedKey.State != AccountProductLeaseKeyStates.VerifyOnly))
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.UntrustedKid);
        }

        if ((expected.DisallowPublicTestKeys || Ed25519KeyUtilities.IsProductionEnvironment()) &&
            Ed25519KeyUtilities.IsPublicTestFixtureKey(trustedKey.PublicKeyPem, kid))
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.UntrustedKid);
        }

        if (!Ed25519KeyUtilities.TryParsePublicKey(trustedKey.PublicKeyPem, out var publicKey) ||
            publicKey is null)
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.InvalidSignature);
        }

        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        if (!Ed25519KeyUtilities.VerifyEd25519Signature(publicKey, signingInput, signature))
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.InvalidSignature);
        }

        using var payloadDoc = StrictJsonParser.TryParseUnambiguous(payloadBytes, out var parsedPayloadDoc)
            ? parsedPayloadDoc
            : null;
        if (payloadDoc is null || !TryParseClaims(payloadDoc.RootElement, out var claims, out var issuedAt, out var expiresAt) || claims is null)
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.InvalidClaims);
        }

        if (claims.Issuer != expected.Issuer ||
            claims.Audience != expected.Audience ||
            claims.AccountId != expected.AccountId ||
            claims.UserId != expected.UserId ||
            claims.ProductId != expected.ProductId ||
            claims.AgentSessionId != expected.AgentSessionId ||
            claims.AgentKeyThumbprint != expected.AgentKeyThumbprint ||
            !claims.AllowedActions.Contains(expected.Action, StringComparer.Ordinal))
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.ClaimMismatch);
        }

        if (expected.AllowedFutureSkewMs < 0 || expected.AllowedFutureSkewMs > AccountProductLeaseConstants.MaxFutureSkewMs)
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.InvalidClaims);
        }

        var nowMs = expected.Now.ToUnixTimeMilliseconds();
        if (issuedAt.ToUnixTimeMilliseconds() > nowMs + expected.AllowedFutureSkewMs)
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.FutureIssuedAt);
        }

        if (nowMs >= expiresAt.ToUnixTimeMilliseconds())
        {
            return AccountProductLeaseVerificationResult.Fail(AccountProductLeaseFailureReasons.Expired);
        }

        return AccountProductLeaseVerificationResult.Success(kid!, claims);
    }

    private static bool TryParseClaims(
        JsonElement root,
        out AccountProductLeaseClaims? claims,
        out DateTimeOffset issuedAt,
        out DateTimeOffset expiresAt)
    {
        claims = null;
        issuedAt = default;
        expiresAt = default;

        if (!HasExactObjectKeys(root, RequiredClaimFields))
        {
            return false;
        }

        if (!TryGetStringProperty(root, "schema", out var schema) ||
            schema != AccountProductLeaseConstants.Schema ||
            !TryGetBoundedText(root, "issuer", 256, out var issuer) ||
            !TryGetBoundedText(root, "audience", 256, out var audience) ||
            !TryGetBoundedText(root, "leaseId", 128, out var leaseId) ||
            !TryGetBoundedText(root, "accountId", 128, out var accountId) ||
            !TryGetBoundedText(root, "userId", 128, out var userId) ||
            !TryGetBoundedText(root, "productId", 128, out var productId) ||
            !TryGetBoundedText(root, "agentSessionId", 128, out var agentSessionId) ||
            !TryGetBoundedText(root, "plan", 128, out var plan) ||
            !TryGetStringProperty(root, "agentKeyThumbprint", out var thumbprint) ||
            !Ed25519KeyUtilities.IsValidThumbprint(thumbprint) ||
            !TryGetStringProperty(root, "keyProtection", out var keyProtection) ||
            (keyProtection != "tpm" && keyProtection != "software"))
        {
            return false;
        }

        if (!root.TryGetProperty("allowedActions", out var actionsElem) ||
            actionsElem.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var actionList = new List<string>();
        var seenActions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in actionsElem.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                return false;
            }
            var action = item.GetString();
            if (action is null ||
                !AccountProductLeaseConstants.AllowedActions.Contains(action, StringComparer.Ordinal) ||
                !seenActions.Add(action))
            {
                return false;
            }
            actionList.Add(action);
        }

        if (actionList.Count == 0 || actionList.Count > AccountProductLeaseConstants.AllowedActions.Count)
        {
            return false;
        }

        if (!TryGetStringProperty(root, "issuedAt", out var issuedAtStr) ||
            !TryGetStringProperty(root, "refreshAfter", out var refreshAfterStr) ||
            !TryGetStringProperty(root, "expiresAt", out var expiresAtStr) ||
            !Ed25519KeyUtilities.TryParseStrictIsoUtc(issuedAtStr, out issuedAt) ||
            !Ed25519KeyUtilities.TryParseStrictIsoUtc(refreshAfterStr, out var refreshAfter) ||
            !Ed25519KeyUtilities.TryParseStrictIsoUtc(expiresAtStr, out expiresAt))
        {
            return false;
        }

        if (issuedAt > refreshAfter || refreshAfter >= expiresAt)
        {
            return false;
        }

        claims = new AccountProductLeaseClaims(
            schema!,
            issuer!,
            audience!,
            leaseId!,
            accountId!,
            userId!,
            productId!,
            agentSessionId!,
            thumbprint!,
            keyProtection!,
            plan!,
            actionList.AsReadOnly(),
            issuedAtStr!,
            refreshAfterStr!,
            expiresAtStr!);
        return true;
    }

    internal static bool HasExactObjectKeys(JsonElement root, string[] required)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var count = 0;
        foreach (var prop in root.EnumerateObject())
        {
            if (!required.Contains(prop.Name, StringComparer.Ordinal))
            {
                return false;
            }
            count++;
        }

        return count == required.Length;
    }

    internal static bool TryGetStringProperty(JsonElement root, string name, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var prop) || prop.ValueKind != JsonValueKind.String)
        {
            return false;
        }
        value = prop.GetString();
        return value is not null;
    }

    internal static bool TryGetBoundedText(JsonElement root, string name, int maxLength, out string? value)
    {
        value = null;
        return TryGetStringProperty(root, name, out value) &&
               Ed25519KeyUtilities.IsBoundedNonWhitespaceText(value, maxLength);
    }
}
