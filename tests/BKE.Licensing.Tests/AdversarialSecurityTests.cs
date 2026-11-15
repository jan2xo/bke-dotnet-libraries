using System.Security.Cryptography;
using System.Text;
using BKE.Licensing.Contracts;
using BKE.Licensing.Policy;
using BKE.Licensing.Verification;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace BKE.Licensing.Tests;

public sealed class AdversarialSecurityTests
{
    private sealed record Ed25519Pair(
        Ed25519PrivateKeyParameters PrivateKey,
        Ed25519PublicKeyParameters PublicKey,
        string PublicKeyPem,
        string Thumbprint);

    private static Ed25519Pair GenerateKeyPair()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = generator.GenerateKeyPair();
        var priv = (Ed25519PrivateKeyParameters)kp.Private;
        var pub = (Ed25519PublicKeyParameters)kp.Public;
        using var sw = new StringWriter();
        var pemWriter = new PemWriter(sw);
        pemWriter.WriteObject(pub);
        pemWriter.Writer.Flush();
        return new Ed25519Pair(priv, pub, sw.ToString(), Ed25519KeyUtilities.ComputeSpkiThumbprint(pub));
    }

    private static string SignJws(string headerJson, string payloadJson, Ed25519PrivateKeyParameters privateKey)
    {
        var h = Ed25519KeyUtilities.EncodeBase64Url(Encoding.UTF8.GetBytes(headerJson));
        var p = Ed25519KeyUtilities.EncodeBase64Url(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = Encoding.ASCII.GetBytes($"{h}.{p}");
        var signer = new Ed25519Signer();
        signer.Init(true, privateKey);
        signer.BlockUpdate(signingInput, 0, signingInput.Length);
        var sig = Ed25519KeyUtilities.EncodeBase64Url(signer.GenerateSignature());
        return $"{h}.{p}.{sig}";
    }

    private static string SignCompactJws(Ed25519PrivateKeyParameters key, string kid, string claimsJson) =>
        SignJws(
            $$"""{"alg":"EdDSA","kid":"{{kid}}","typ":"bke.product-lease.v1+jws"}""",
            claimsJson,
            key);

    private static string SampleClaimsJson(
        string productId = "render-dock",
        string thumbprint = "EZyRf39CtYjY7Eo2vsxSQNMW3JstQqNX2D279miJrAY",
        string issuedAt = "2026-11-11T00:00:00.000Z",
        string expiresAt = "2026-11-14T00:00:00.000Z",
        string allowedAction = "OPEN") =>
        $$"""{"schema":"bke.product-lease.v1","issuer":"BKE Digital Solutions","audience":"bke-product","leaseId":"lease-001","accountId":"acct-001","userId":"usr-001","productId":"{{productId}}","agentSessionId":"sess-001","agentKeyThumbprint":"{{thumbprint}}","keyProtection":"tpm","plan":"pro","allowedActions":["{{allowedAction}}"],"issuedAt":"{{issuedAt}}","refreshAfter":"2026-11-11T01:00:00.000Z","expiresAt":"{{expiresAt}}"}""";

    [Fact]
    public void AccountLease_Rejects_AllAdversarialMutations_And_AcceptsValid()
    {
        var kp = GenerateKeyPair();
        var attacker = GenerateKeyPair();
        var now = DateTimeOffset.Parse("2026-11-11T02:00:00.000Z");
        const string kid = "prod-authority-2026-k1";
        var keys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            [kid] = new(kp.PublicKeyPem, AccountProductLeaseKeyStates.Active),
            ["prod-revoked-k0"] = new(kp.PublicKeyPem, AccountProductLeaseKeyStates.Revoked),
        };
        var expected = new AccountProductLeaseVerificationContext(
            "BKE Digital Solutions",
            "bke-product",
            "acct-001",
            "usr-001",
            "render-dock",
            "sess-001",
            "EZyRf39CtYjY7Eo2vsxSQNMW3JstQqNX2D279miJrAY",
            "OPEN",
            now,
            DisallowPublicTestKeys: true);

        var valid = SignCompactJws(kp.PrivateKey, kid, SampleClaimsJson());
        Assert.True(AccountProductLeaseVerifier.Verify(valid, keys, expected).Ok);

        // Modified payload keeps old signature
        var parts = valid.Split('.');
        var alteredPayload = Ed25519KeyUtilities.EncodeBase64Url(Encoding.UTF8.GetBytes(SampleClaimsJson(productId: "other-app")));
        Assert.Equal(
            AccountProductLeaseFailureReasons.InvalidSignature,
            AccountProductLeaseVerifier.Verify($"{parts[0]}.{alteredPayload}.{parts[2]}", keys, expected).Reason);

        // Revoked kid rejected even with matching key
        var withRevokedKid = SignCompactJws(kp.PrivateKey, "prod-revoked-k0", SampleClaimsJson());
        Assert.Equal(
            AccountProductLeaseFailureReasons.UntrustedKid,
            AccountProductLeaseVerifier.Verify(withRevokedKid, keys, expected).Reason);

        // Untrusted key swap with valid signature under attacker key under same kid
        var attackerSigned = SignCompactJws(attacker.PrivateKey, kid, SampleClaimsJson());
        Assert.Equal(
            AccountProductLeaseFailureReasons.InvalidSignature,
            AccountProductLeaseVerifier.Verify(attackerSigned, keys, expected).Reason);

        // Algorithm confusion
        var algNone = SignJws(
            $$"""{"alg":"none","kid":"{{kid}}","typ":"bke.product-lease.v1+jws"}""",
            SampleClaimsJson(),
            kp.PrivateKey);
        Assert.Equal(
            AccountProductLeaseFailureReasons.MalformedJws,
            AccountProductLeaseVerifier.Verify(algNone, keys, expected).Reason);

        // Duplicate escaped JSON field rejected
        var dupJson = SampleClaimsJson().Replace(
            "\"productId\":\"render-dock\"",
            "\"product\\u0049d\":\"air-stack\",\"productId\":\"render-dock\"",
            StringComparison.Ordinal);
        Assert.Equal(
            AccountProductLeaseFailureReasons.InvalidClaims,
            AccountProductLeaseVerifier.Verify(SignCompactJws(kp.PrivateKey, kid, dupJson), keys, expected).Reason);

        // Wrong action & wrong product
        Assert.Equal(
            AccountProductLeaseFailureReasons.ClaimMismatch,
            AccountProductLeaseVerifier.Verify(SignCompactJws(kp.PrivateKey, kid, SampleClaimsJson(allowedAction: "USE")), keys, expected).Reason);

        // Oversized JWS rejected
        Assert.Equal(
            AccountProductLeaseFailureReasons.MalformedJws,
            AccountProductLeaseVerifier.Verify(new string('A', 20_000), keys, expected).Reason);
    }

    [Fact]
    public void PublicTestFixtureKey_Rejected_WhenStrictModeEnabled()
    {
        var seed = new byte[32];
        Array.Fill(seed, (byte)0x42);
        var priv = new Ed25519PrivateKeyParameters(seed, 0);
        var pub = priv.GeneratePublicKey();
        using var sw = new StringWriter();
        var pw = new PemWriter(sw);
        pw.WriteObject(pub);
        pw.Writer.Flush();
        var pem = sw.ToString();

        // Even with non-"test-" key id, SPKI thumbprint matches 0x42*32 fixture and must fail strict verification.
        var keys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            ["spoofed-prod-kid"] = new(pem, AccountProductLeaseKeyStates.Active),
        };
        var expected = new AccountProductLeaseVerificationContext(
            "BKE Digital Solutions",
            "bke-product",
            "acct-001",
            "usr-001",
            "render-dock",
            "sess-001",
            "EZyRf39CtYjY7Eo2vsxSQNMW3JstQqNX2D279miJrAY",
            "OPEN",
            DateTimeOffset.Parse("2026-11-11T02:00:00.000Z"),
            DisallowPublicTestKeys: true);

        var jws = SignCompactJws(priv, "spoofed-prod-kid", SampleClaimsJson());
        Assert.Equal(
            AccountProductLeaseFailureReasons.UntrustedKid,
            AccountProductLeaseVerifier.Verify(jws, keys, expected).Reason);
    }

    [Fact]
    public async Task ChallengeProof_AllowsExactlyOneAtomicConsumptionUnderConcurrency()
    {
        var agentKp = GenerateKeyPair();
        var now = DateTimeOffset.Parse("2026-11-15T12:00:00.000Z");
        var store = new InMemoryLeaseChallengeStore();
        var tempRecord = new LeaseChallengeRecord(
            "chg_concurrent_001",
            "acct-1",
            "usr-1",
            "render-dock",
            "sess-1",
            agentKp.Thumbprint,
            "OPEN",
            "nonce_concurrent_abcdef012345",
            string.Empty,
            now.AddSeconds(-5),
            now.AddSeconds(25),
            null);
        var msg = LeaseChallengeProofVerifier.BuildCanonicalMessage(tempRecord);
        var hash = Convert.ToHexStringLower(SHA256.HashData(msg));
        var record = tempRecord with { MessageHash = hash };
        store.IssueChallenge(record);

        var signer = new Ed25519Signer();
        signer.Init(true, agentKp.PrivateKey);
        signer.BlockUpdate(msg, 0, msg.Length);
        var sigB64 = Ed25519KeyUtilities.EncodeBase64Url(signer.GenerateSignature());
        var msgB64 = Ed25519KeyUtilities.EncodeBase64Url(msg);

        var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
            LeaseChallengeProofVerifier.VerifyAndConsume(
                store,
                record.ChallengeId,
                msgB64,
                sigB64,
                agentKp.PublicKeyPem,
                record.AccountId,
                record.UserId,
                record.ProductId,
                record.AgentSessionId,
                record.AgentKeyThumbprint,
                record.Action,
                now)));

        var results = await Task.WhenAll(tasks);
        Assert.Single(results, r => r.Ok);
        Assert.Equal(7, results.Count(r => !r.Ok && r.Reason == LeaseChallengeFailureReasons.ChallengeAlreadyConsumed));
    }

    [Fact]
    public void ProductAuthorizationGate_FailsClosed_OnUnavailableAuthorityOrWrongMode()
    {
        var unavailable = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AuthorityAvailable = false,
        });
        Assert.False(unavailable.Authorized);
        Assert.Equal(AuthorizationFailureReasons.AuthorityUnavailable, unavailable.Reason);

        var claimCode = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.ClaimCode,
        });
        Assert.False(claimCode.Authorized);
        Assert.Equal(ActivationModeFailureReasons.ClaimCodeNotActivationCredential, claimCode.Reason);

        var modeMismatch = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Account,
            PresentedCredential = ActivationCredentials.LicenseKey,
        });
        Assert.False(modeMismatch.Authorized);
        Assert.Equal(ActivationModeFailureReasons.ActivationModeMismatch, modeMismatch.Reason);
    }
}
