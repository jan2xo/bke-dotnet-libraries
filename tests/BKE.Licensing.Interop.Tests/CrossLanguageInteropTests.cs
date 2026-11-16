using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using BKE.Licensing.Contracts;
using BKE.Licensing.Policy;
using BKE.Licensing.Verification;

namespace BKE.Licensing.Interop.Tests;

public sealed class CrossLanguageInteropTests
{
    private const string PinnedSuiteSha256 = "27c88a752b4be973f88333e2dba9eba62a04cc17973a16e992c5a1d4152d1830";

    private static string VectorsPath =>
        Path.Combine(AppContext.BaseDirectory, "Vectors", "interop-vectors.json");

    [Fact]
    public void PinnedInteropVectors_MatchExpectedSha256_And_PassAllContracts()
    {
        var jsonBytes = File.ReadAllBytes(VectorsPath);
        var actualHash = Convert.ToHexStringLower(SHA256.HashData(jsonBytes));
        Assert.Equal(PinnedSuiteSha256, actualHash);

        using var doc = JsonDocument.Parse(jsonBytes);
        AssertSuite(doc.RootElement);
    }

    [Fact]
    public void LiveTypeScriptGenerator_ProducesIdenticalSuite_And_RuntimeFreshAuthorizationsVerifyInDotNet()
    {
        var tsRepoPath = ResolveTypeScriptRepoPath();
        if (tsRepoPath is null)
        {
            Assert.True(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI")), "CI must supply BKE_TS_REPO_PATH");
            return;
        }

        var generatorScript = Path.Combine(tsRepoPath, "@bke", "licensing", "tests", "lease-vectors", "generate-interop-suite.cjs");
        Assert.True(File.Exists(generatorScript), $"Missing TS vector generator at {generatorScript}");

        var liveOutput = RunNodeScript(tsRepoPath, generatorScript);
        var liveHash = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(liveOutput)));
        Assert.Equal(PinnedSuiteSha256, liveHash);

        using var liveDoc = JsonDocument.Parse(liveOutput);
        AssertSuite(liveDoc.RootElement);

        // Dynamically mint fresh disposable leases/challenges from live TS source modules and verify in .NET.
        const string inlineScript = """
import { generateKeyPairSync } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const repoRoot = process.env.BKE_TS_WORK_DIR;
const load = (rel) => import(pathToFileURL(path.join(repoRoot, rel)).href);
const { issueAccountProductLeaseJws, spkiThumbprint } = await load('@bke/licensing/providers/ed25519-account-product-lease.ts');
const { createEd25519CommercialLeaseSigner } = await load('@bke/licensing/providers/ed25519-commercial-lease-signer.ts');
const { createInMemoryLeaseChallengeStore, issueLeaseChallenge, signLeaseChallengeProof } = await load('@bke/licensing/logic/lease-challenge-proof.ts');

const authKp = generateKeyPairSync('ed25519');
const agentKp = generateKeyPairSync('ed25519');
const authPubPem = authKp.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const authPrivPem = authKp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const agentPubPem = agentKp.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const agentPrivPem = agentKp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const thumb = spkiThumbprint(agentKp.publicKey);
const now = new Date('2026-11-15T12:00:00.000Z');

const accountJws = issueAccountProductLeaseJws({
  schema: 'bke.product-lease.v1',
  issuer: 'https://live-interop.test',
  audience: 'bke-desktop',
  leaseId: 'lease-live-001',
  accountId: 'acct-live-001',
  userId: 'usr-live-001',
  productId: 'render-dock',
  agentSessionId: 'sess-live-001',
  agentKeyThumbprint: thumb,
  keyProtection: 'tpm',
  plan: 'PRO',
  allowedActions: ['OPEN', 'USE'],
  issuedAt: '2026-11-15T11:55:00.000Z',
  refreshAfter: '2026-11-15T18:00:00.000Z',
  expiresAt: '2026-11-16T12:00:00.000Z',
}, { kid: 'live-authority-k1', privateKeyPem: authPrivPem });

const signer = createEd25519CommercialLeaseSigner({ resolve: () => authPrivPem });
const commercialEnvelope = await signer.issue({
  license_id: 'lic-live-001',
  lease_id: 'comm-lease-live-001',
  generation: 1,
  server_revision: 1,
  product_id: 'render-dock',
  installation_id: 'inst-live-device-0001',
  device_id: 'dev-live-machine-0001',
  version: '2.5.0',
  issuer: 'BKE Digital Solutions',
  issued_at: '2026-11-15T11:55:00.000Z',
  not_before: '2026-11-15T11:55:00.000Z',
  expires_at: '2026-12-15T12:00:00.000Z',
  key_id: 'comm-live-k1',
  algorithm: 'Ed25519',
  revoked: false,
  superseded_by: null,
}, {
  id: 'krec-1',
  keyId: 'comm-live-k1',
  algorithm: 'Ed25519',
  status: 'ACTIVE',
  publicKey: authPubPem,
  privateKeyReference: 'mem:live',
  createdAt: now,
  activatedAt: now,
  retiredAt: null,
  rotationReason: null,
  createdBy: 'interop',
});

const store = createInMemoryLeaseChallengeStore();
const chg = await issueLeaseChallenge(store, {
  challengeId: 'chg-live-001',
  accountId: 'acct-live-001',
  userId: 'usr-live-001',
  productId: 'render-dock',
  agentSessionId: 'sess-live-001',
  agentKeyThumbprint: thumb,
  action: 'OPEN',
  now,
});
const popSig = signLeaseChallengeProof(chg.messageBase64url, agentPrivPem);

console.log(JSON.stringify({
  authPubPem,
  agentPubPem,
  thumb,
  accountJws,
  commercialEnvelope,
  challengeRecord: {
    ...chg.record,
    createdAt: chg.record.createdAt.toISOString(),
    expiresAt: chg.record.expiresAt.toISOString(),
  },
  challengeMsgB64: chg.messageBase64url,
  challengeSigB64: popSig,
}));
""";
        var liveMintJson = RunInlineTsx(tsRepoPath, inlineScript);
        using var mintDoc = JsonDocument.Parse(liveMintJson);
        var root = mintDoc.RootElement;

        var authPubPem = root.GetProperty("authPubPem").GetString()!;
        var agentPubPem = root.GetProperty("agentPubPem").GetString()!;
        var thumb = root.GetProperty("thumb").GetString()!;
        var accountJws = root.GetProperty("accountJws").GetString()!;
        var now = DateTimeOffset.Parse("2026-11-15T12:00:00.000Z");

        var acctDecision = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            DisallowPublicTestKeys = true,
            AccountJws = accountJws,
            AccountTrustedKeys = new Dictionary<string, AccountProductLeaseTrustedKey>
            {
                ["live-authority-k1"] = new(authPubPem, AccountProductLeaseKeyStates.Active),
            },
            AccountExpected = new AccountProductLeaseVerificationContext(
                "https://live-interop.test",
                "bke-desktop",
                "acct-live-001",
                "usr-live-001",
                "render-dock",
                "sess-live-001",
                thumb,
                "OPEN",
                now,
                DisallowPublicTestKeys: true),
        });
        Assert.True(acctDecision.Authorized);
        Assert.Equal("lease-live-001", acctDecision.LeaseId);

        var envElem = root.GetProperty("commercialEnvelope");
        var env = new CommercialLeaseEnvelope(
            envElem.GetProperty("payload").GetString()!,
            envElem.GetProperty("signature").GetString()!,
            envElem.GetProperty("key_id").GetString()!,
            envElem.GetProperty("algorithm").GetString()!);

        var commDecision = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.LicenseKey,
            DisallowPublicTestKeys = true,
            CommercialEnvelope = env,
            CommercialTrustedKeys = new Dictionary<string, CommercialLeaseTrustedKey>
            {
                ["comm-live-k1"] = new(authPubPem, CommercialLeaseKeyStatuses.Active),
            },
            CommercialExpected = new CommercialLeaseVerificationContext(
                "BKE Digital Solutions",
                "render-dock",
                "inst-live-device-0001",
                "dev-live-machine-0001",
                "2.5.0",
                now,
                DisallowPublicTestKeys: true),
        });
        Assert.True(commDecision.Authorized);
        Assert.Equal("comm-lease-live-001", commDecision.LeaseId);

        var recElem = root.GetProperty("challengeRecord");
        var challengeStore = new InMemoryLeaseChallengeStore();
        challengeStore.IssueChallenge(new LeaseChallengeRecord(
            recElem.GetProperty("challengeId").GetString()!,
            recElem.GetProperty("accountId").GetString()!,
            recElem.GetProperty("userId").GetString()!,
            recElem.GetProperty("productId").GetString()!,
            recElem.GetProperty("agentSessionId").GetString()!,
            recElem.GetProperty("agentKeyThumbprint").GetString()!,
            recElem.GetProperty("action").GetString()!,
            recElem.GetProperty("nonce").GetString()!,
            recElem.GetProperty("messageHash").GetString()!,
            DateTimeOffset.Parse(recElem.GetProperty("createdAt").GetString()!),
            DateTimeOffset.Parse(recElem.GetProperty("expiresAt").GetString()!),
            null));

        var popMsgB64 = root.GetProperty("challengeMsgB64").GetString()!;
        var popSigB64 = root.GetProperty("challengeSigB64").GetString()!;
        var popFirst = LeaseChallengeProofVerifier.VerifyAndConsume(
            challengeStore,
            "chg-live-001",
            popMsgB64,
            popSigB64,
            agentPubPem,
            "acct-live-001",
            "usr-live-001",
            "render-dock",
            "sess-live-001",
            thumb,
            "OPEN",
            now);
        Assert.True(popFirst.Ok);

        var popReplay = LeaseChallengeProofVerifier.VerifyAndConsume(
            challengeStore,
            "chg-live-001",
            popMsgB64,
            popSigB64,
            agentPubPem,
            "acct-live-001",
            "usr-live-001",
            "render-dock",
            "sess-live-001",
            thumb,
            "OPEN",
            now);
        Assert.False(popReplay.Ok);
        Assert.Equal(LeaseChallengeFailureReasons.ChallengeAlreadyConsumed, popReplay.Reason);
    }

    [Fact]
    public void CloudflareWorkerFixture_EmitsRealSignedBytes_VerifiedInDotNet()
    {
        var tsRepoPath = ResolveTypeScriptRepoPath();
        if (tsRepoPath is null)
        {
            Assert.True(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI")), "CI must supply BKE_TS_REPO_PATH");
            return;
        }

        var workerFixtureDir = Path.Combine(tsRepoPath, "fixtures", "cloudflare-licensing-worker");
        Assert.True(Directory.Exists(workerFixtureDir), $"Missing Cloudflare worker fixture at {workerFixtureDir}");

        const string inlineHarnessScript = """
import { createTestHarness } from 'wrangler';
import { generateKeyPairSync, sign, randomUUID } from 'node:crypto';

const ATTESTATION_DOMAIN = "BKE-AGENT-STARTUP-INSTALL-ATTESTATION-V1\n";
const DEFAULT_AGENT_PRIVATE_KEY_PEM =
  "-----BEGIN PRIVATE KEY-----\n" +
  "MC4CAQAwBQYDK2VwBCIEIDmiRmOgeUcW+4yKJLLfZmIJn10vYVvWsUZPCpKdSHH9\n" +
  "-----END PRIVATE KEY-----\n";

function createTestInstallAttestation(options = {}) {
  const installationId = options.installationId ?? '00000000-0000-0000-0000-000000000123';
  const productId = options.productId ?? 'render-dock';
  const version = options.version ?? '1.0.3';
  const imagePath = options.imagePath ?? 'C:\\Program Files\\BKE Digital Solutions\\Render Dock\\RENDER DOCK.exe';
  const imageSha256 = options.imageSha256 ?? 'a'.repeat(64);
  const allowedUserSid = options.allowedUserSid ?? 'S-1-5-21-111-222-333-1001';
  const deviceId = options.deviceId ?? 'dev_cf_machine_0001';
  const attestationId = options.attestationId ?? randomUUID();
  const now = new Date();
  const issuedAt = options.issuedAt ?? now.toISOString();
  const expiresAt = options.expiresAt ?? new Date(now.getTime() + 60000).toISOString();
  const kid = options.kid ?? 'startup-test-key-001';
  const privateKeyPem = options.privateKeyPem ?? DEFAULT_AGENT_PRIVATE_KEY_PEM;

  const payload = JSON.stringify({
    schema: 'bke.agent-startup-install-attestation.v1',
    product_id: productId,
    version,
    installation_id: installationId,
    image_path: imagePath,
    image_sha256: imageSha256,
    allowed_user_sid: allowedUserSid,
    device_id: deviceId,
    attestation_id: attestationId,
    issued_at: issuedAt,
    expires_at: expiresAt,
  });

  const message = Buffer.from(ATTESTATION_DOMAIN + payload, 'utf8');
  const signature = sign(null, message, privateKeyPem).toString('base64');

  return JSON.stringify({
    schema: 'bke.agent-startup-install-attestation-envelope.v1',
    kid,
    payload,
    signature,
  });
}

const configPath = './wrangler.jsonc';
const harness = createTestHarness({
  workers: [{ configPath }],
});

await harness.listen();
try {
  const healthRes = await harness.fetch('http://localhost/health');
  const health = await healthRes.json();

  const keysRes = await harness.fetch('http://localhost/api/test/public-keys');
  const keys = await keysRes.json();

  const acctRes = await harness.fetch('http://localhost/api/test/issue-account-lease', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      productId: 'render-dock',
      accountId: 'acct_cf_test_001',
      userId: 'usr_cf_test_001',
      allowedActions: ['OPEN', 'USE'],
      ttlMinutes: 20,
    }),
  });
  const acct = await acctRes.json();

  const commRes = await harness.fetch('http://localhost/api/test/issue-commercial-lease', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      productId: 'render-dock',
      installationId: '00000000-0000-0000-0000-000000000123',
      deviceId: 'dev_cf_machine_0001',
      version: '1.0.3',
      ttlMinutes: 60,
    }),
  });
  const comm = await commRes.json();

  const attestation = createTestInstallAttestation();
  const startupRes = await harness.fetch('http://localhost/api/agent-sessions/startup-policy', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-bke-test-fixture': 'disposable-nonproduction',
      'x-bke-startup-policy-protocol': 'bke.installed-startup-issuance.v1',
    },
    body: JSON.stringify({
      signed_install_attestation: attestation,
    }),
  });
  const startup = await startupRes.json();

  console.log(JSON.stringify({
    health,
    keys,
    acct,
    comm,
    startup,
  }));
} finally {
  await harness.close();
}
""";

        var liveOutput = RunInlineNodeModule(workerFixtureDir, inlineHarnessScript);
        using var doc = JsonDocument.Parse(liveOutput);
        var root = doc.RootElement;

        // 1. Verify health & runtime identity
        var health = root.GetProperty("health");
        Assert.Equal("ok", health.GetProperty("status").GetString());
        Assert.Equal("cloudflare-worker-workerd", health.GetProperty("runtime").GetString());

        // 2. Extract public key
        var keysArray = root.GetProperty("keys").GetProperty("keys");
        var activeKey = keysArray[0];
        var kid = activeKey.GetProperty("kid").GetString()!;
        var pubPem = activeKey.GetProperty("publicKeyPem").GetString()!;

        // 3. Cryptographically verify the real Account Lease JWS in .NET
        var acctElem = root.GetProperty("acct");
        var jws = acctElem.GetProperty("jws").GetString()!;
        var claimsElem = acctElem.GetProperty("claims");
        var issuedAt = DateTimeOffset.Parse(claimsElem.GetProperty("issuedAt").GetString()!);

        var acctKeys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            [kid] = new(pubPem, AccountProductLeaseKeyStates.Active),
        };
        var acctExpected = new AccountProductLeaseVerificationContext(
            claimsElem.GetProperty("issuer").GetString()!,
            claimsElem.GetProperty("audience").GetString()!,
            claimsElem.GetProperty("accountId").GetString()!,
            claimsElem.GetProperty("userId").GetString()!,
            claimsElem.GetProperty("productId").GetString()!,
            claimsElem.GetProperty("agentSessionId").GetString()!,
            claimsElem.GetProperty("agentKeyThumbprint").GetString()!,
            "OPEN",
            issuedAt.AddMinutes(1),
            DisallowPublicTestKeys: true);

        var acctVerification = AccountProductLeaseVerifier.Verify(jws, acctKeys, acctExpected);
        Assert.True(acctVerification.Ok, $"Account lease JWS from Worker failed: {acctVerification.Reason}");
        Assert.NotNull(acctVerification.Claims);
        Assert.Equal("render-dock", acctVerification.Claims.ProductId);

        // Negative: tampered JWS rejected by .NET
        var jwsParts = jws.Split('.');
        var tamperedJws = $"{jwsParts[0]}.{Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{\"tampered\":true}"))}.{jwsParts[2]}";
        var tamperedAcct = AccountProductLeaseVerifier.Verify(tamperedJws, acctKeys, acctExpected);
        Assert.False(tamperedAcct.Ok);

        // 4. Cryptographically verify the real Commercial Lease Envelope in .NET
        var commElem = root.GetProperty("comm");
        var envElem = commElem.GetProperty("envelope");
        var commercialEnvelope = new CommercialLeaseEnvelope(
            envElem.GetProperty("payload").GetString()!,
            envElem.GetProperty("signature").GetString()!,
            envElem.GetProperty("key_id").GetString()!,
            envElem.GetProperty("algorithm").GetString()!);

        var commKeys = new Dictionary<string, CommercialLeaseTrustedKey>
        {
            [kid] = new(pubPem, CommercialLeaseKeyStatuses.Active),
        };
        var commExpected = new CommercialLeaseVerificationContext(
            "BKE Digital Solutions",
            "render-dock",
            "00000000-0000-0000-0000-000000000123",
            "dev_cf_machine_0001",
            "1.0.3",
            issuedAt.AddMinutes(1),
            DisallowPublicTestKeys: true);

        var commVerification = CommercialLeaseVerifier.Verify(commercialEnvelope, commKeys, commExpected);
        Assert.True(commVerification.Ok, $"Commercial lease from Worker failed: {commVerification.Reason}");
        Assert.NotNull(commVerification.Payload);
        Assert.Equal("render-dock", commVerification.Payload.ProductId);

        // Negative: tampered commercial payload rejected by .NET
        var tamperedPayload = commercialEnvelope.Payload.Replace("render-dock", "tampered-dock");
        var tamperedComm = CommercialLeaseVerifier.Verify(commercialEnvelope with { Payload = tamperedPayload }, commKeys, commExpected);
        Assert.False(tamperedComm.Ok);
        Assert.Equal(CommercialLeaseFailureReasons.InvalidSignature, tamperedComm.Reason);

        // 5. Cryptographically verify the real Standalone Startup Policy Envelope in .NET
        var startupElem = root.GetProperty("startup");
        Assert.Equal("issued", startupElem.GetProperty("status").GetString());
        Assert.Equal("LICENSE_KEY", startupElem.GetProperty("activation_mode").GetString());
        Assert.Equal(kid, startupElem.GetProperty("kid").GetString());

        // Verify startup expires_at is in canonical .NET format
        var topLevelExpiresAtStr = startupElem.GetProperty("expires_at").GetString()!;
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}\+00:00$", topLevelExpiresAtStr);
        var parsedTopLevelExpires = DateTimeOffset.Parse(topLevelExpiresAtStr, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind);
        Assert.Equal(topLevelExpiresAtStr, parsedTopLevelExpires.ToString("O", System.Globalization.CultureInfo.InvariantCulture));

        var signedEnv = startupElem.GetProperty("signed_policy_envelope").GetString()!;
        using var envDoc = JsonDocument.Parse(signedEnv);
        var envRoot = envDoc.RootElement;
        Assert.Equal("bke.standalone-startup-envelope.v1", envRoot.GetProperty("schema").GetString());
        Assert.Equal(kid, envRoot.GetProperty("kid").GetString());
        var rawPolicyPayload = envRoot.GetProperty("payload").GetString()!;
        var rawSignatureBase64 = envRoot.GetProperty("signature").GetString()!;

        // Cryptographically verify Ed25519 signature over (Domain + payload) using BouncyCastle
        var sigBytes = Convert.FromBase64String(rawSignatureBase64);
        var signedData = System.Text.Encoding.UTF8.GetBytes("BKE-STANDALONE-STARTUP-POLICY-V1\n" + rawPolicyPayload);

        Assert.True(Ed25519KeyUtilities.TryParsePublicKey(pubPem, out var pubKeyParams), "Failed to parse issuer public key PEM");
        var policyVerifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        policyVerifier.Init(false, pubKeyParams);
        policyVerifier.BlockUpdate(signedData, 0, signedData.Length);
        Assert.True(policyVerifier.VerifySignature(sigBytes), "Ed25519 signature of startup policy failed in .NET");

        // Verify policy payload fields match enrolled fixture identity
        using var policyDoc = JsonDocument.Parse(rawPolicyPayload);
        var policyRoot = policyDoc.RootElement;
        Assert.Equal("bke.standalone-startup-policy.v1", policyRoot.GetProperty("schema").GetString());
        Assert.Equal("09c16bc5c7e1d6ab3cb8df0ba569e6da05498f3f", policyRoot.GetProperty("issuer_source_sha").GetString());
        Assert.Equal("render-dock", policyRoot.GetProperty("product_id").GetString());
        Assert.Equal("1.0.3", policyRoot.GetProperty("version").GetString());
        Assert.Equal("00000000-0000-0000-0000-000000000123", policyRoot.GetProperty("installation_id").GetString());
        Assert.Equal("LICENSE_KEY", policyRoot.GetProperty("activation_mode").GetString());

        // Verify policy payload timestamps adhere to canonical .NET roundtrip format expected by Agent RequiredTime()
        var policyNotBeforeStr = policyRoot.GetProperty("not_before").GetString()!;
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}\+00:00$", policyNotBeforeStr);
        var parsedNotBefore = DateTimeOffset.Parse(policyNotBeforeStr, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind);
        Assert.Equal(policyNotBeforeStr, parsedNotBefore.ToString("O", System.Globalization.CultureInfo.InvariantCulture));

        var policyExpiresAtStr = policyRoot.GetProperty("expires_at").GetString()!;
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}\+00:00$", policyExpiresAtStr);
        var parsedPolicyExpires = DateTimeOffset.Parse(policyExpiresAtStr, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind);
        Assert.Equal(policyExpiresAtStr, parsedPolicyExpires.ToString("O", System.Globalization.CultureInfo.InvariantCulture));

        // Negative: Tampered signature rejected in .NET
        var corruptedSig = (byte[])sigBytes.Clone();
        corruptedSig[0] ^= 0xFF;
        var tamperVerifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        tamperVerifier.Init(false, pubKeyParams);
        tamperVerifier.BlockUpdate(signedData, 0, signedData.Length);
        Assert.False(tamperVerifier.VerifySignature(corruptedSig));

        // Negative: Tampered policy payload rejected in .NET
        var tamperedPolicyData = System.Text.Encoding.UTF8.GetBytes("BKE-STANDALONE-STARTUP-POLICY-V1\n" + rawPolicyPayload.Replace("render-dock", "tampered-dock"));
        var tamperPayloadVerifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        tamperPayloadVerifier.Init(false, pubKeyParams);
        tamperPayloadVerifier.BlockUpdate(tamperedPolicyData, 0, tamperedPolicyData.Length);
        Assert.False(tamperPayloadVerifier.VerifySignature(sigBytes));
    }

    private static void AssertSuite(JsonElement root)
    {
        // 1. Account-product lease vectors (14 cases)
        var acct = root.GetProperty("accountProductLease");
        var acctNow = DateTimeOffset.Parse(acct.GetProperty("now").GetString()!);
        var acctPub = acct.GetProperty("publicKeyPem").GetString()!;
        var activeKid = acct.GetProperty("activeKid").GetString()!;
        var retiredKid = acct.GetProperty("retiredKid").GetString()!;
        var acctKeys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            [activeKid] = new(acctPub, AccountProductLeaseKeyStates.Active),
            [retiredKid] = new(acctPub, AccountProductLeaseKeyStates.Revoked),
        };
        var acctExp = acct.GetProperty("expected");
        var acctContext = new AccountProductLeaseVerificationContext(
            acctExp.GetProperty("issuer").GetString()!,
            acctExp.GetProperty("audience").GetString()!,
            acctExp.GetProperty("accountId").GetString()!,
            acctExp.GetProperty("userId").GetString()!,
            acctExp.GetProperty("productId").GetString()!,
            acctExp.GetProperty("agentSessionId").GetString()!,
            acctExp.GetProperty("agentKeyThumbprint").GetString()!,
            acctExp.GetProperty("action").GetString()!,
            acctNow,
            DisallowPublicTestKeys: false);

        foreach (var vector in acct.GetProperty("vectors").EnumerateArray())
        {
            var name = vector.GetProperty("name").GetString()!;
            var jws = vector.GetProperty("jws").GetString()!;
            var accept = vector.GetProperty("accept").GetBoolean();
            var result = AccountProductLeaseVerifier.Verify(jws, acctKeys, acctContext);
            Assert.True(result.Ok == accept, $"Account vector '{name}' expected accept={accept} but got ok={result.Ok} reason={result.Reason}");
            if (!accept)
            {
                Assert.Equal(vector.GetProperty("reason").GetString(), result.Reason);
            }
        }

        // 2. Commercial lease vectors (19 cases)
        var comm = root.GetProperty("commercialLease");
        var commNow = DateTimeOffset.Parse(comm.GetProperty("now").GetString()!);
        var commExp = comm.GetProperty("expected");
        var commKeys = new Dictionary<string, CommercialLeaseTrustedKey>();
        foreach (var k in comm.GetProperty("keys").EnumerateArray())
        {
            commKeys[k.GetProperty("keyId").GetString()!] = new(
                k.GetProperty("publicKey").GetString()!,
                k.GetProperty("status").GetString()!);
        }
        var baseCommContext = new CommercialLeaseVerificationContext(
            commExp.GetProperty("issuer").GetString()!,
            commExp.GetProperty("productId").GetString()!,
            commExp.GetProperty("installationId").GetString()!,
            commExp.GetProperty("deviceId").GetString()!,
            commExp.GetProperty("version").GetString()!,
            commNow,
            DisallowPublicTestKeys: false);

        foreach (var vector in comm.GetProperty("vectors").EnumerateArray())
        {
            var name = vector.GetProperty("name").GetString()!;
            var env = vector.GetProperty("envelope");
            var envelope = new CommercialLeaseEnvelope(
                env.GetProperty("payload").GetString()!,
                env.GetProperty("signature").GetString()!,
                env.GetProperty("key_id").GetString()!,
                env.GetProperty("algorithm").GetString()!);
            var accept = vector.GetProperty("accept").GetBoolean();
            var strict = vector.TryGetProperty("disallowPublicTestKeys", out var dpt) && dpt.GetBoolean();
            var ctx = baseCommContext with { DisallowPublicTestKeys = strict };
            var result = CommercialLeaseVerifier.Verify(envelope, commKeys, ctx);
            Assert.True(result.Ok == accept, $"Commercial vector '{name}' expected accept={accept} but got ok={result.Ok} reason={result.Reason}");
            if (!accept)
            {
                Assert.Equal(vector.GetProperty("reason").GetString(), result.Reason);
            }
        }

        // 3. Challenge PoP vectors
        var chg = root.GetProperty("challengeProof");
        var chgNow = DateTimeOffset.Parse(chg.GetProperty("now").GetString()!);
        var agentPub = chg.GetProperty("agentPublicKeyPem").GetString()!;
        var wrongAgentPub = chg.GetProperty("wrongAgentPublicKeyPem").GetString()!;
        var rec = chg.GetProperty("record");
        var record = new LeaseChallengeRecord(
            rec.GetProperty("challengeId").GetString()!,
            rec.GetProperty("accountId").GetString()!,
            rec.GetProperty("userId").GetString()!,
            rec.GetProperty("productId").GetString()!,
            rec.GetProperty("agentSessionId").GetString()!,
            rec.GetProperty("agentKeyThumbprint").GetString()!,
            rec.GetProperty("action").GetString()!,
            rec.GetProperty("nonce").GetString()!,
            rec.GetProperty("messageHash").GetString()!,
            DateTimeOffset.Parse(rec.GetProperty("createdAt").GetString()!),
            DateTimeOffset.Parse(rec.GetProperty("expiresAt").GetString()!),
            null);

        var msgB64 = chg.GetProperty("validMessageBase64url").GetString()!;
        var sigB64 = chg.GetProperty("validSignatureBase64url").GetString()!;
        var forgedSigB64 = chg.GetProperty("forgedSignatureBase64url").GetString()!;

        var store = new InMemoryLeaseChallengeStore();
        store.IssueChallenge(record);
        Assert.True(LeaseChallengeProofVerifier.VerifyAndConsume(
            store, record.ChallengeId, msgB64, sigB64, agentPub,
            record.AccountId, record.UserId, record.ProductId, record.AgentSessionId, record.AgentKeyThumbprint, record.Action,
            chgNow).Ok);
        var replay = LeaseChallengeProofVerifier.VerifyAndConsume(
            store, record.ChallengeId, msgB64, sigB64, agentPub,
            record.AccountId, record.UserId, record.ProductId, record.AgentSessionId, record.AgentKeyThumbprint, record.Action,
            chgNow);
        Assert.Equal(LeaseChallengeFailureReasons.ChallengeAlreadyConsumed, replay.Reason);

        var storeWrongKey = new InMemoryLeaseChallengeStore();
        storeWrongKey.IssueChallenge(record);
        var wrongKeyResult = LeaseChallengeProofVerifier.VerifyAndConsume(
            storeWrongKey, record.ChallengeId, msgB64, forgedSigB64, wrongAgentPub,
            record.AccountId, record.UserId, record.ProductId, record.AgentSessionId, record.AgentKeyThumbprint, record.Action,
            chgNow);
        Assert.Equal(LeaseChallengeFailureReasons.ScopeMismatch, wrongKeyResult.Reason);

        // 4. Activation mode cases
        foreach (var modeCase in root.GetProperty("activationModes").EnumerateArray())
        {
            var res = ActivationModePolicy.Evaluate(
                modeCase.GetProperty("mode").GetString(),
                modeCase.GetProperty("credential").GetString());
            var ok = modeCase.GetProperty("ok").GetBoolean();
            Assert.Equal(ok, res.Ok);
            if (!ok)
            {
                Assert.Equal(modeCase.GetProperty("reason").GetString(), res.Reason);
            }
        }
    }

    private static string? ResolveTypeScriptRepoPath()
    {
        var env = Environment.GetEnvironmentVariable("BKE_TS_REPO_PATH");
        if (!string.IsNullOrWhiteSpace(env) && Directory.Exists(env))
        {
            return Path.GetFullPath(env);
        }

        // Walk up to find sibling bke-libraries-typescript during local runs.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "bke-libraries-typescript");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
            dir = dir.Parent;
        }
        return null;
    }

    private static string RunNodeScript(string workDir, string scriptPath)
    {
        var psi = new ProcessStartInfo("node")
        {
            WorkingDirectory = workDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(scriptPath);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"node failed ({p.ExitCode}): {stderr}");
        return stdout;
    }

    private static string RunInlineTsx(string workDir, string moduleSource)
    {
        var tmpFile = Path.Combine(Path.GetTempPath(), $"bke-interop-mint-{Guid.NewGuid():N}.mjs");
        File.WriteAllText(tmpFile, moduleSource);
        try
        {
            var tsxEntry = Path.Combine(workDir, "node_modules", "tsx", "dist", "cli.mjs");
            var psi = new ProcessStartInfo("node")
            {
                WorkingDirectory = workDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding = System.Text.Encoding.UTF8,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.Environment["BKE_TS_WORK_DIR"] = workDir;
            psi.ArgumentList.Add(tsxEntry);
            psi.ArgumentList.Add(tmpFile);
            using var p = Process.Start(psi)!;
            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();
            Assert.True(p.ExitCode == 0, $"tsx failed ({p.ExitCode}): {stderr}");
            return stdout;
        }
        finally
        {
            if (File.Exists(tmpFile))
            {
                File.Delete(tmpFile);
            }
        }
    }

    private static string RunInlineNodeModule(string workDir, string moduleSource)
    {
        var tmpFile = Path.Combine(workDir, $"bke-worker-test-{Guid.NewGuid():N}.mjs");
        File.WriteAllText(tmpFile, moduleSource, System.Text.Encoding.UTF8);
        try
        {
            var psi = new ProcessStartInfo("node")
            {
                WorkingDirectory = workDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding = System.Text.Encoding.UTF8,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add(tmpFile);
            using var p = Process.Start(psi)!;
            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();
            Assert.True(p.ExitCode == 0, $"node failed ({p.ExitCode}): {stderr}");
            return stdout;
        }
        finally
        {
            if (File.Exists(tmpFile))
            {
                File.Delete(tmpFile);
            }
        }
    }
}
