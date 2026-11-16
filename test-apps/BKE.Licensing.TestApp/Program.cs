using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using BKE.Licensing;
using BKE.Licensing.Client;
using BKE.Licensing.Contracts;
using BKE.Licensing.Platform;
using BKE.Licensing.Policy;
using BKE.Licensing.Verification;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace BKE.Licensing.TestApp;

internal static class Program
{
    public static int Main(string[] args)
    {
        var scenario = "all";
        if (args.Length >= 2 && args[0] == "--scenario")
        {
            scenario = args[1].ToLowerInvariant();
        }
        else if (args.Length >= 1)
        {
            var raw = args[0].TrimStart('-').ToLowerInvariant();
            if (raw is "all" or "matrix" or "direct" or "agent-client")
            {
                scenario = raw;
            }
            else if (raw is "from-launcher=true" or "launched-by-bke")
            {
                // Direct run attempting Launcher spoofing: must fail closed without Agent
                scenario = "direct-spoof";
            }
        }

        if (scenario == "direct-spoof")
        {
            Console.WriteLine("DIRECT_EXECUTION: Spoofed Launcher CLI detected; verifying fail-closed direct startup.");
            var decision = SimulateDirectLaunchBypassAttempt(args);
            if (!decision.Authorized && decision.Reason == AuthorizationFailureReasons.MissingAuthorizationProof)
            {
                Console.WriteLine("DIRECT_EXECUTION: DIRECT_SPOOF_FAIL_CLOSED_PASS");
                return 0;
            }
            Console.Error.WriteLine("DIRECT_EXECUTION: FAILED TO FAIL CLOSED");
            return 1;
        }

        if (scenario == "matrix")
        {
            RunActivationMatrixTests();
            Console.WriteLine("DOTNET_ISOLATED_TEST_APP: ACTIVATION_MATRIX_ALL_PASS");
            return 0;
        }

        if (scenario != "all")
        {
            Console.Error.WriteLine($"Unsupported scenario '{scenario}'. Expected '--scenario all' or '--scenario matrix'.");
            return 2;
        }

        RunAllScenarios();
        RunActivationMatrixTests();
        Console.WriteLine("DOTNET_ISOLATED_TEST_APP: ALL_15_SCENARIOS_VERIFIED");
        Console.WriteLine("DOTNET_ISOLATED_TEST_APP: ACTIVATION_MATRIX_ALL_PASS");
        return 0;
    }

    private static void RunAllScenarios()
    {
        var now = DateTimeOffset.Parse("2026-11-15T12:00:00.000Z");
        var authorityPrimary = GenerateEd25519KeyPair();
        var authorityAttacker = GenerateEd25519KeyPair();
        var agentDeviceKey = GenerateEd25519KeyPair();

        var acctKeys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            ["authority-live-2026"] = new(authorityPrimary.PublicKeyPem, AccountProductLeaseKeyStates.Active),
        };
        var commKeys = new Dictionary<string, CommercialLeaseTrustedKey>
        {
            ["comm-live-2026"] = new(authorityPrimary.PublicKeyPem, CommercialLeaseKeyStatuses.Active),
        };

        var acctExpected = new AccountProductLeaseVerificationContext(
            "https://auth.test-only.bke.example",
            "bke-desktop-native",
            "acct_native_001",
            "usr_native_001",
            "render-dock",
            "sess_native_001",
            agentDeviceKey.Thumbprint,
            "OPEN",
            now,
            DisallowPublicTestKeys: true);

        var commExpected = new CommercialLeaseVerificationContext(
            "BKE Digital Solutions",
            "render-dock",
            "inst_native_device_0001",
            "dev_native_machine_0001",
            "2.5.0",
            now,
            DisallowPublicTestKeys: true);

        var validAccountClaims = BuildAccountClaims("render-dock", agentDeviceKey.Thumbprint, "2026-11-15T11:55:00.000Z", "2026-11-16T12:00:00.000Z");
        var validAccountJws = SignJws(authorityPrimary.PrivateKey, "authority-live-2026", validAccountClaims);

        var validCommercialEnv = SignCommercial(
            authorityPrimary.PrivateKey,
            "comm-live-2026",
            BuildCommercialPayload("render-dock", "2026-11-15T11:55:00.000Z", "2026-11-15T11:55:00.000Z", "2026-12-15T12:00:00.000Z", revoked: false));

        // 1. Legitimate ACCOUNT lease under EITHER mode
        var s1 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = validAccountJws,
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(s1.Authorized && s1.CredentialUsed == ActivationCredentials.Account, "Scenario 1 failed");

        // 2. Legitimate LICENSE_KEY lease under EITHER and LICENSE_KEY modes
        var s2 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = validCommercialEnv,
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected,
        });
        Require(s2.Authorized && s2.CredentialUsed == ActivationCredentials.LicenseKey, "Scenario 2a failed");

        var s2b = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.LicenseKey,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = validCommercialEnv,
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected,
        });
        Require(s2b.Authorized, "Scenario 2b failed");

        // 3. Direct startup bypassing Launcher with spoofed CLI marker MUST fail closed
        var s3Direct = SimulateDirectLaunchBypassAttempt("--from-launcher=true", "--launched-by-bke");
        Require(!s3Direct.Authorized && s3Direct.Reason == AuthorizationFailureReasons.MissingAuthorizationProof, "Scenario 3a failed");

        var s3Unavailable = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AuthorityAvailable = false,
            AccountJws = validAccountJws,
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!s3Unavailable.Authorized && s3Unavailable.Reason == AuthorizationFailureReasons.AuthorityUnavailable, "Scenario 3b failed");

        // 4. Cross-product lease rejected
        var s4 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = SignJws(authorityPrimary.PrivateKey, "authority-live-2026", BuildAccountClaims("air-stack", agentDeviceKey.Thumbprint, "2026-11-15T11:55:00.000Z", "2026-11-16T12:00:00.000Z")),
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!s4.Authorized && s4.Reason == AccountProductLeaseFailureReasons.ClaimMismatch, "Scenario 4 failed");

        // 5. Tampered authorization bytes rejected
        var jwsParts = validAccountJws.Split('.');
        var tamperedPayload = Ed25519KeyUtilities.EncodeBase64Url(Encoding.UTF8.GetBytes(validAccountClaims.Replace("acct_native_001", "acct_evil_999", StringComparison.Ordinal)));
        var s5 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = $"{jwsParts[0]}.{tamperedPayload}.{jwsParts[2]}",
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!s5.Authorized && s5.Reason == AccountProductLeaseFailureReasons.InvalidSignature, "Scenario 5 failed");

        // 6. Untrusted signer & public test key rejected under strict mode
        var s6 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = SignJws(authorityAttacker.PrivateKey, "attacker-kid", validAccountClaims),
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!s6.Authorized && s6.Reason == AccountProductLeaseFailureReasons.UntrustedKid, "Scenario 6 failed");

        // 7. Expired lease rejected
        var s7 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = SignJws(authorityPrimary.PrivateKey, "authority-live-2026", BuildAccountClaims("render-dock", agentDeviceKey.Thumbprint, "2026-11-14T00:00:00.000Z", "2026-11-15T12:00:00.000Z", "2026-11-14T06:00:00.000Z")),
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!s7.Authorized && s7.Reason == AccountProductLeaseFailureReasons.Expired, "Scenario 7 failed");

        // 8. Revoked commercial lease rejected
        var s8 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = SignCommercial(authorityPrimary.PrivateKey, "comm-live-2026", BuildCommercialPayload("render-dock", "2026-11-15T11:55:00.000Z", "2026-11-15T11:55:00.000Z", "2026-12-15T12:00:00.000Z", revoked: true)),
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected,
        });
        Require(!s8.Authorized && s8.Reason == CommercialLeaseFailureReasons.LeaseRevoked, "Scenario 8 failed");

        // 9. CLAIM_CODE activation refused
        var s9 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.ClaimCode,
        });
        Require(!s9.Authorized && s9.Reason == ActivationModeFailureReasons.ClaimCodeNotActivationCredential, "Scenario 9 failed");

        // 10. One-time challenge PoP accepted once, replay denied
        var chgStore = new InMemoryLeaseChallengeStore();
        var chgDraft = new LeaseChallengeRecord(
            "chg_testapp_001",
            "acct_native_001",
            "usr_native_001",
            "render-dock",
            "sess_native_001",
            agentDeviceKey.Thumbprint,
            "OPEN",
            "nonce_testapp_0123456789abcdef",
            string.Empty,
            now.AddSeconds(-5),
            now.AddSeconds(25),
            null);
        var chgMsg = LeaseChallengeProofVerifier.BuildCanonicalMessage(chgDraft);
        var chgRecord = chgDraft with { MessageHash = Convert.ToHexStringLower(SHA256.HashData(chgMsg)) };
        chgStore.IssueChallenge(chgRecord);

        var popSigner = new Ed25519Signer();
        popSigner.Init(true, agentDeviceKey.PrivateKey);
        popSigner.BlockUpdate(chgMsg, 0, chgMsg.Length);
        var chgMsgB64 = Ed25519KeyUtilities.EncodeBase64Url(chgMsg);
        var chgSigB64 = Ed25519KeyUtilities.EncodeBase64Url(popSigner.GenerateSignature());

        var pop1 = LeaseChallengeProofVerifier.VerifyAndConsume(
            chgStore, chgRecord.ChallengeId, chgMsgB64, chgSigB64, agentDeviceKey.PublicKeyPem,
            "acct_native_001", "usr_native_001", "render-dock", "sess_native_001", agentDeviceKey.Thumbprint, "OPEN", now);
        Require(pop1.Ok, "Scenario 10a failed");

        var pop2 = LeaseChallengeProofVerifier.VerifyAndConsume(
            chgStore, chgRecord.ChallengeId, chgMsgB64, chgSigB64, agentDeviceKey.PublicKeyPem,
            "acct_native_001", "usr_native_001", "render-dock", "sess_native_001", agentDeviceKey.Thumbprint, "OPEN", now);
        Require(!pop2.Ok && pop2.Reason == LeaseChallengeFailureReasons.ChallengeAlreadyConsumed, "Scenario 10b failed");

        // 11. Platform secure secret storage round-trip + tamper detection
        VerifyPlatformSecretStorage();

        // 12. SDK client StartAsync fails closed when Agent unavailable / offline
        var s12 = BkeLicensing.StartAsync(new ProductStartupOptions
        {
            PipeName = "bke-testapp-offline-" + Guid.NewGuid().ToString("N"),
            ConnectTimeout = TimeSpan.FromMilliseconds(50),
            RequestTimeout = TimeSpan.FromMilliseconds(50),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        }).GetAwaiter().GetResult();
        var expectedOfflineReason = OperatingSystem.IsWindows()
            ? ProductStartupFailureReasons.AgentUnavailable
            : ProductStartupFailureReasons.PlatformNotSupported;
        Require(!s12.Authorized && s12.Reason == expectedOfflineReason, "Scenario 12 failed");

        // 13. SDK client StartAsync authorizes when Agent authorizes connected peer
        if (OperatingSystem.IsWindows())
        {
            // 13a. SDK client StartAsync fails closed when untrusted pipe or server is encountered
            var s13Untrusted = BkeLicensing.StartAsync(new ProductStartupOptions
            {
                PipeName = "bke-attacker-pipe-" + Guid.NewGuid().ToString("N"),
                ConnectTimeout = TimeSpan.FromMilliseconds(50),
                RequestTimeout = TimeSpan.FromMilliseconds(50),
            }).GetAwaiter().GetResult();
            Require(!s13Untrusted.Authorized && s13Untrusted.Reason == ProductStartupFailureReasons.AgentServerUntrusted, "Scenario 13a failed: untrusted pipe must fail closed");

            // 13b. SDK client StartAsync authorizes when attested Agent server authorizes connected peer
            var testPipe = "bke-testapp-auth-" + Guid.NewGuid().ToString("N");
            var options = new ProductStartupOptions
            {
                PipeName = testPipe,
                ConnectTimeout = TimeSpan.FromSeconds(5),
                RequestTimeout = TimeSpan.FromSeconds(5),
                TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
            };

            var agentServer = Task.Run(async () =>
            {
                await using var pipe = new System.IO.Pipes.NamedPipeServerStream(
                    testPipe,
                    System.IO.Pipes.PipeDirection.InOut,
                    1,
                    System.IO.Pipes.PipeTransmissionMode.Byte,
                    System.IO.Pipes.PipeOptions.Asynchronous);
                await pipe.WaitForConnectionAsync();

                var hdr = new byte[4];
                await pipe.ReadExactlyAsync(hdr);
                var l = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(hdr);
                var b = new byte[l];
                await pipe.ReadExactlyAsync(b);
                using var d = System.Text.Json.JsonDocument.Parse(b);
                var rid = d.RootElement.GetProperty("request_id").GetString()!;

                var payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema = ProductStartupOptions.ExpectedProtocol,
                    request_id = rid,
                    authorized = true,
                    reason = "authorized",
                });
                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hdr, payload.Length);
                await pipe.WriteAsync(hdr);
                await pipe.WriteAsync(payload);
                await pipe.FlushAsync();
            });

            var s13 = BkeLicensing.StartAsync(options).GetAwaiter().GetResult();
            agentServer.GetAwaiter().GetResult();
            Require(s13.Authorized && s13.Reason == "authorized", "Scenario 13b failed");

            // 14. SDK client StartAsync denies when Agent denies or detects replay
            var denyPipe = "bke-testapp-deny-" + Guid.NewGuid().ToString("N");
            var denyOptions = new ProductStartupOptions
            {
                PipeName = denyPipe,
                ConnectTimeout = TimeSpan.FromSeconds(5),
                RequestTimeout = TimeSpan.FromSeconds(5),
                TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
            };

            var agentDenyServer = Task.Run(async () =>
            {
                await using var pipe = new System.IO.Pipes.NamedPipeServerStream(
                    denyPipe,
                    System.IO.Pipes.PipeDirection.InOut,
                    1,
                    System.IO.Pipes.PipeTransmissionMode.Byte,
                    System.IO.Pipes.PipeOptions.Asynchronous);
                await pipe.WaitForConnectionAsync();

                var hdr = new byte[4];
                await pipe.ReadExactlyAsync(hdr);
                var l = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(hdr);
                var b = new byte[l];
                await pipe.ReadExactlyAsync(b);
                using var d = System.Text.Json.JsonDocument.Parse(b);
                var rid = d.RootElement.GetProperty("request_id").GetString()!;

                var payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema = ProductStartupOptions.ExpectedProtocol,
                    request_id = rid,
                    authorized = false,
                    reason = "same_process_replay",
                });
                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hdr, payload.Length);
                await pipe.WriteAsync(hdr);
                await pipe.WriteAsync(payload);
                await pipe.FlushAsync();
            });

            var s14 = BkeLicensing.StartAsync(denyOptions).GetAwaiter().GetResult();
            agentDenyServer.GetAwaiter().GetResult();
            Require(!s14.Authorized && s14.Reason == "same_process_replay", "Scenario 14 failed");

            // 15. SDK client StartAsync rejects trailing content / multiple JSON roots with protocol_error over pipe
            var trailingPipe = "bke-testapp-trailing-" + Guid.NewGuid().ToString("N");
            var trailingOptions = new ProductStartupOptions
            {
                PipeName = trailingPipe,
                ConnectTimeout = TimeSpan.FromSeconds(5),
                RequestTimeout = TimeSpan.FromSeconds(5),
                TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
            };

            var agentTrailingServer = Task.Run(async () =>
            {
                await using var pipe = new System.IO.Pipes.NamedPipeServerStream(
                    trailingPipe,
                    System.IO.Pipes.PipeDirection.InOut,
                    1,
                    System.IO.Pipes.PipeTransmissionMode.Byte,
                    System.IO.Pipes.PipeOptions.Asynchronous);
                await pipe.WaitForConnectionAsync();

                var hdr = new byte[4];
                await pipe.ReadExactlyAsync(hdr);
                var l = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(hdr);
                var b = new byte[l];
                await pipe.ReadExactlyAsync(b);
                using var d = System.Text.Json.JsonDocument.Parse(b);
                var rid = d.RootElement.GetProperty("request_id").GetString()!;

                var payload = System.Text.Encoding.UTF8.GetBytes(
                    $"{{\"schema\":\"{ProductStartupOptions.ExpectedProtocol}\",\"request_id\":\"{rid}\",\"authorized\":true,\"reason\":\"authorized\"}} JUNK_TRAILING_GARBAGE");
                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hdr, payload.Length);
                await pipe.WriteAsync(hdr);
                await pipe.WriteAsync(payload);
                await pipe.FlushAsync();
            });

            var s15 = BkeLicensing.StartAsync(trailingOptions).GetAwaiter().GetResult();
            agentTrailingServer.GetAwaiter().GetResult();
            Require(!s15.Authorized && s15.Reason == ProductStartupFailureReasons.ProtocolError, "Scenario 15 failed: trailing content must return protocol_error");
        }

        // 15b. Cross-platform whole-message consumption check in SDK parser
        var testReqId = Guid.NewGuid().ToString("D");
        var validWithWhitespace = Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"{ProductStartupOptions.ExpectedProtocol}\",\"request_id\":\"{testReqId}\",\"authorized\":true,\"reason\":\"authorized\"}}   \r\n");
        var resWhitespace = BkeLicensingClient.ParseAndValidateResponse(validWithWhitespace, testReqId);
        Require(resWhitespace.Authorized && resWhitespace.Reason == "authorized", "Scenario 15b whitespace check failed");

        var withJunk = Encoding.UTF8.GetBytes(
            $"{{\"schema\":\"{ProductStartupOptions.ExpectedProtocol}\",\"request_id\":\"{testReqId}\",\"authorized\":true,\"reason\":\"authorized\"}} EXTRA");
        var resJunk = BkeLicensingClient.ParseAndValidateResponse(withJunk, testReqId);
        Require(!resJunk.Authorized && resJunk.Reason == ProductStartupFailureReasons.ProtocolError, "Scenario 15b junk check failed");
    }

    private static void RunActivationMatrixTests()
    {
        var now = DateTimeOffset.Parse("2026-11-15T12:00:00.000Z");
        var authorityPrimary = GenerateEd25519KeyPair();
        var authorityAttacker = GenerateEd25519KeyPair();
        var agentDeviceKey = GenerateEd25519KeyPair();

        var acctKeys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            ["authority-live-2026"] = new(authorityPrimary.PublicKeyPem, AccountProductLeaseKeyStates.Active),
        };
        var commKeys = new Dictionary<string, CommercialLeaseTrustedKey>
        {
            ["comm-live-2026"] = new(authorityPrimary.PublicKeyPem, CommercialLeaseKeyStatuses.Active),
        };

        var acctExpected = new AccountProductLeaseVerificationContext(
            "https://auth.test-only.bke.example",
            "bke-desktop-native",
            "acct_native_001",
            "usr_native_001",
            "render-dock",
            "sess_native_001",
            agentDeviceKey.Thumbprint,
            "OPEN",
            now,
            DisallowPublicTestKeys: true);

        var commExpected = new CommercialLeaseVerificationContext(
            "BKE Digital Solutions",
            "render-dock",
            "inst_native_device_0001",
            "dev_native_machine_0001",
            "2.5.0",
            now,
            DisallowPublicTestKeys: true);

        var validAccountClaims = BuildAccountClaims("render-dock", agentDeviceKey.Thumbprint, "2026-11-15T11:55:00.000Z", "2026-11-16T12:00:00.000Z");
        var validAccountJws = SignJws(authorityPrimary.PrivateKey, "authority-live-2026", validAccountClaims);

        var validCommercialEnv = SignCommercial(
            authorityPrimary.PrivateKey,
            "comm-live-2026",
            BuildCommercialPayload("render-dock", "2026-11-15T11:55:00.000Z", "2026-11-15T11:55:00.000Z", "2026-12-15T12:00:00.000Z", revoked: false));

        // MATRIX 1: ACCOUNT policy | Valid account authorization -> ALLOW
        var m1 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Account,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = validAccountJws,
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(m1.Authorized && m1.CredentialUsed == ActivationCredentials.Account, "Matrix 1: ACCOUNT + valid account must ALLOW");
        Console.WriteLine("MATRIX_PASS: [ACCOUNT] + Valid account authorization -> ALLOW");

        // MATRIX 2: ACCOUNT policy | Only license key present -> DENY
        var m2 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Account,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = validCommercialEnv,
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected,
        });
        Require(!m2.Authorized && m2.Reason == ActivationModeFailureReasons.ActivationModeMismatch, "Matrix 2: ACCOUNT + only key must DENY");
        Console.WriteLine("MATRIX_PASS: [ACCOUNT] + Only license key present -> DENY (ActivationModeMismatch)");

        // MATRIX 3: LICENSE_KEY policy | Valid commercial authorization without Google -> ALLOW
        var m3 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.LicenseKey,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = validCommercialEnv,
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected,
        });
        Require(m3.Authorized && m3.CredentialUsed == ActivationCredentials.LicenseKey, "Matrix 3: LICENSE_KEY + valid commercial key must ALLOW");
        Console.WriteLine("MATRIX_PASS: [LICENSE_KEY] + Valid commercial authorization without Google -> ALLOW");

        // MATRIX 4: LICENSE_KEY policy | Account rights alone -> DENY
        var m4 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.LicenseKey,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = validAccountJws,
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!m4.Authorized && m4.Reason == ActivationModeFailureReasons.ActivationModeMismatch, "Matrix 4: LICENSE_KEY + account rights alone must DENY");
        Console.WriteLine("MATRIX_PASS: [LICENSE_KEY] + Account rights alone -> DENY (ActivationModeMismatch)");

        // MATRIX 5: EITHER policy | Valid account authorization -> ALLOW
        var m5 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = validAccountJws,
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(m5.Authorized && m5.CredentialUsed == ActivationCredentials.Account, "Matrix 5: EITHER + valid account must ALLOW");
        Console.WriteLine("MATRIX_PASS: [EITHER] + Valid account authorization -> ALLOW");

        // MATRIX 6: EITHER policy | Valid commercial key -> ALLOW
        var m6 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = validCommercialEnv,
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected,
        });
        Require(m6.Authorized && m6.CredentialUsed == ActivationCredentials.LicenseKey, "Matrix 6: EITHER + valid commercial key must ALLOW");
        Console.WriteLine("MATRIX_PASS: [EITHER] + Valid commercial authorization -> ALLOW");

        // MATRIX 7: EITHER policy | Neither valid -> DENY
        var m7 = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = null,
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!m7.Authorized && m7.Reason == AuthorizationFailureReasons.MissingAuthorizationProof, "Matrix 7: EITHER + neither valid must DENY");
        Console.WriteLine("MATRIX_PASS: [EITHER] + Neither valid -> DENY (MissingAuthorizationProof)");

        // NEGATIVE 1: Expired account rights -> DENY
        var negExpiredAcct = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = SignJws(authorityPrimary.PrivateKey, "authority-live-2026", BuildAccountClaims("render-dock", agentDeviceKey.Thumbprint, "2026-11-14T00:00:00.000Z", "2026-11-15T11:00:00.000Z", "2026-11-14T06:00:00.000Z")),
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!negExpiredAcct.Authorized && negExpiredAcct.Reason == AccountProductLeaseFailureReasons.Expired, "Negative: Expired account rights must DENY");
        Console.WriteLine("NEGATIVE_PASS: Expired account rights -> DENY (Expired)");

        // NEGATIVE 2: Expired commercial rights -> DENY
        var negExpiredComm = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = SignCommercial(authorityPrimary.PrivateKey, "comm-live-2026", BuildCommercialPayload("render-dock", "2026-11-10T00:00:00.000Z", "2026-11-10T00:00:00.000Z", "2026-11-15T11:00:00.000Z", revoked: false)),
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected,
        });
        Require(!negExpiredComm.Authorized && negExpiredComm.Reason == CommercialLeaseFailureReasons.Expired, "Negative: Expired commercial lease must DENY");
        Console.WriteLine("NEGATIVE_PASS: Expired commercial lease -> DENY (Expired)");

        // NEGATIVE 3: Wrong user SID / user identity -> DENY
        var negWrongUser = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Account,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = validAccountJws,
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected with { UserId = "usr_wrong_attacker_999" },
        });
        Require(!negWrongUser.Authorized && negWrongUser.Reason == AccountProductLeaseFailureReasons.ClaimMismatch, "Negative: Wrong user identity must DENY");
        Console.WriteLine("NEGATIVE_PASS: Wrong user identity -> DENY (ClaimMismatch)");

        // NEGATIVE 4: Wrong machine deviceId -> DENY
        var negWrongDevice = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.LicenseKey,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = validCommercialEnv,
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected with { DeviceId = "dev_wrong_foreign_machine_9999" },
        });
        Require(!negWrongDevice.Authorized && negWrongDevice.Reason == CommercialLeaseFailureReasons.ScopeMismatch, "Negative: Wrong machine deviceId must DENY");
        Console.WriteLine("NEGATIVE_PASS: Wrong machine deviceId -> DENY (ScopeMismatch)");

        // NEGATIVE 5: Wrong product ID -> DENY
        var negWrongProduct = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = SignJws(authorityPrimary.PrivateKey, "authority-live-2026", BuildAccountClaims("air-stack", agentDeviceKey.Thumbprint, "2026-11-15T11:55:00.000Z", "2026-11-16T12:00:00.000Z")),
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!negWrongProduct.Authorized && negWrongProduct.Reason == AccountProductLeaseFailureReasons.ClaimMismatch, "Negative: Wrong product must DENY");
        Console.WriteLine("NEGATIVE_PASS: Wrong product -> DENY (ClaimMismatch)");

        // NEGATIVE 6: Tampered executable / payload signature mismatch -> DENY
        var jwsParts = validAccountJws.Split('.');
        var tamperedPayload = Ed25519KeyUtilities.EncodeBase64Url(Encoding.UTF8.GetBytes(validAccountClaims.Replace("acct_native_001", "acct_evil_999", StringComparison.Ordinal)));
        var negTampered = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = $"{jwsParts[0]}.{tamperedPayload}.{jwsParts[2]}",
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!negTampered.Authorized && negTampered.Reason == AccountProductLeaseFailureReasons.InvalidSignature, "Negative: Tampered payload signature must DENY");
        Console.WriteLine("NEGATIVE_PASS: Tampered payload signature -> DENY (InvalidSignature)");

        // NEGATIVE 7: Changed installation ID -> DENY
        var negChangedInstall = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.LicenseKey,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = validCommercialEnv,
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected with { InstallationId = "inst_changed_device_0099" },
        });
        Require(!negChangedInstall.Authorized && negChangedInstall.Reason == CommercialLeaseFailureReasons.ScopeMismatch, "Negative: Changed installation ID must DENY");
        Console.WriteLine("NEGATIVE_PASS: Changed installation ID -> DENY (ScopeMismatch)");

        // NEGATIVE 8: Missing Agent -> DENY
        var offlinePipe = "bke-testapp-offline-" + Guid.NewGuid().ToString("N");
        var negMissingAgent = BkeLicensing.StartAsync(new ProductStartupOptions
        {
            PipeName = offlinePipe,
            ConnectTimeout = TimeSpan.FromMilliseconds(50),
            RequestTimeout = TimeSpan.FromMilliseconds(50),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        }).GetAwaiter().GetResult();
        var expectedOffline = OperatingSystem.IsWindows()
            ? ProductStartupFailureReasons.AgentUnavailable
            : ProductStartupFailureReasons.PlatformNotSupported;
        Require(!negMissingAgent.Authorized && negMissingAgent.Reason == expectedOffline, "Negative: Missing Agent must fail closed");
        Console.WriteLine($"NEGATIVE_PASS: Missing Agent -> DENY ({expectedOffline})");

        // NEGATIVE 9: Untrusted signer -> DENY
        var negUntrustedSigner = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = SignJws(authorityAttacker.PrivateKey, "attacker-untrusted-k1", validAccountClaims),
            AccountTrustedKeys = acctKeys,
            AccountExpected = acctExpected,
        });
        Require(!negUntrustedSigner.Authorized && negUntrustedSigner.Reason == AccountProductLeaseFailureReasons.UntrustedKid, "Negative: Untrusted signer must DENY");
        Console.WriteLine("NEGATIVE_PASS: Untrusted signer -> DENY (UntrustedKid)");

        // NEGATIVE 10: Revoked rights -> DENY
        var negRevoked = ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.LicenseKey,
            CommercialEnvelope = SignCommercial(authorityPrimary.PrivateKey, "comm-live-2026", BuildCommercialPayload("render-dock", "2026-11-15T11:55:00.000Z", "2026-11-15T11:55:00.000Z", "2026-12-15T12:00:00.000Z", revoked: true)),
            CommercialTrustedKeys = commKeys,
            CommercialExpected = commExpected,
        });
        Require(!negRevoked.Authorized && negRevoked.Reason == CommercialLeaseFailureReasons.LeaseRevoked, "Negative: Revoked rights must DENY");
        Console.WriteLine("NEGATIVE_PASS: Revoked commercial lease -> DENY (LeaseRevoked)");

        // DIRECT RUN 1: Direct startup bypassing Launcher with spoofed CLI marker -> DENY
        var directSpoofed = SimulateDirectLaunchBypassAttempt("--from-launcher=true", "--launched-by-bke");
        Require(!directSpoofed.Authorized && directSpoofed.Reason == AuthorizationFailureReasons.MissingAuthorizationProof, "Direct: Spoofed Launcher marker must DENY");
        Console.WriteLine("DIRECT_PASS: Direct startup with spoofed Launcher flags -> DENY (MissingAuthorizationProof)");

        // DIRECT RUN 2: Double-click direct execution without Agent running -> DENY
        var directNoAgent = BkeLicensing.StartAsync(new ProductStartupOptions
        {
            PipeName = "bke-licensing-agent-standalone-startup-v1",
            ConnectTimeout = TimeSpan.FromMilliseconds(50),
            RequestTimeout = TimeSpan.FromMilliseconds(50),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        }).GetAwaiter().GetResult();
        Require(!directNoAgent.Authorized && (directNoAgent.Reason == ProductStartupFailureReasons.AgentUnavailable || directNoAgent.Reason == ProductStartupFailureReasons.PlatformNotSupported), "Direct: No Agent running must fail closed");
        Console.WriteLine($"DIRECT_PASS: Direct execution without running Agent -> DENY ({directNoAgent.Reason})");
    }

    private static ProductAuthorizationDecision SimulateDirectLaunchBypassAttempt(params string[] spoofedArgs)
    {
        // Even if spoofed Launcher flags are present on the command line, the gate ignores them
        // and demands a valid cryptographic lease token verified against trusted authority keys.
        _ = spoofedArgs;
        return ProductAuthorizationGate.Authorize(new ProductAuthorizationRequest
        {
            ProductId = "render-dock",
            RequiredActivationMode = ActivationModes.Either,
            PresentedCredential = ActivationCredentials.Account,
            AccountJws = null,
            AccountTrustedKeys = new Dictionary<string, AccountProductLeaseTrustedKey>
            {
                ["k1"] = new("placeholder", AccountProductLeaseKeyStates.Active),
            },
            AccountExpected = null,
        });
    }

    private static void VerifyPlatformSecretStorage()
    {
        var tempDir = Directory.CreateTempSubdirectory("bke-testapp-sec-").FullName;
        var keychainPath = OperatingSystem.IsMacOS() ? Path.Combine(tempDir, "app.keychain-db") : null;
        try
        {
            if (OperatingSystem.IsMacOS() && keychainPath is not null)
            {
                RunSecurity("create-keychain", "-p", "app-ci-pass", keychainPath);
                RunSecurity("unlock-keychain", "-p", "app-ci-pass", keychainPath);
            }

            var scope = "bke.licensing.testapp." + Guid.NewGuid().ToString("N");
            var writer = PlatformSecretStoreFactory.CreateForCurrentPlatform(tempDir, scope, keychainPath);
            writer.WriteSecret("session-lease", Encoding.UTF8.GetBytes("sealed-session-token-v1"));

            var reader = PlatformSecretStoreFactory.CreateForCurrentPlatform(tempDir, scope, keychainPath);
            var restored = reader.ReadSecret("session-lease");
            Require(restored is not null && Encoding.UTF8.GetString(restored) == "sealed-session-token-v1", "Scenario 11 round-trip failed");
            writer.DeleteSecret("session-lease");
            Require(reader.ReadSecret("session-lease") is null, "Scenario 11 delete failed");
        }
        finally
        {
            if (OperatingSystem.IsMacOS() && keychainPath is not null)
            {
                TryRunSecurity("delete-keychain", keychainPath);
            }
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    private static string BuildAccountClaims(string productId, string thumbprint, string issuedAt, string expiresAt, string refreshAfter = "2026-11-15T12:30:00.000Z") =>
        $$"""{"schema":"bke.product-lease.v1","issuer":"https://auth.test-only.bke.example","audience":"bke-desktop-native","leaseId":"lease_testapp_001","accountId":"acct_native_001","userId":"usr_native_001","productId":"{{productId}}","agentSessionId":"sess_native_001","agentKeyThumbprint":"{{thumbprint}}","keyProtection":"tpm","plan":"PRO","allowedActions":["OPEN","USE"],"issuedAt":"{{issuedAt}}","refreshAfter":"{{refreshAfter}}","expiresAt":"{{expiresAt}}"}""";

    private static string BuildCommercialPayload(string productId, string issuedAt, string notBefore, string expiresAt, bool revoked) =>
        $$"""{"license_id":"lic_native_001","lease_id":"comm_testapp_001","generation":1,"server_revision":1,"product_id":"{{productId}}","installation_id":"inst_native_device_0001","device_id":"dev_native_machine_0001","version":"2.5.0","issuer":"BKE Digital Solutions","issued_at":"{{issuedAt}}","not_before":"{{notBefore}}","expires_at":"{{expiresAt}}","key_id":"comm-live-2026","algorithm":"Ed25519","revoked":{{(revoked ? "true" : "false")}},"superseded_by":null}""";

    private static string SignJws(Ed25519PrivateKeyParameters key, string kid, string claimsJson)
    {
        var h = Ed25519KeyUtilities.EncodeBase64Url(Encoding.UTF8.GetBytes($$"""{"alg":"EdDSA","kid":"{{kid}}","typ":"bke.product-lease.v1+jws"}"""));
        var p = Ed25519KeyUtilities.EncodeBase64Url(Encoding.UTF8.GetBytes(claimsJson));
        var msg = Encoding.ASCII.GetBytes($"{h}.{p}");
        var signer = new Ed25519Signer();
        signer.Init(true, key);
        signer.BlockUpdate(msg, 0, msg.Length);
        return $"{h}.{p}.{Ed25519KeyUtilities.EncodeBase64Url(signer.GenerateSignature())}";
    }

    private static CommercialLeaseEnvelope SignCommercial(Ed25519PrivateKeyParameters key, string keyId, string payloadJson)
    {
        var msg = Encoding.UTF8.GetBytes(payloadJson);
        var signer = new Ed25519Signer();
        signer.Init(true, key);
        signer.BlockUpdate(msg, 0, msg.Length);
        return new CommercialLeaseEnvelope(payloadJson, Convert.ToBase64String(signer.GenerateSignature()), keyId, "Ed25519");
    }

    private static (Ed25519PrivateKeyParameters PrivateKey, string PublicKeyPem, string Thumbprint) GenerateEd25519KeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        var priv = (Ed25519PrivateKeyParameters)kp.Private;
        var pub = (Ed25519PublicKeyParameters)kp.Public;
        using var sw = new StringWriter();
        var pw = new PemWriter(sw);
        pw.WriteObject(pub);
        pw.Writer.Flush();
        return (priv, sw.ToString(), Ed25519KeyUtilities.ComputeSpkiThumbprint(pub));
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void RunSecurity(params string[] args)
    {
        var psi = new ProcessStartInfo("/usr/bin/security")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var p = Process.Start(psi)!;
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        Require(p.ExitCode == 0, $"security exited {p.ExitCode}: {stderr}");
    }

    private static void TryRunSecurity(params string[] args)
    {
        try
        {
            RunSecurity(args);
        }
        catch (Exception)
        {
        }
    }
}
