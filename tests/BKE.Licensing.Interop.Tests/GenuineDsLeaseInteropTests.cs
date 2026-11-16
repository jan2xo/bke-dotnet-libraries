using System.Text.Json;
using BKE.Licensing.Contracts;
using BKE.Licensing.Verification;
using Xunit;

namespace BKE.Licensing.Interop.Tests;

public sealed class GenuineDsLeaseInteropTests
{
    private const string EmbeddedFixtureJson = """
    {
      "jws": "eyJhbGciOiJFZERTQSIsImtpZCI6InV0bS1zdGFuZGFsb25lLWlzc3Vlci0yMDI2IiwidHlwIjoiYmtlLnByb2R1Y3QtbGVhc2UudjErandzIn0.eyJzY2hlbWEiOiJia2UucHJvZHVjdC1sZWFzZS52MSIsImlzc3VlciI6IkJLRSBEaWdpdGFsIFNvbHV0aW9ucyIsImF1ZGllbmNlIjoiYmtlLXByb2R1Y3QiLCJsZWFzZUlkIjoiNjUwOTNkYjctMjc4Ni00YjQ1LWIwYmUtZTJhYjZhZTY4MWFiIiwiYWNjb3VudElkIjoiYWNjXzAwMDAwMDAwMDAwMDAwMDEiLCJ1c2VySWQiOiJ1c3JfMDAwMDAwMDAwMDAwMDAwMSIsInByb2R1Y3RJZCI6ImJrZS1hY2NlcHRhbmNlLWNsaWVudCIsImFnZW50U2Vzc2lvbklkIjoic2VzXzAwMDAwMDAwMDAwMDAwMDEiLCJhZ2VudEtleVRodW1icHJpbnQiOiIwS3piWTY1MkYzS3lnZ3JaQnM3QWtJWm1TRHNnUXZULXM4WmQ1Wlc5aWtrIiwia2V5UHJvdGVjdGlvbiI6InNvZnR3YXJlIiwicGxhbiI6InN1YnNjcmlwdGlvbiIsImFsbG93ZWRBY3Rpb25zIjpbIk9QRU4iXSwiaXNzdWVkQXQiOiIyMDI2LTExLTE2VDA2OjA3OjA1LjEyN1oiLCJyZWZyZXNoQWZ0ZXIiOiIyMDI2LTExLTE2VDA2OjA4OjM1LjEyN1oiLCJleHBpcmVzQXQiOiIyMDI2LTExLTE2VDA2OjEwOjA1LjEyN1oifQ.oCVRR9KzJGgiVyyT-a_lDYWlu1Uhbks5cHGV_30jotlmto26ozbuvU9ZsFkKBUlgPded7dxhvyDQcIqJMFjlDg",
      "kid": "utm-standalone-issuer-2026",
      "claims": {
        "schema": "bke.product-lease.v1",
        "issuer": "BKE Digital Solutions",
        "audience": "bke-product",
        "leaseId": "65093db7-2786-4b45-b0be-e2ab6ae681ab",
        "accountId": "acc_0000000000000001",
        "userId": "usr_0000000000000001",
        "productId": "bke-acceptance-client",
        "agentSessionId": "ses_0000000000000001",
        "agentKeyThumbprint": "0KzbY652F3KyggrZBs7AkIZmSDsgQvT-s8Zd5ZW9ikk",
        "keyProtection": "software",
        "plan": "subscription",
        "allowedActions": [
          "OPEN"
        ],
        "issuedAt": "2026-11-16T06:07:05.127Z",
        "refreshAfter": "2026-11-16T06:08:35.127Z",
        "expiresAt": "2026-11-16T06:10:05.127Z"
      },
      "pubPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAi8bkLe2jeCmpNxlop/pIoXD2R/XVGgpmE0whdPiFj2Q=\n-----END PUBLIC KEY-----\n"
    }
    """;

    private static string ResolveFixtureJson()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var target = Path.Combine(dir.FullName, "latest-lease.json");
            if (File.Exists(target))
            {
                try { return File.ReadAllText(target); } catch { }
            }
            dir = dir.Parent;
        }
        return EmbeddedFixtureJson;
    }

    [Fact]
    public void GenuineDsIssuedLease_VerifiesInDotNet_AndMatchesTypeScriptClaims()
    {
        var rawJson = ResolveFixtureJson();
        using var doc = JsonDocument.Parse(rawJson);
        var root = doc.RootElement;

        var jws = root.GetProperty("jws").GetString()!;
        var kid = root.GetProperty("kid").GetString()!;
        var pubPem = root.GetProperty("pubPem").GetString()!;
        var claimsElem = root.GetProperty("claims");

        var issuer = claimsElem.GetProperty("issuer").GetString()!;
        var audience = claimsElem.GetProperty("audience").GetString()!;
        var accountId = claimsElem.GetProperty("accountId").GetString()!;
        var userId = claimsElem.GetProperty("userId").GetString()!;
        var productId = claimsElem.GetProperty("productId").GetString()!;
        var agentSessionId = claimsElem.GetProperty("agentSessionId").GetString()!;
        var agentKeyThumbprint = claimsElem.GetProperty("agentKeyThumbprint").GetString()!;
        var issuedAtStr = claimsElem.GetProperty("issuedAt").GetString()!;
        var expiresAtStr = claimsElem.GetProperty("expiresAt").GetString()!;
        var issuedAt = DateTimeOffset.Parse(issuedAtStr);

        var keys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            [kid] = new(pubPem, AccountProductLeaseKeyStates.Active)
        };

        var expected = new AccountProductLeaseVerificationContext(
            issuer,
            audience,
            accountId,
            userId,
            productId,
            agentSessionId,
            agentKeyThumbprint,
            "OPEN",
            issuedAt);

        var result = AccountProductLeaseVerifier.Verify(jws, keys, expected);
        Assert.True(result.Ok, $"Verification failed: {result.Reason}");
        Assert.NotNull(result.Claims);
        Assert.Equal(kid, result.Kid);

        var c = result.Claims;
        Assert.Equal("bke.product-lease.v1", c.Schema);
        Assert.Equal(issuer, c.Issuer);
        Assert.Equal(audience, c.Audience);
        Assert.Equal(claimsElem.GetProperty("leaseId").GetString(), c.LeaseId);
        Assert.Equal(accountId, c.AccountId);
        Assert.Equal(userId, c.UserId);
        Assert.Equal(productId, c.ProductId);
        Assert.Equal(agentSessionId, c.AgentSessionId);
        Assert.Equal(agentKeyThumbprint, c.AgentKeyThumbprint);
        Assert.Equal("software", c.KeyProtection);
        Assert.Equal("subscription", c.Plan);
        Assert.Contains("OPEN", c.AllowedActions);
        Assert.Equal(issuedAtStr, c.IssuedAt);
        Assert.Equal(expiresAtStr, c.ExpiresAt);
    }

    [Fact]
    public void GenuineDsIssuedLease_TamperedSignature_FailsClosed()
    {
        var rawJson = ResolveFixtureJson();
        using var doc = JsonDocument.Parse(rawJson);
        var root = doc.RootElement;

        var jws = root.GetProperty("jws").GetString()!;
        var kid = root.GetProperty("kid").GetString()!;
        var pubPem = root.GetProperty("pubPem").GetString()!;
        var claimsElem = root.GetProperty("claims");

        var parts = jws.Split('.');
        var tamperedSig = parts[2][..^4] + "AAAA";
        var tamperedJws = $"{parts[0]}.{parts[1]}.{tamperedSig}";

        var keys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            [kid] = new(pubPem, AccountProductLeaseKeyStates.Active)
        };

        var expected = new AccountProductLeaseVerificationContext(
            claimsElem.GetProperty("issuer").GetString()!,
            claimsElem.GetProperty("audience").GetString()!,
            claimsElem.GetProperty("accountId").GetString()!,
            claimsElem.GetProperty("userId").GetString()!,
            claimsElem.GetProperty("productId").GetString()!,
            claimsElem.GetProperty("agentSessionId").GetString()!,
            claimsElem.GetProperty("agentKeyThumbprint").GetString()!,
            "OPEN",
            DateTimeOffset.Parse(claimsElem.GetProperty("issuedAt").GetString()!));

        var result = AccountProductLeaseVerifier.Verify(tamperedJws, keys, expected);
        Assert.False(result.Ok);
        Assert.Equal(AccountProductLeaseFailureReasons.InvalidSignature, result.Reason);
    }

    [Fact]
    public void GenuineDsIssuedLease_ExpiredTimestamp_FailsClosed()
    {
        var rawJson = ResolveFixtureJson();
        using var doc = JsonDocument.Parse(rawJson);
        var root = doc.RootElement;

        var jws = root.GetProperty("jws").GetString()!;
        var kid = root.GetProperty("kid").GetString()!;
        var pubPem = root.GetProperty("pubPem").GetString()!;
        var claimsElem = root.GetProperty("claims");

        var keys = new Dictionary<string, AccountProductLeaseTrustedKey>
        {
            [kid] = new(pubPem, AccountProductLeaseKeyStates.Active)
        };

        var expiresAt = DateTimeOffset.Parse(claimsElem.GetProperty("expiresAt").GetString()!);
        var expected = new AccountProductLeaseVerificationContext(
            claimsElem.GetProperty("issuer").GetString()!,
            claimsElem.GetProperty("audience").GetString()!,
            claimsElem.GetProperty("accountId").GetString()!,
            claimsElem.GetProperty("userId").GetString()!,
            claimsElem.GetProperty("productId").GetString()!,
            claimsElem.GetProperty("agentSessionId").GetString()!,
            claimsElem.GetProperty("agentKeyThumbprint").GetString()!,
            "OPEN",
            expiresAt.AddSeconds(10));

        var result = AccountProductLeaseVerifier.Verify(jws, keys, expected);
        Assert.False(result.Ok);
        Assert.Equal(AccountProductLeaseFailureReasons.Expired, result.Reason);
    }
}
