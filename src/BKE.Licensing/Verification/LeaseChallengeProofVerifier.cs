using System.Security.Cryptography;
using System.Text;
using BKE.Licensing.Contracts;

namespace BKE.Licensing.Verification;

public static class LeaseChallengeProofVerifier
{
    public static byte[] BuildCanonicalMessage(LeaseChallengeRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        var joined = string.Join(
            '\n',
            LeaseChallengeConstants.Schema,
            record.ChallengeId,
            record.AccountId,
            record.UserId,
            record.ProductId,
            record.AgentSessionId,
            record.AgentKeyThumbprint,
            record.Action,
            record.Nonce);
        return Encoding.UTF8.GetBytes(joined);
    }

    public static LeaseChallengeVerificationResult VerifyAndConsume(
        ILeaseChallengeStore store,
        string? challengeId,
        string? messageBase64url,
        string? signatureBase64url,
        string? publicKeyPem,
        string expectedAccountId,
        string expectedUserId,
        string expectedProductId,
        string expectedAgentSessionId,
        string expectedAgentKeyThumbprint,
        string expectedAction,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(store);

        if (!Ed25519KeyUtilities.IsValidKeyId(challengeId))
        {
            return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.InvalidChallenge);
        }

        var messageBytes = Ed25519KeyUtilities.DecodeCanonicalBase64Url(messageBase64url, 4096);
        var signatureBytes = Ed25519KeyUtilities.DecodeCanonicalBase64Url(signatureBase64url, 128);
        if (messageBytes is null || signatureBytes is null || signatureBytes.Length != 64)
        {
            return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.BadSignature);
        }

        if (!Ed25519KeyUtilities.TryParsePublicKey(publicKeyPem, out var publicKey) || publicKey is null)
        {
            return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.BadSignature);
        }

        var thumbprint = Ed25519KeyUtilities.ComputeSpkiThumbprint(publicKey);
        if (!string.Equals(thumbprint, expectedAgentKeyThumbprint, StringComparison.Ordinal))
        {
            return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.ScopeMismatch);
        }

        var consumed = store.ConsumeChallengeAtomically(challengeId!, now);
        switch (consumed.Status)
        {
            case LeaseChallengeConsumeStatus.NotFound:
            case LeaseChallengeConsumeStatus.NotYetValid:
                return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.InvalidChallenge);
            case LeaseChallengeConsumeStatus.AlreadyConsumed:
                return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.ChallengeAlreadyConsumed);
            case LeaseChallengeConsumeStatus.Expired:
                return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.ChallengeExpired);
            case LeaseChallengeConsumeStatus.Consumed when consumed.Record is not null:
                break;
            default:
                return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.InvalidChallenge);
        }

        var record = consumed.Record!;
        if (record.AccountId != expectedAccountId ||
            record.UserId != expectedUserId ||
            record.ProductId != expectedProductId ||
            record.AgentSessionId != expectedAgentSessionId ||
            record.AgentKeyThumbprint != expectedAgentKeyThumbprint ||
            record.Action != expectedAction)
        {
            return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.ScopeMismatch);
        }

        var expectedMessage = BuildCanonicalMessage(record);
        var messageHash = Convert.ToHexStringLower(SHA256.HashData(messageBytes));
        if (!string.Equals(messageHash, record.MessageHash, StringComparison.Ordinal) ||
            !messageBytes.AsSpan().SequenceEqual(expectedMessage) ||
            !Ed25519KeyUtilities.VerifyEd25519Signature(publicKey, messageBytes, signatureBytes))
        {
            return LeaseChallengeVerificationResult.Fail(LeaseChallengeFailureReasons.BadSignature);
        }

        return LeaseChallengeVerificationResult.Success(record);
    }
}

public sealed class InMemoryLeaseChallengeStore : ILeaseChallengeStore
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, LeaseChallengeRecord> _records = new(StringComparer.Ordinal);

    public void IssueChallenge(LeaseChallengeRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        lock (_gate)
        {
            if (!_records.TryAdd(record.ChallengeId, record))
            {
                throw new InvalidOperationException("LEASE_CHALLENGE_ID_CONFLICT");
            }
        }
    }

    public LeaseChallengeConsumeResult ConsumeChallengeAtomically(string challengeId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(challengeId, out var existing))
            {
                return new LeaseChallengeConsumeResult(LeaseChallengeConsumeStatus.NotFound);
            }

            if (existing.CreatedAt > now)
            {
                return new LeaseChallengeConsumeResult(LeaseChallengeConsumeStatus.NotYetValid);
            }

            if (existing.ConsumedAt is not null)
            {
                return new LeaseChallengeConsumeResult(LeaseChallengeConsumeStatus.AlreadyConsumed);
            }

            if (existing.ExpiresAt <= now)
            {
                return new LeaseChallengeConsumeResult(LeaseChallengeConsumeStatus.Expired);
            }

            var updated = existing with { ConsumedAt = now };
            _records[challengeId] = updated;
            return new LeaseChallengeConsumeResult(LeaseChallengeConsumeStatus.Consumed, updated);
        }
    }
}
