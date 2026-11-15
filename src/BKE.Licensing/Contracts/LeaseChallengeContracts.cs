namespace BKE.Licensing.Contracts;

public static class LeaseChallengeConstants
{
    public const string Schema = "bke.lease-challenge.v1";
}

public static class LeaseChallengeFailureReasons
{
    public const string InvalidChallenge = "INVALID_CHALLENGE";
    public const string ChallengeAlreadyConsumed = "CHALLENGE_ALREADY_CONSUMED";
    public const string ChallengeExpired = "CHALLENGE_EXPIRED";
    public const string ScopeMismatch = "SCOPE_MISMATCH";
    public const string BadSignature = "BAD_SIGNATURE";
}

public sealed record LeaseChallengeRecord(
    string ChallengeId,
    string AccountId,
    string UserId,
    string ProductId,
    string AgentSessionId,
    string AgentKeyThumbprint,
    string Action,
    string Nonce,
    string MessageHash,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? ConsumedAt);

public enum LeaseChallengeConsumeStatus
{
    Consumed,
    NotFound,
    AlreadyConsumed,
    Expired,
    NotYetValid,
}

public sealed record LeaseChallengeConsumeResult(
    LeaseChallengeConsumeStatus Status,
    LeaseChallengeRecord? Record = null);

public interface ILeaseChallengeStore
{
    void IssueChallenge(LeaseChallengeRecord record);
    LeaseChallengeConsumeResult ConsumeChallengeAtomically(string challengeId, DateTimeOffset now);
}

public sealed record LeaseChallengeVerificationResult
{
    public bool Ok { get; init; }
    public string? ChallengeId { get; init; }
    public LeaseChallengeRecord? Record { get; init; }
    public string? Reason { get; init; }

    public static LeaseChallengeVerificationResult Success(LeaseChallengeRecord record) =>
        new() { Ok = true, ChallengeId = record.ChallengeId, Record = record };

    public static LeaseChallengeVerificationResult Fail(string reason) =>
        new() { Ok = false, Reason = reason };
}
