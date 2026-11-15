namespace BKE.Licensing.Client;

public static class ProductStartupFailureReasons
{
    public const string Authorized = "authorized";
    public const string AgentUnavailable = "agent_unavailable";
    public const string PlatformNotSupported = "platform_not_supported";
    public const string ProtocolError = "protocol_error";
    public const string RequestTimedOut = "request_timed_out";
    public const string PeerDenied = "peer_denied";
    public const string ReplayDenied = "replay_denied";
}

public sealed record ProductStartupResult(
    bool Authorized,
    string Reason,
    string? RequestId = null);

public sealed record ProductStartupOptions
{
    public const string DefaultPipeName = "bke-licensing-agent-standalone-startup-v1";
    public const string ExpectedProtocol = "bke.standalone-startup.v1";

    public string PipeName { get; init; } = DefaultPipeName;
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(10);
}
