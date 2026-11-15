using BKE.Licensing.Client;

namespace BKE.Licensing;

/// <summary>
/// Small reusable product-facing licensing API for BKE software.
/// Verifies startup authorization through the trusted BKE Licensing Agent.
/// </summary>
public static class BkeLicensing
{
    /// <summary>
    /// Performs standard product startup authorization through the local Licensing Agent.
    /// Fails closed if the Agent is unavailable, peer unverified, or rights expired.
    /// </summary>
    public static Task<ProductStartupResult> StartAsync(CancellationToken cancellationToken = default) =>
        BkeLicensingClient.RequestStartupAuthorizationAsync(null, cancellationToken);

    /// <summary>
    /// Performs product startup authorization with custom client options (e.g. custom pipe or timeout).
    /// </summary>
    public static Task<ProductStartupResult> StartAsync(
        ProductStartupOptions options,
        CancellationToken cancellationToken = default) =>
        BkeLicensingClient.RequestStartupAuthorizationAsync(options, cancellationToken);
}
