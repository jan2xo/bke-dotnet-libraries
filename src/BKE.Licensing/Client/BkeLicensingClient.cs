using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace BKE.Licensing.Client;

public static class BkeLicensingClient
{
    private const int MaxMessageBytes = 1024;

    public static async Task<ProductStartupResult> RequestStartupAuthorizationAsync(
        ProductStartupOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ProductStartupOptions();

        if (!OperatingSystem.IsWindows())
        {
            return new ProductStartupResult(false, ProductStartupFailureReasons.PlatformNotSupported);
        }

        var requestId = Guid.NewGuid().ToString("N");

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(options.ConnectTimeout + options.RequestTimeout);

            await using var pipe = new NamedPipeClientStream(
                ".",
                options.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Impersonation);

            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(timeoutCts.Token);
                connectCts.CancelAfter(options.ConnectTimeout);
                await pipe.ConnectAsync(connectCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.AgentUnavailable);
            }
            catch (TimeoutException)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.AgentUnavailable);
            }
            catch (IOException)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.AgentUnavailable);
            }

            var requestPayload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = ProductStartupOptions.ExpectedProtocol,
                operation = "authorize",
                request_id = requestId,
            });

            if (requestPayload.Length > MaxMessageBytes)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            var lengthHeader = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(lengthHeader, requestPayload.Length);

            await pipe.WriteAsync(lengthHeader, timeoutCts.Token).ConfigureAwait(false);
            await pipe.WriteAsync(requestPayload, timeoutCts.Token).ConfigureAwait(false);
            await pipe.FlushAsync(timeoutCts.Token).ConfigureAwait(false);

            await pipe.ReadExactlyAsync(lengthHeader, timeoutCts.Token).ConfigureAwait(false);
            var responseLength = BinaryPrimitives.ReadInt32BigEndian(lengthHeader);
            if (responseLength is < 2 or > MaxMessageBytes)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            var responseBuffer = new byte[responseLength];
            await pipe.ReadExactlyAsync(responseBuffer, timeoutCts.Token).ConfigureAwait(false);

            using var doc = JsonDocument.Parse(responseBuffer, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4,
            });

            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            if (!root.TryGetProperty("schema", out var schemaProp) ||
                schemaProp.GetString() != ProductStartupOptions.ExpectedProtocol)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            if (!root.TryGetProperty("request_id", out var reqIdProp) ||
                reqIdProp.GetString() != requestId)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            if (!root.TryGetProperty("authorized", out var authProp) ||
                authProp.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            var authorized = authProp.GetBoolean();
            var reason = root.TryGetProperty("reason", out var reasonProp) && reasonProp.ValueKind == JsonValueKind.String
                ? reasonProp.GetString() ?? (authorized ? ProductStartupFailureReasons.Authorized : ProductStartupFailureReasons.PeerDenied)
                : (authorized ? ProductStartupFailureReasons.Authorized : ProductStartupFailureReasons.PeerDenied);

            return new ProductStartupResult(authorized, reason, requestId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new ProductStartupResult(false, ProductStartupFailureReasons.RequestTimedOut);
        }
        catch (Exception)
        {
            return new ProductStartupResult(false, ProductStartupFailureReasons.AgentUnavailable);
        }
    }
}
