using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
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

        // Production security boundary:
        // Untrusted callers cannot select a custom pipe name without an internal test validator.
        IAgentServerTrustValidator trustValidator;
        if (options.TestTrustValidator is not null)
        {
            trustValidator = options.TestTrustValidator;
        }
        else
        {
            if (!string.Equals(options.PipeName, ProductStartupOptions.DefaultPipeName, StringComparison.Ordinal))
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.AgentServerUntrusted);
            }

            trustValidator = WindowsAgentServerTrustValidator.Instance;
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

            // 1. Authenticate the connected pipe server process identity before sending or trusting authorization
            var initialTrust = trustValidator.ValidateConnectedServer(pipe.SafePipeHandle, options.PipeName);
            if (!initialTrust.IsTrusted)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.AgentServerUntrusted);
            }

            // 2. Transmit correlated authorization request
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

            // 3. Receive correlated response
            await pipe.ReadExactlyAsync(lengthHeader, timeoutCts.Token).ConfigureAwait(false);
            var responseLength = BinaryPrimitives.ReadInt32BigEndian(lengthHeader);
            if (responseLength is < 2 or > MaxMessageBytes)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            var responseBuffer = new byte[responseLength];
            await pipe.ReadExactlyAsync(responseBuffer, timeoutCts.Token).ConfigureAwait(false);

            // 4. TOCTOU Protection: Re-verify that server PID, process instance, and identity did not change mid-flight
            if (initialTrust.Evidence is not null)
            {
                var liveTrust = trustValidator.ValidateLiveServer(pipe.SafePipeHandle, initialEvidence: initialTrust.Evidence);
                if (!liveTrust.IsTrusted)
                {
                    return new ProductStartupResult(false, ProductStartupFailureReasons.AgentServerUntrusted);
                }
            }

            // 5. Strict schema, duplicate rejection, and semantic consistency validation
            return ParseAndValidateResponse(responseBuffer, requestId);
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

    internal static ProductStartupResult ParseAndValidateResponse(byte[] responseBuffer, string expectedRequestId)
    {
        try
        {
            var seenProperties = new HashSet<string>(StringComparer.Ordinal);
            var reader = new Utf8JsonReader(responseBuffer, new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4,
            });

            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            string? schema = null;
            string? requestId = null;
            bool? authorized = null;
            string? reason = null;

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    break;
                }

                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                }

                var propName = reader.GetString();
                if (string.IsNullOrEmpty(propName) || !seenProperties.Add(propName))
                {
                    // Duplicate property name detected
                    return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                }

                if (!reader.Read())
                {
                    return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                }

                switch (propName)
                {
                    case "schema":
                        if (reader.TokenType != JsonTokenType.String)
                            return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                        schema = reader.GetString();
                        break;

                    case "request_id":
                        if (reader.TokenType != JsonTokenType.String)
                            return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                        requestId = reader.GetString();
                        break;

                    case "authorized":
                        if (reader.TokenType is not (JsonTokenType.True or JsonTokenType.False))
                            return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                        authorized = reader.GetBoolean();
                        break;

                    case "reason":
                        if (reader.TokenType != JsonTokenType.String)
                            return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                        reason = reader.GetString();
                        break;

                    default:
                        // Unexpected property name
                        return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                }
            }

            // Require exactly the 4 canonical properties
            if (seenProperties.Count != 4 ||
                schema is null || requestId is null || authorized is null || reason is null)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            // Enforce whole-message consumption: reject trailing tokens, multiple JSON roots, extra tokens
            while (reader.Read())
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            // Allow only permitted trailing whitespace, reject unparsed trailing bytes or garbage
            var remainingBytes = responseBuffer.AsSpan((int)reader.BytesConsumed);
            foreach (var b in remainingBytes)
            {
                if (b is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'))
                {
                    return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
                }
            }

            if (schema != ProductStartupOptions.ExpectedProtocol ||
                requestId != expectedRequestId ||
                string.IsNullOrWhiteSpace(reason) ||
                reason.Length > 128)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            // Enforce semantic consistency: prevent contradictory authorization grants
            if (authorized.Value && reason != ProductStartupFailureReasons.Authorized)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            if (!authorized.Value && reason == ProductStartupFailureReasons.Authorized)
            {
                return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
            }

            return new ProductStartupResult(authorized.Value, reason, requestId);
        }
        catch (JsonException)
        {
            return new ProductStartupResult(false, ProductStartupFailureReasons.ProtocolError);
        }
    }
}
