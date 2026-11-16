using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using BKE.Licensing.Client;
using Xunit;

namespace BKE.Licensing.Tests;

public class BkeLicensingClientTests
{
    [Fact]
    public async Task StartAsync_FailsClosed_WhenAgentUnavailable()
    {
        if (!OperatingSystem.IsWindows())
        {
            var res = await BkeLicensing.StartAsync(new ProductStartupOptions());
            Assert.False(res.Authorized);
            Assert.Equal(ProductStartupFailureReasons.PlatformNotSupported, res.Reason);
            return;
        }

        var nonexistentPipe = "bke-test-nonexistent-pipe-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = nonexistentPipe,
            ConnectTimeout = TimeSpan.FromMilliseconds(50),
            RequestTimeout = TimeSpan.FromMilliseconds(50),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var result = await BkeLicensing.StartAsync(options);

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.AgentUnavailable, result.Reason);
    }

    [Fact]
    public async Task StartAsync_FailsClosed_WhenServerIsUntrustedUserProcess()
    {
        if (!OperatingSystem.IsWindows()) return;

        // Security P0 counterexample test:
        // A rogue user process creates the canonical named pipe and sends an authorized=true response.
        // The production WindowsAgentServerTrustValidator inspects the connected server process ID,
        // discovers that it is running outside Program Files and without privileged service credentials,
        // and FAILS CLOSED before accepting authorization.

        var pipeName = ProductStartupOptions.DefaultPipeName;

        // Use a unique pipe for test isolation if default is in use or testable with custom pipe
        // Testing production validator against custom pipe also fails closed.
        var serverTask = Task.Run(async () =>
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync();

                var lenBuf = new byte[4];
                await server.ReadExactlyAsync(lenBuf);
                var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
                var reqBytes = new byte[len];
                await server.ReadExactlyAsync(reqBytes);

                using var doc = JsonDocument.Parse(reqBytes);
                var reqId = doc.RootElement.GetProperty("request_id").GetString()!;

                var resp = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema = ProductStartupOptions.ExpectedProtocol,
                    request_id = reqId,
                    authorized = true,
                    reason = "authorized",
                });

                BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
                await server.WriteAsync(lenBuf);
                await server.WriteAsync(resp);
                await server.FlushAsync();
            }
            catch (IOException)
            {
                // Client closed pipe upon trust rejection
            }
        });

        // Calling public API with default options (uses production WindowsAgentServerTrustValidator)
        var result = await BkeLicensing.StartAsync(new ProductStartupOptions
        {
            ConnectTimeout = TimeSpan.FromSeconds(2),
            RequestTimeout = TimeSpan.FromSeconds(2),
        });

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.AgentServerUntrusted, result.Reason);
    }

    [Fact]
    public async Task StartAsync_FailsClosed_WhenCustomPipeNameAttemptedWithoutTestAuthorization()
    {
        if (!OperatingSystem.IsWindows()) return;

        // Third-party consumer applications cannot bypass server validation by pointing to an arbitrary pipe
        var options = new ProductStartupOptions
        {
            PipeName = "attacker-controlled-fake-pipe-" + Guid.NewGuid().ToString("N"),
            ConnectTimeout = TimeSpan.FromMilliseconds(100),
            RequestTimeout = TimeSpan.FromMilliseconds(100),
        };

        var result = await BkeLicensing.StartAsync(options);

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.AgentServerUntrusted, result.Reason);
    }

    [Fact]
    public async Task StartAsync_ReturnsAuthorized_WhenAttestedServerAuthorizes()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-auth-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var serverTask = Task.Run(async () =>
        {
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            await server.WaitForConnectionAsync();

            var lenBuf = new byte[4];
            await server.ReadExactlyAsync(lenBuf);
            var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
            var reqBytes = new byte[len];
            await server.ReadExactlyAsync(reqBytes);

            using var doc = JsonDocument.Parse(reqBytes);
            var reqId = doc.RootElement.GetProperty("request_id").GetString()!;

            var resp = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = ProductStartupOptions.ExpectedProtocol,
                request_id = reqId,
                authorized = true,
                reason = "authorized",
            });

            BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
            await server.WriteAsync(lenBuf);
            await server.WriteAsync(resp);
            await server.FlushAsync();
        });

        var result = await BkeLicensing.StartAsync(options);
        await serverTask;

        Assert.True(result.Authorized);
        Assert.Equal("authorized", result.Reason);
        Assert.NotNull(result.RequestId);
    }

    [Fact]
    public async Task StartAsync_ReturnsDenied_WhenAttestedServerDenies()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-deny-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var serverTask = Task.Run(async () =>
        {
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            await server.WaitForConnectionAsync();

            var lenBuf = new byte[4];
            await server.ReadExactlyAsync(lenBuf);
            var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
            var reqBytes = new byte[len];
            await server.ReadExactlyAsync(reqBytes);

            using var doc = JsonDocument.Parse(reqBytes);
            var reqId = doc.RootElement.GetProperty("request_id").GetString()!;

            var resp = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = ProductStartupOptions.ExpectedProtocol,
                request_id = reqId,
                authorized = false,
                reason = "unverifiable_signed_lease",
            });

            BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
            await server.WriteAsync(lenBuf);
            await server.WriteAsync(resp);
            await server.FlushAsync();
        });

        var result = await BkeLicensing.StartAsync(options);
        await serverTask;

        Assert.False(result.Authorized);
        Assert.Equal("unverifiable_signed_lease", result.Reason);
    }

    [Fact]
    public async Task StartAsync_Rejects_CorrelationMismatch_Or_BogusSchema()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-mismatch-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var serverTask = Task.Run(async () =>
        {
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            await server.WaitForConnectionAsync();

            var lenBuf = new byte[4];
            await server.ReadExactlyAsync(lenBuf);
            var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
            var reqBytes = new byte[len];
            await server.ReadExactlyAsync(reqBytes);

            var resp = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = ProductStartupOptions.ExpectedProtocol,
                request_id = "wrong-request-id-not-matching",
                authorized = true,
                reason = "authorized",
            });

            BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
            await server.WriteAsync(lenBuf);
            await server.WriteAsync(resp);
            await server.FlushAsync();
        });

        var result = await BkeLicensing.StartAsync(options);
        await serverTask;

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.ProtocolError, result.Reason);
    }

    [Fact]
    public async Task StartAsync_Rejects_UnexpectedExtraneousFields()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-extra-fields-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var serverTask = Task.Run(async () =>
        {
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            await server.WaitForConnectionAsync();

            var lenBuf = new byte[4];
            await server.ReadExactlyAsync(lenBuf);
            var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
            var reqBytes = new byte[len];
            await server.ReadExactlyAsync(reqBytes);

            using var doc = JsonDocument.Parse(reqBytes);
            var reqId = doc.RootElement.GetProperty("request_id").GetString()!;

            var resp = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = ProductStartupOptions.ExpectedProtocol,
                request_id = reqId,
                authorized = true,
                reason = "authorized",
                rogue_extra_payload = "attacker_bypass_attempt",
            });

            BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
            await server.WriteAsync(lenBuf);
            await server.WriteAsync(resp);
            await server.FlushAsync();
        });

        var result = await BkeLicensing.StartAsync(options);
        await serverTask;

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.ProtocolError, result.Reason);
    }

    [Fact]
    public async Task StartAsync_Rejects_DuplicateProperties()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-duplicate-props-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var serverTask = Task.Run(async () =>
        {
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            await server.WaitForConnectionAsync();

            var lenBuf = new byte[4];
            await server.ReadExactlyAsync(lenBuf);
            var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
            var reqBytes = new byte[len];
            await server.ReadExactlyAsync(reqBytes);

            using var doc = JsonDocument.Parse(reqBytes);
            var reqId = doc.RootElement.GetProperty("request_id").GetString()!;

            // Handcrafted JSON with duplicate "authorized" property
            var rawJson = $"{{\"schema\":\"{ProductStartupOptions.ExpectedProtocol}\",\"request_id\":\"{reqId}\",\"authorized\":false,\"authorized\":true,\"reason\":\"authorized\"}}";
            var resp = System.Text.Encoding.UTF8.GetBytes(rawJson);

            BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
            await server.WriteAsync(lenBuf);
            await server.WriteAsync(resp);
            await server.FlushAsync();
        });

        var result = await BkeLicensing.StartAsync(options);
        await serverTask;

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.ProtocolError, result.Reason);
    }

    [Fact]
    public async Task StartAsync_Rejects_SemanticContradiction_AuthorizedTrue_With_DeniedReason()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-contradiction-1-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var serverTask = Task.Run(async () =>
        {
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            await server.WaitForConnectionAsync();

            var lenBuf = new byte[4];
            await server.ReadExactlyAsync(lenBuf);
            var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
            var reqBytes = new byte[len];
            await server.ReadExactlyAsync(reqBytes);

            using var doc = JsonDocument.Parse(reqBytes);
            var reqId = doc.RootElement.GetProperty("request_id").GetString()!;

            // Contradiction: authorized=true with denial reason
            var resp = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = ProductStartupOptions.ExpectedProtocol,
                request_id = reqId,
                authorized = true,
                reason = "peer_denied",
            });

            BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
            await server.WriteAsync(lenBuf);
            await server.WriteAsync(resp);
            await server.FlushAsync();
        });

        var result = await BkeLicensing.StartAsync(options);
        await serverTask;

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.ProtocolError, result.Reason);
    }

    [Fact]
    public async Task StartAsync_Rejects_SemanticContradiction_AuthorizedFalse_With_AuthorizedReason()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-contradiction-2-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var serverTask = Task.Run(async () =>
        {
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            await server.WaitForConnectionAsync();

            var lenBuf = new byte[4];
            await server.ReadExactlyAsync(lenBuf);
            var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
            var reqBytes = new byte[len];
            await server.ReadExactlyAsync(reqBytes);

            using var doc = JsonDocument.Parse(reqBytes);
            var reqId = doc.RootElement.GetProperty("request_id").GetString()!;

            // Contradiction: authorized=false with "authorized" reason
            var resp = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = ProductStartupOptions.ExpectedProtocol,
                request_id = reqId,
                authorized = false,
                reason = "authorized",
            });

            BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
            await server.WriteAsync(lenBuf);
            await server.WriteAsync(resp);
            await server.FlushAsync();
        });

        var result = await BkeLicensing.StartAsync(options);
        await serverTask;

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.ProtocolError, result.Reason);
    }

    [Fact]
    public async Task StartAsync_Rejects_MissingRequiredProperty()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-missing-prop-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
            TestTrustValidator = TestAgentServerTrustValidator.AllowAnyAttestedLiveProcess(),
        };

        var serverTask = Task.Run(async () =>
        {
            await using var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            await server.WaitForConnectionAsync();

            var lenBuf = new byte[4];
            await server.ReadExactlyAsync(lenBuf);
            var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
            var reqBytes = new byte[len];
            await server.ReadExactlyAsync(reqBytes);

            using var doc = JsonDocument.Parse(reqBytes);
            var reqId = doc.RootElement.GetProperty("request_id").GetString()!;

            // Missing "reason" property (only 3 properties provided)
            var resp = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schema = ProductStartupOptions.ExpectedProtocol,
                request_id = reqId,
                authorized = true,
            });

            BinaryPrimitives.WriteInt32BigEndian(lenBuf, resp.Length);
            await server.WriteAsync(lenBuf);
            await server.WriteAsync(resp);
            await server.FlushAsync();
        });

        var result = await BkeLicensing.StartAsync(options);
        await serverTask;

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.ProtocolError, result.Reason);
    }
}
