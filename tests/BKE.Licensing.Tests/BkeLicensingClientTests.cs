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
        var nonexistentPipe = "bke-test-nonexistent-pipe-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = nonexistentPipe,
            ConnectTimeout = TimeSpan.FromMilliseconds(50),
            RequestTimeout = TimeSpan.FromMilliseconds(50),
        };

        var result = await BkeLicensing.StartAsync(options);

        Assert.False(result.Authorized);
        Assert.Equal(ProductStartupFailureReasons.AgentUnavailable, result.Reason);
    }

    [Fact]
    public async Task StartAsync_ReturnsAuthorized_WhenAgentPipeAuthorizes()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-auth-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
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
    public async Task StartAsync_ReturnsDenied_WhenAgentPipeDenies()
    {
        if (!OperatingSystem.IsWindows()) return;

        var pipeName = "bke-test-deny-" + Guid.NewGuid().ToString("N");
        var options = new ProductStartupOptions
        {
            PipeName = pipeName,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(5),
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
}
