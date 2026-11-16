using System.Net;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

[NotInParallel]
public sealed class JsonAndBufferHardeningTests
{
    private const int FourMegabytes = 4 * 1024 * 1024;
    private const string ReadJson =
        """{"secret":{"id":"11111111-1111-4111-8111-111111111111","workspace":"project","environment":"test","secretPath":"/","type":"shared","secretKey":"key","secretValue":"v","secretValueHidden":false,"version":1}}""";
    private const string LoginJson =
        """{"accessToken":"token-canary","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0}""";
    private const string RevokeJson = """{"message":"Successfully revoked token"}""";
    private const string DynamicListJson = """{"dynamicSecrets":[]}""";
    private const string RotationListJson = """{"secretRotations":[]}""";
    private const string ErrorJson = """{"reqId":"req-1","statusCode":403,"error":"PermissionDenied"}""";

    [Test]
    public async Task SmallResponseDoesNotEagerlyAllocateResponseLimitBuffer()
    {
        var tokens = new FixedTokens();
        await MeasureAsync("InfisicalClient.ReadAsync", async () =>
        {
            using var wire = new SyncWire(HttpStatusCode.OK, ReadJson);
            await using var client = new InfisicalClient(new("https://api.test"), tokens, Options(wire));
            var target = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "test", "/", "key"));
            using (var warm = (await client.ReadAsync(target)).Value) { }
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < 16; i++)
            {
                using var read = (await client.ReadAsync(target)).Value;
            }
            return GC.GetTotalAllocatedBytes(precise: true) - before;
        });

        await MeasureAsync("InfisicalDynamicClient.ListDefinitionsAsync", async () =>
        {
            using var wire = new SyncWire(HttpStatusCode.OK, DynamicListJson);
            await using var client = new InfisicalDynamicClient(new("https://api.test"), tokens,
                new("project", "test", "/", Guid.NewGuid()), Options(wire));
            _ = await client.ListDefinitionsAsync();
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < 16; i++)
            {
                var outcome = await client.ListDefinitionsAsync();
                await Assert.That(outcome.IsSuccess).IsTrue();
            }
            return GC.GetTotalAllocatedBytes(precise: true) - before;
        });

        await MeasureAsync("InfisicalRotationClient.ListAsync", async () =>
        {
            using var wire = new SyncWire(HttpStatusCode.OK, RotationListJson);
            var authority = new SecretAuthority();
            await using var client = new InfisicalRotationClient(new("https://api.test"), authority,
                new(authority, tokens, "project"), Options(wire));
            var scope = new SecretReference(authority, new InfisicalRotationScope("project"));
            _ = await client.ListAsync(scope);
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < 16; i++)
            {
                var outcome = await client.ListAsync(scope);
                await Assert.That(outcome.IsSuccess).IsTrue();
            }
            return GC.GetTotalAllocatedBytes(precise: true) - before;
        });

        await MeasureAsync("InfisicalUniversalAuthentication.LoginAsync", async () =>
        {
            using var wire = new SyncWire(HttpStatusCode.OK, LoginJson);
            using var auth = new InfisicalUniversalAuthentication(new("https://auth.test"), wire, Options(wire));
            using var secret = SecretMaterial.FromText("client-secret");
            using (var warm = (await auth.LoginAsync("client-id", secret, auth.CreateReceipt())).Value) { }
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < 16; i++)
            {
                using var login = (await auth.LoginAsync("client-id", secret, auth.CreateReceipt())).Value;
            }
            return GC.GetTotalAllocatedBytes(precise: true) - before;
        });

        await MeasureAsync("InfisicalProofAuthentication.LoginAsync", async () =>
        {
            using var wire = new SyncWire(HttpStatusCode.OK, LoginJson);
            using var auth = new InfisicalProofAuthentication(new("https://auth.test"), wire, Options(wire));
            using var jwt = SecretMaterial.FromText("jwt-canary");
            using var proof = InfisicalLoginProof.Jwt("identity", jwt);
            using (var warm = (await auth.LoginAsync(proof, auth.CreateReceipt())).Value) { }
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < 16; i++)
            {
                using var login = (await auth.LoginAsync(proof, auth.CreateReceipt())).Value;
            }
            return GC.GetTotalAllocatedBytes(precise: true) - before;
        });

        await MeasureAsync("InfisicalProofAuthentication.RevokeTokenAsync", async () =>
        {
            using var wire = new SyncWire(HttpStatusCode.OK, RevokeJson);
            using var auth = new InfisicalProofAuthentication(new("https://auth.test"), wire, Options(wire));
            using var tok = SecretMaterial.FromText("tok-canary");
            _ = await auth.RevokeTokenAsync(tok, auth.CreateRevocationReceipt());
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < 16; i++)
            {
                var outcome = await auth.RevokeTokenAsync(tok, auth.CreateRevocationReceipt());
                await Assert.That(outcome.IsSuccess).IsTrue();
            }
            return GC.GetTotalAllocatedBytes(precise: true) - before;
        });

        await MeasureAsync("InfisicalPeriodicTokenSession.RenewAsync", async () =>
        {
            var clock = new FixedClock();
            using var wire = new SyncWire(HttpStatusCode.OK, LoginJson);
            using var initialToken = SecretMaterial.FromText("token-initial");
            await using var session = NewPeriodicSession(wire, initialToken, clock);
            _ = await session.RenewAsync();
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < 16; i++)
            {
                var outcome = await session.RenewAsync();
                await Assert.That(outcome.IsSuccess).IsTrue();
            }
            return GC.GetTotalAllocatedBytes(precise: true) - before;
        });

        await MeasureAsync("InfisicalFailureResponse.ReadAsync", async () =>
        {
            using var wire = new SyncWire(HttpStatusCode.Forbidden, ErrorJson);
            await using var client = new InfisicalClient(new("https://api.test"), tokens, Options(wire));
            var target = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "test", "/", "key"));
            _ = await client.ReadAsync(target);
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < 16; i++)
            {
                var outcome = await client.ReadAsync(target);
                await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Denied);
            }
            return GC.GetTotalAllocatedBytes(precise: true) - before;
        });
    }

    [Test]
    public async Task NestedDuplicateJsonKeysAreRejectedAcrossReaders()
    {
        var tokens = new FixedTokens();
        {
            using var wire = new SyncWire(HttpStatusCode.OK,
                """{"secret":{"id":"11111111-1111-4111-8111-111111111111","workspace":"project","environment":"test","secretPath":"/","type":"shared","secretKey":"key","secretValue":"v","secretValue":"evil","secretValueHidden":false,"version":1}}""");
            await using var client = new InfisicalClient(new("https://api.test"), tokens, Options(wire));
            var result = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress("project", "test", "/", "key")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.InvalidResponse);
        }

        {
            using var wire = new SyncWire(HttpStatusCode.OK,
                """{"accessToken":"tok","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0,"meta":{"k":1,"k":2}}""");
            using var auth = new InfisicalUniversalAuthentication(new("https://auth.test"), wire, Options(wire));
            using var secret = SecretMaterial.FromText("client-secret");
            var result = await auth.LoginAsync("client-id", secret, auth.CreateReceipt());
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.InvalidResponse);
        }

        {
            using var wire = new SyncWire(HttpStatusCode.OK,
                """{"accessToken":"tok","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0,"meta":{"k":1,"k":2}}""");
            using var auth = new InfisicalProofAuthentication(new("https://auth.test"), wire, Options(wire));
            using var jwt = SecretMaterial.FromText("jwt-canary");
            using var proof = InfisicalLoginProof.Jwt("identity", jwt);
            var result = await auth.LoginAsync(proof, auth.CreateReceipt());
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.InvalidResponse);
        }

        {
            var clock = new FixedClock();
            using var wire = new SyncWire(HttpStatusCode.OK,
                """{"accessToken":"tok","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0,"meta":{"k":1,"k":2}}""");
            using var initialToken = SecretMaterial.FromText("token-initial");
            await using var session = NewPeriodicSession(wire, initialToken, clock);
            var result = await session.RenewAsync();
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.InvalidResponse);
        }

        {
            string id = Guid.NewGuid().ToString("D");
            using var wire = new SyncWire(HttpStatusCode.OK,
                $$"""{"dynamicSecrets":[{"id":"{{id}}","name":"db","type":"sql-database","defaultTTL":"1h","maxTTL":"2h","inputs":{"k":1,"k":2},"status":null}]}""");
            await using var client = new InfisicalDynamicClient(new("https://api.test"), tokens,
                new("project", "test", "/", Guid.NewGuid()), Options(wire));
            var result = await client.ListDefinitionsAsync();
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.InvalidResponse);
        }

        {
            using var wire = new SyncWire(HttpStatusCode.Forbidden,
                """{"reqId":"req-1","statusCode":403,"error":"PermissionDenied","details":{"k":1,"k":2}}""");
            await using var client = new InfisicalClient(new("https://api.test"), tokens, Options(wire));
            var result = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress("project", "test", "/", "key")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.None);
            await Assert.That(result.CorrelationId).IsNull();
        }
    }

    [Test]
    public async Task ChunkedStreamAcrossPoolGrowthAndOversizeFailsClosed()
    {
        var tokens = new FixedTokens();
        string longValue = new('v', 10_000);
        string body = $$$"""{"secret":{"id":"11111111-1111-4111-8111-111111111111","workspace":"project","environment":"test","secretPath":"/","type":"shared","secretKey":"key","secretValue":"{{{longValue}}}","secretValueHidden":false,"version":1}}""";
        using var goodWire = new ChunkedWire(Encoding.UTF8.GetBytes(body), chunkSize: 128);
        await using var goodClient = new InfisicalClient(new("https://api.test"), tokens,
            new InfisicalNetworkOptions { MaximumResponseBytes = 16 * 1024, Transport = InfisicalTransportOptions.HostControlled(goodWire) });
        var target = new SecretReference(goodClient.Authority, new InfisicalSecretAddress("project", "test", "/", "key"));
        using SecretRead read = (await goodClient.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo(longValue);

        byte[] oversized = Encoding.UTF8.GetBytes($$"""{"accessToken":"{{new string('a', 17_000)}}","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0}""");
        using var hugeWire = new ChunkedWire(oversized, chunkSize: 256);
        using var auth = new InfisicalUniversalAuthentication(new("https://auth.test"), hugeWire,
            new InfisicalNetworkOptions { MaximumResponseBytes = 16 * 1024 });
        using var secret = SecretMaterial.FromText("client-secret");
        var hugeResult = await auth.LoginAsync("client-id", secret, auth.CreateReceipt());
        await Assert.That(hugeResult.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(hugeResult.Reason).IsEqualTo(SecretFailureReason.ResponseTooLarge);
    }

    private static async Task MeasureAsync(string name, Func<Task<long>> probe)
    {
        long allocated = await probe();
        await Assert.That(allocated).IsLessThan(8 * 1024 * 1024)
            .Because($"{name} across 16 calls should use pooled buffers rather than 16x MaximumResponseBytes ({FourMegabytes}B).");
    }

    private static InfisicalNetworkOptions Options(HttpMessageHandler wire) => new()
    {
        MaximumResponseBytes = FourMegabytes,
        Transport = InfisicalTransportOptions.HostControlled(wire)
    };

    private static InfisicalPeriodicTokenSession NewPeriodicSession(
        HttpMessageHandler wire, SecretMaterial initialToken, TimeProvider clock)
    {
        DateTimeOffset now = clock.GetUtcNow();
        return new InfisicalPeriodicTokenSession(
            new("https://auth.test"), initialToken,
            new()
            {
                Lifetime = InfisicalTokenLifetime.Periodic,
                OriginalIssuedAt = now,
                ExpiresAt = now + TimeSpan.FromMinutes(2),
                Period = TimeSpan.FromMinutes(2),
                ReportedMaximumTtl = TimeSpan.Zero
            }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(2),
            Options(wire), clock, wire, ownsTransport: false);
    }

    private sealed class FixedClock : TimeProvider
    {
        private static readonly DateTimeOffset Now = new(2026, 11, 16, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class FixedTokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("token"))));
    }

    private sealed class SyncWire(HttpStatusCode status, string body) : HttpMessageHandler
    {
        private readonly byte[] _utf8 = Encoding.UTF8.GetBytes(body);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new ByteArrayContent(_utf8)
            });
        }
    }

    private sealed class ChunkedWire(byte[] bytes, int chunkSize) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new ChunkedStream(bytes, chunkSize))
            });
    }

    private sealed class ChunkedStream(byte[] bytes, int chunkSize) : Stream
    {
        private int _offset;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            int take = Math.Min(Math.Min(buffer.Length, chunkSize), bytes.Length - _offset);
            if (take <= 0) return 0;
            bytes.AsSpan(_offset, take).CopyTo(buffer);
            _offset += take;
            return take;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Read(buffer.Span));
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
