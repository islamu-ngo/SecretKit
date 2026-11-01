using System.Net;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class OperationBudgetTests
{
    [Test]
    public async Task SecondarySerializersRejectEncodedOverflowWithoutDispatch()
    {
        using var wire = new FailureEvidenceTests.Wire(_ => throw new InvalidOperationException("Oversized request dispatched."));
        await using var client = new InfisicalClient(new("https://api.test"), new FailureEvidenceTests.Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire), MaximumRequestBytes = 1024 });
        var authority = new InfisicalNativeAuthority(client.Authority, new FailureEvidenceTests.Tokens(), "project");
        string escaped = new('\u00e9', 600);
        var tag = new SecretReference(client.Authority, new InfisicalTagAddress("project", "tag", InfisicalOrganizationSelector.Slug));
        var tagResult = await client.CreateTagAsync(tag, escaped, authority, new(tag));
        var import = new SecretReference(client.Authority,
            new InfisicalImportAddress("project", "test", "/", Guid.NewGuid().ToString()));
        var importResult = await client.CreateImportAsync(import, new(escaped, "/"), false, authority, new(import));
        var rule = new SecretReference(client.Authority,
            new InfisicalValidationAddress("project", InfisicalValidationKind.StaticSecrets, secretPath: "/"));
        var ruleResult = await client.CreateValidationRuleAsync(rule,
            new(name: "rule", keyConstraints: new(regexPattern: escaped)), authority, new(rule));
        var bulk = new SecretReference(client.Authority, new InfisicalBulkAddress("project", "test", "/"));
        using var material = SecretMaterial.FromText(escaped);
        InfisicalBulkSecret[] inputs = [new("key", material)];
        var bulkReceipt = new InfisicalBulkReceipt(client, bulk, inputs, InfisicalBulkOperation.Create);
        var bulkResult = await client.CreateSecretsAsync(bulk, inputs, authority, bulkReceipt);
        await Assert.That(tagResult.Reason).IsEqualTo(SecretFailureReason.RequestTooLarge);
        await Assert.That(importResult.Reason).IsEqualTo(SecretFailureReason.RequestTooLarge);
        await Assert.That(ruleResult.Reason).IsEqualTo(SecretFailureReason.RequestTooLarge);
        await Assert.That(bulkResult.Reason).IsEqualTo(SecretFailureReason.RequestTooLarge);
        await Assert.That(bulkReceipt.Envelope.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1023)]
    [Arguments(16777217)]
    public async Task InvalidRequestBudgetsAreRejectedBeforeTransportUse(int maximum)
    {
        using var wire = new FailureEvidenceTests.Wire(_ => throw new InvalidOperationException("Invalid budget dispatched."));
        var network = new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire), MaximumRequestBytes = maximum };
        await Assert.That(() => new InfisicalUniversalAuthentication(new("https://api.test"), network)).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalProofAuthentication(new("https://api.test"), network)).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalClient(new("https://api.test"), new FailureEvidenceTests.Tokens(), network)).Throws<ArgumentException>();
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    public async Task LargerRequestBudgetDoesNotDependOnSmallerResponseBudget()
    {
        using var wire = new FailureEvidenceTests.Wire(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"secret":{"secretKey":"key-canary","workspace":"project-canary","environment":"test","secretPath":"/","type":"shared","version":1}}""")
        });
        await using var client = new InfisicalClient(new("https://api.test"), new FailureEvidenceTests.Tokens(),
            new InfisicalNetworkOptions
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                MaximumRequestBytes = 4096,
                MaximumResponseBytes = 1024
            });
        using var material = SecretMaterial.FromText(new string('x', 2000));
        var target = FailureEvidenceTests.Reference(client);
        var receipt = new MutationReceipt(target);
        var result = await client.CreateAsync(target, material, receipt);
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Requests).IsEqualTo(1);
    }

    [Test]
    public async Task OversizedResponsePreservesReadAndMutationFailureEvidence()
    {
        using var wire = new FailureEvidenceTests.Wire(_ => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(new string('x', 1025)) });
        await using var client = new InfisicalClient(new("https://api.test"), new FailureEvidenceTests.Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire), MaximumResponseBytes = 1024 });
        var target = FailureEvidenceTests.Reference(client);
        var read = await client.ReadNativeAsync(target);
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(read.Reason).IsEqualTo(SecretFailureReason.ResponseTooLarge);
        using var material = SecretMaterial.FromText("value");
        var receipt = new MutationReceipt(target);
        var mutation = await client.CreateAsync(target, material, receipt);
        await Assert.That(mutation.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(mutation.Reason).IsEqualTo(SecretFailureReason.ResponseTooLarge);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Requests).IsEqualTo(2);
    }

    [Test]
    [Arguments("read", SecretStatus.Unavailable)]
    [Arguments("dynamic", SecretStatus.Unavailable)]
    [Arguments("rotation", SecretStatus.Unavailable)]
    [Arguments("universal", SecretStatus.Unknown)]
    [Arguments("proof", SecretStatus.Unknown)]
    [Arguments("revocation", SecretStatus.Unknown)]
    [Arguments("renewal", SecretStatus.RecoveryRequired)]
    public async Task EveryDispatchOwnerBoundsStreamingAndSettlesOwnedBody(string owner, SecretStatus expected)
    {
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        using var body = new StalledBody();
        using var wire = new FailureEvidenceTests.Wire(_ => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StreamContent(body) });
        var network = new InfisicalNetworkOptions
        {
            Transport = InfisicalTransportOptions.HostControlled(wire),
            OperationTimeout = TimeSpan.FromSeconds(2)
        };
        Task<SecretStatus> pending = ExecuteAsync();
        await body.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        clock.Advance(TimeSpan.FromSeconds(3));
        await Assert.That(await pending.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(expected);
        await Assert.That(body.Disposed).IsTrue();
        await Assert.That(wire.Requests).IsEqualTo(1);

        async Task<SecretStatus> ExecuteAsync()
        {
            var tokens = new FailureEvidenceTests.Tokens();
            using var material = SecretMaterial.FromText("owned-token");
            switch (owner)
            {
                case "read":
                    await using (var client = new InfisicalClient(new("https://api.test"), tokens, network, clock))
                        return (await client.ReadAsync(FailureEvidenceTests.Reference(client))).Status;
                case "dynamic":
                    await using (var client = new InfisicalDynamicClient(new("https://api.test"), tokens,
                        new("project", "test", "/", Guid.NewGuid()), network, clock))
                        return (await client.ListDefinitionsAsync()).Status;
                case "rotation":
                    var authority = new SecretAuthority();
                    using (var client = new InfisicalRotationClient(new("https://api.test"), authority,
                        new(authority, tokens, "project"), network, clock))
                        return (await client.ListAsync(new(authority, new InfisicalRotationScope("project")))).Status;
                case "universal":
                    using (var client = new InfisicalUniversalAuthentication(new("https://api.test"), network, clock))
                        return (await client.LoginAsync("client", material, client.CreateReceipt())).Status;
                case "proof":
                    using (var client = new InfisicalProofAuthentication(new("https://api.test"), network, clock))
                    using (var proof = InfisicalLoginProof.Jwt("identity", material))
                        return (await client.LoginAsync(proof, client.CreateReceipt())).Status;
                case "revocation":
                    using (var client = new InfisicalProofAuthentication(new("https://api.test"), network, clock))
                        return await client.RevokeTokenAsync(material, client.CreateRevocationReceipt());
                case "renewal":
                    await using (var session = new InfisicalPeriodicTokenSession(new("https://api.test"), material,
                        new InfisicalTokenLifetimeEvidence
                        {
                            OriginalIssuedAt = clock.GetUtcNow(),
                            ExpiresAt = clock.GetUtcNow().AddMinutes(2),
                            Lifetime = InfisicalTokenLifetime.Periodic,
                            Period = TimeSpan.FromMinutes(2),
                            ReportedMaximumTtl = TimeSpan.Zero
                        }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), network, clock))
                        return await session.RenewAsync();
                default: throw new InvalidOperationException("Unexpected dispatch owner.");
            }
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LateCredentialIsDisposedWithoutDispatchAndCallerCancellationWins(bool callerCanceled)
    {
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tokens = new LateTokens(entered, release);
        using var wire = new FailureEvidenceTests.Wire(_ => throw new InvalidOperationException("Unexpected dispatch."));
        await using var client = new InfisicalClient(new("https://api.test"), tokens,
            new InfisicalNetworkOptions
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                OperationTimeout = TimeSpan.FromSeconds(2)
            }, clock);
        using var caller = new CancellationTokenSource();
        var pending = client.ReadAsync(FailureEvidenceTests.Reference(client), caller.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        clock.Advance(TimeSpan.FromSeconds(3));
        if (callerCanceled) caller.Cancel();
        release.SetResult();
        if (callerCanceled)
            await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        else
        {
            var result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        }
        await Assert.That(() => tokens.Issued!.Material.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    public async Task UnexpectedDependencyCancellationIsTransportFailure()
    {
        using var wire = new FailureEvidenceTests.Wire(_ => throw new OperationCanceledException("dependency-canary"));
        await using var client = new InfisicalClient(new("https://api.test"), new FailureEvidenceTests.Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var result = await client.ReadAsync(FailureEvidenceTests.Reference(client));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.TransportFailure);
    }

    [Test]
    public async Task RequestAndResponseLimitsAreIndependentAndOversizeNeverDispatches()
    {
        using var wire = new FailureEvidenceTests.Wire(_ => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent("""{"secret":{"secretValue":"small","secretKey":"key-canary","secretValueHidden":false}}""", Encoding.UTF8, "application/json") });
        await using var client = new InfisicalClient(new("https://api.test"), new FailureEvidenceTests.Tokens(),
            new InfisicalNetworkOptions
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                MaximumRequestBytes = 1024,
                MaximumResponseBytes = 4096
            });
        using var value = SecretMaterial.FromText(new string('x', 2000));
        var target = FailureEvidenceTests.Reference(client);
        var receipt = new MutationReceipt(target);
        var result = await client.CreateAsync(target, value, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.RequestTooLarge);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.Requests).IsEqualTo(0);
        using var read = (await client.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("small");
    }

    [Test]
    public async Task LateLoginRejectsPublicationButRetainsActualAppliedReceipt()
    {
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        using var wire = new FailureEvidenceTests.Wire(_ =>
        {
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new OnDisposeContent(
                    """{"accessToken":"issued","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""",
                    () => clock.Advance(TimeSpan.FromSeconds(3)))
            };
        });
        using var authentication = new InfisicalUniversalAuthentication(new("https://auth.test"),
            new InfisicalNetworkOptions
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                OperationTimeout = TimeSpan.FromSeconds(2)
            }, clock);
        using var secret = SecretMaterial.FromText("bootstrap");
        var receipt = authentication.CreateReceipt();
        var result = await authentication.LoginAsync("client", secret, receipt);
        await Assert.That(result.IsSuccess).IsFalse();
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    private sealed class LateTokens(TaskCompletionSource entered, TaskCompletionSource release) : IInfisicalTokenSource
    {
        internal InfisicalAccessToken? Issued { get; private set; }
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            entered.SetResult();
            await release.Task;
            Issued = new(SecretMaterial.FromText("late-token"));
            return SecretOutcome<InfisicalAccessToken>.Success(Issued);
        }
    }

    private sealed class StalledBody : Stream
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _never = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Disposed { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Entered.TrySetResult();
            await _never.Task.WaitAsync(cancellationToken);
            return 0;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
    }

    private sealed class OnDisposeContent(string body, Action onDispose) : StringContent(body)
    {
        private bool _disposed;
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (!_disposed) { _disposed = true; onDispose(); }
        }
    }
}
