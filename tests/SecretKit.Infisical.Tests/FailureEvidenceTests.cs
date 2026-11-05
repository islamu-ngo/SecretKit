using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

[NotInParallel]
public sealed class FailureEvidenceTests
{
    [Test]
    public async Task ListenerReentryAcrossAnAsynchronousReadDoesNotRecurse()
    {
        using var wire = new AsynchronousWire();
        await using var client = new InfisicalClient(new("https://api.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        SecretReference reference = Reference(client);
        int callbacks = 0;
        Exception? reentryError = null;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "SecretKit.Infisical",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = _ =>
            {
                // Bound the faulty implementation's recursion without suppressing its evidence.
                if (Interlocked.Increment(ref callbacks) != 1) return;
                try
                {
                    using SecretRead nested = client.ReadAsync(reference).AsTask()
                        .WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult().Value;
                }
                catch (Exception error) { reentryError = error; }
            }
        };
        ActivitySource.AddActivityListener(listener);

        using SecretRead read = (await client.ReadAsync(reference)).Value;
        await Assert.That(reentryError).IsNull();
        await Assert.That(callbacks).IsEqualTo(1);
        await Assert.That(wire.Requests).IsEqualTo(2);
    }

    private sealed class AsynchronousWire : HttpMessageHandler
    {
        internal int Requests;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Requests);
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"secret":{"secretKey":"key-canary","secretValueHidden":false,"secretValue":"value-canary"}}""")
            };
        }
    }

    [Test]
    [Arguments("invalid", false)]
    [Arguments("past", true)]
    public async Task MalformedAdviceIsAbsentAndPastAdviceIsZero(string selection, bool zero)
    {
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        using var wire = new Wire(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            response.Headers.TryAddWithoutValidation("Retry-After", selection == "past"
                ? clock.GetUtcNow().AddDays(-1).ToString("R") : "not-a-duration-canary");
            return response;
        });
        await using var client = new InfisicalClient(new("https://api.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) }, clock);
        var result = await client.ReadAsync(Reference(client));
        await Assert.That(result.RetryAfter).IsEqualTo(zero ? TimeSpan.Zero : (TimeSpan?)null);
        await Assert.That(wire.Requests).IsEqualTo(1);
    }

    [Test]
    public async Task NativeFamiliesPreserveUnavailableAdviceWithoutReplayingMutations()
    {
        using var wire = new Wire(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
            return response;
        });
        var network = new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) };
        var tokens = new Tokens();
        await using var client = new InfisicalClient(new("https://api.test"), tokens, network);
        var tags = await client.ListTagsAsync(new(client.Authority, new InfisicalTagAddress("project-canary")));
        var imports = await client.ListImportsAsync(new(client.Authority,
            new InfisicalImportAddress("project-canary", "test", "/", Guid.NewGuid().ToString())));
        var rules = await client.ListValidationRulesAsync(new(client.Authority,
            new InfisicalValidationAddress("project-canary", InfisicalValidationKind.StaticSecrets)));
        await using var dynamicClient = new InfisicalDynamicClient(new("https://api.test"), tokens,
            new("project-canary", "test", "/", Guid.NewGuid()), network);
        var definitions = await dynamicClient.ListDefinitionsAsync();
        var authority = new InfisicalNativeAuthority(client.Authority, tokens, "project-canary");
        using var rotation = new InfisicalRotationClient(new("https://api.test"), client.Authority, authority, network);
        var rotations = await rotation.ListAsync(new(client.Authority, new InfisicalRotationScope("project-canary")));
        await Assert.That(tags.RetryAfter).IsEqualTo(TimeSpan.FromSeconds(7));
        await Assert.That(imports.RetryAfter).IsEqualTo(TimeSpan.FromSeconds(7));
        await Assert.That(rules.RetryAfter).IsEqualTo(TimeSpan.FromSeconds(7));
        await Assert.That(definitions.RetryAfter).IsEqualTo(TimeSpan.FromSeconds(7));
        await Assert.That(rotations.RetryAfter).IsEqualTo(TimeSpan.FromSeconds(7));
        var target = Reference(client);
        var receipt = client.CreateReceipt(target);
        using var material = SecretMaterial.FromText("mutation-canary");
        var mutation = await client.CreateAsync(target, material, receipt);
        await Assert.That(mutation.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(mutation.RetryAfter).IsNull();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.CreateAsync(target, material, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests).IsEqualTo(6);
    }

    [Test]
    [Arguments(429, false, 12)]
    [Arguments(503, false, 12)]
    [Arguments(503, true, 12)]
    [Arguments(503, false, 1000000)]
    public async Task AdviceSurvivesCommonNativeAndInventoryProjection(int code, bool date, int seconds)
    {
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        var wire = new Wire(_ =>
        {
            var response = new HttpResponseMessage((HttpStatusCode)code);
            response.Headers.RetryAfter = date
                ? new RetryConditionHeaderValue(clock.GetUtcNow().AddSeconds(seconds))
                : new RetryConditionHeaderValue(TimeSpan.FromSeconds(seconds));
            return response;
        });
        await using var client = new InfisicalClient(new("https://coordinate-canary.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) }, clock);
        var reference = Reference(client);
        var common = await client.ReadAsync(reference);
        var native = await client.ReadNativeAsync(reference);
        var inventory = await client.InspectAsync(new InfisicalInventoryScope(client.Authority, "project-canary", "test", "/"));
        TimeSpan expected = TimeSpan.FromSeconds(Math.Min(seconds, 86400));
        await Assert.That(common.RetryAfter).IsEqualTo(expected);
        await Assert.That(native.RetryAfter).IsEqualTo(expected);
        await Assert.That(inventory.RetryAfter).IsEqualTo(expected);
        await Assert.That(wire.Requests).IsEqualTo(3);
        await Assert.That(JsonSerializer.Serialize(common).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task TransportFailureHasClosedReasonWithoutExceptionCanary()
    {
        using var wire = new Wire(_ => throw new HttpRequestException("exception-canary"));
        await using var client = new InfisicalClient(new("https://coordinate-canary.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var outcome = await client.ReadNativeAsync(Reference(client));
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(outcome.Reason).IsEqualTo(SecretFailureReason.TransportFailure);
        await Assert.That(JsonSerializer.Serialize(outcome).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(wire.Requests).IsEqualTo(1);
    }

    [Test]
    public async Task ThrowingSamplerCannotReplaceMutationReceiptOrOutcome()
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "SecretKit.Infisical",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => throw new InvalidOperationException("sampler-canary")
        };
        ActivitySource.AddActivityListener(listener);
        using var wire = new Wire(_ => new HttpResponseMessage(HttpStatusCode.Conflict));
        await using var client = new InfisicalClient(new("https://coordinate-canary.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var target = Reference(client);
        var receipt = client.CreateReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");
        var result = await client.CreateAsync(target, material, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Conflict);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Conflict);
        await Assert.That(wire.Requests).IsEqualTo(1);
        await Assert.That(JsonSerializer.Serialize(result).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ClosedDiagnosticsRemainObservableWithThrowingAndReentrantListeners(bool hostile)
    {
        var captured = new List<KeyValuePair<string, object?>>();
        int activities = 0, measurements = 0;
        bool reentered = false;
        InfisicalClient? client = null;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "SecretKit.Infisical",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = activity =>
            {
                activities++;
                captured.AddRange(activity.TagObjects);
                if (activity.OperationName == "positive-control") return;
                if (!reentered)
                {
                    reentered = true;
                    _ = client!.ReadAsync(new SecretReference(new SecretAuthority(),
                        new InfisicalSecretAddress("foreign-canary", "test", "/", "key-canary"))).GetAwaiter().GetResult();
                }
                if (hostile) throw new InvalidOperationException("listener-canary");
            }
        };
        ActivitySource.AddActivityListener(listener);
        using var meter = new MeterListener();
        meter.InstrumentPublished = (instrument, owner) =>
        {
            if (instrument.Meter.Name == "SecretKit.Infisical") owner.EnableMeasurementEvents(instrument);
        };
        meter.SetMeasurementEventCallback<long>((instrument, _, tags, _) =>
        {
            measurements++;
            foreach (var tag in tags) captured.Add(tag);
            if (instrument.Name == "positive-control") return;
            if (hostile) throw new InvalidOperationException("measurement-canary");
        });
        meter.Start();
        using var controlSource = new ActivitySource("SecretKit.Infisical");
        using (var control = controlSource.StartActivity("positive-control"))
            control?.SetTag("positive", "canary");
        using var controlMeter = new Meter("SecretKit.Infisical");
        controlMeter.CreateCounter<long>("positive-control").Add(1, new KeyValuePair<string, object?>("positive", "canary"));
        await Assert.That(activities > 0 && measurements > 0).IsTrue();
        await Assert.That(JsonSerializer.Serialize(captured).Contains("canary", StringComparison.Ordinal)).IsTrue();
        captured.Clear();
        activities = measurements = 0;
        using var wire = new Wire(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        await using (client = new InfisicalClient(new("https://coordinate-canary.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) }))
        {
            var result = await client.ReadAsync(Reference(client));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
        }
        await Assert.That(activities > 0).IsTrue();
        await Assert.That(measurements > 0).IsTrue();
        await Assert.That(captured.All(tag => tag.Key is "operation" or "outcome" or "reason" or "dispatch" or "termination")).IsTrue();
        await Assert.That(JsonSerializer.Serialize(captured).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    internal static SecretReference Reference(InfisicalClient client) =>
        new(client.Authority, new InfisicalSecretAddress("project-canary", "test", "/", "key-canary"));

    internal sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("token-canary"))));
    }

    internal sealed class Wire(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(response(request));
        }
    }
}
