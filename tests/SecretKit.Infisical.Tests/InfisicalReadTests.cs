using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class InfisicalReadTests
{
    [Test]
    public async Task NativeReadPreservesBytesAndExplicitVersion()
    {
        string value = NewMaterial() + "\r\n \n";
        Uri? observed = null;
        await using InfisicalClient client = Client(new WireHandler((request, _) =>
        {
            observed = request.RequestUri;
            return Task.FromResult(Json(new { secret = new { secretKey = "test-key", secretValue = value, secretValueHidden = false, version = 7 } }));
        }));
        var reference = Reference(client, version: 7);

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(reference);

        using SecretRead read = outcome.Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo(value);
        await Assert.That(read.Observation.Version).IsEqualTo("7");
        await Assert.That(observed!.AbsolutePath).IsEqualTo("/api/v4/secrets/test-key");
        await Assert.That(observed.Query.Contains("version=7", StringComparison.Ordinal)).IsTrue();
        await Assert.That(observed.Query.Contains("expandSecretReferences=false", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task RequestedVersionCannotBeSilentlySubstituted()
    {
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            Task.FromResult(Json(new { secret = new { secretKey = "test-key", secretValue = NewMaterial(), secretValueHidden = false, version = 3 } }))));

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client, version: 7));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ConcurrentIdentitiesWithSameKeyRetainIndependentValues()
    {
        string firstToken = NewMaterial();
        string secondToken = NewMaterial();
        string firstValue = NewMaterial();
        string secondValue = NewMaterial();
        var firstEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        WireHandler Transport(TaskCompletionSource entered) => new(async (request, token) =>
        {
            string? bearer = request.Headers.Authorization!.Parameter;
            entered.SetResult();
            await release.Task.WaitAsync(token);
            return Json(new
            {
                secret = new
                {
                    secretKey = "test-key",
                    secretValue = bearer == firstToken ? firstValue :
                        bearer == secondToken ? secondValue :
                        throw new InvalidOperationException("Unknown fixture identity."),
                    secretValueHidden = false,
                    version = 1
                }
            });
        });
        TokenSource Source(string token) => new(_ => ValueTask.FromResult(
            SecretOutcome<InfisicalAccessToken>.Success(new InfisicalAccessToken(SecretMaterial.FromText(token)))));
        await using InfisicalClient first = Client(Transport(firstEntered), Source(firstToken));
        await using InfisicalClient second = Client(Transport(secondEntered), Source(secondToken));
        Task<SecretOutcome<SecretRead>> firstPending = first.ReadAsync(Reference(first)).AsTask();
        Task<SecretOutcome<SecretRead>> secondPending = second.ReadAsync(Reference(second)).AsTask();
        await Task.WhenAll(firstEntered.Task, secondEntered.Task).WaitAsync(TimeSpan.FromSeconds(5));

        release.SetResult();

        SecretOutcome<SecretRead>[] outcomes = await Task.WhenAll(firstPending, secondPending);
        using SecretRead firstRead = outcomes[0].Value;
        using SecretRead secondRead = outcomes[1].Value;
        await Assert.That(firstRead.Material.Reveal()).IsEqualTo(firstValue);
        await Assert.That(secondRead.Material.Reveal()).IsEqualTo(secondValue);
        firstRead.Dispose();
        await Assert.That(secondRead.Material.Reveal()).IsEqualTo(secondValue);
    }

    [Test]
    public async Task InvalidTokenIsRejectedWithoutLeakingItsContents()
    {
        string canary = NewMaterial() + "\r\ninjected-header";
        var source = new TokenSource(_ => ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
            new InfisicalAccessToken(SecretMaterial.FromText(canary)))));
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            throw new InvalidOperationException("Invalid token dispatched.")), source);

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(JsonSerializer.Serialize(outcome).Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task PreDispatchCancellationDoesNotAcquireCredentials()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var source = new TokenSource(_ => throw new InvalidOperationException("Cancelled credential acquisition."));
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            throw new InvalidOperationException("Cancelled network dispatch.")), source);

        await Assert.That(async () => await client.ReadAsync(Reference(client), cancelled.Token))
            .Throws<OperationCanceledException>();
    }

    [Test]
    public async Task ShutdownCancelsAndDrainsActiveTransportBeforeReturning()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        InfisicalClient client = Client(new WireHandler(async (_, token) =>
        {
            entered.SetResult();
            return await response.Task.WaitAsync(token);
        }));
        Task<SecretOutcome<SecretRead>> pending = client.ReadAsync(Reference(client)).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await client.DisposeAsync();

        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(async () => await client.ReadAsync(Reference(client))).Throws<ObjectDisposedException>();
        await client.DisposeAsync();
    }

    [Test]
    [Arguments("true", SecretStatus.Denied)]
    [Arguments("null", SecretStatus.Unknown)]
    [Arguments("\"false\"", SecretStatus.Unknown)]
    public async Task WithheldOrUnverifiedMaterialIsNeverDeliveryEvidence(string visibility, SecretStatus expected)
    {
        await using InfisicalClient client = Client(new WireHandler((_, _) => Task.FromResult(Json(new
        {
            secret = new
            {
                secretKey = "test-key",
                secretValue = NewMaterial(),
                secretValueHidden = JsonSerializer.Deserialize<JsonElement>(visibility),
                version = 1
            }
        }))));

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(expected);
        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MissingVisibilityEvidenceFailsClosed()
    {
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            Task.FromResult(Json(new { secret = new { secretKey = "test-key", secretValue = NewMaterial(), version = 1 } }))));

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task AuthenticationTransportFailureCannotExposeItsMessage()
    {
        string canary = NewMaterial();
        var source = new TokenSource(_ => throw new HttpRequestException(canary));
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            throw new InvalidOperationException("Unauthenticated request dispatched.")), source);

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(JsonSerializer.Serialize(outcome).Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ReturnedKeyCannotReplaceTheSelectedReference()
    {
        await using InfisicalClient client = Client(new WireHandler((_, _) => Task.FromResult(Json(new
        {
            secret = new
            {
                secretKey = "other-key",
                secretValue = NewMaterial(),
                secretValueHidden = false,
                version = 1
            }
        }))));

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task AbsoluteRetryDateUsesOneClockObservation()
    {
        DateTimeOffset retryAt = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var clock = new AdvancingTime(retryAt.AddTicks(-5));
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
        {
            HttpResponseMessage response = Json(new { });
            response.StatusCode = HttpStatusCode.TooManyRequests;
            response.Headers.RetryAfter = new RetryConditionHeaderValue(retryAt);
            return Task.FromResult(response);
        }), time: clock);

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Throttled);
        await Assert.That(outcome.RetryAfter!.Value >= TimeSpan.Zero).IsTrue();
    }

    [Test]
    public async Task ForeignAuthorityIsRejectedBeforeTransportOrCredentials()
    {
        var source = new TokenSource(_ => throw new InvalidOperationException("Unexpected credential acquisition."));
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            throw new InvalidOperationException("Unexpected network dispatch.")), source);
        var reference = new SecretReference(new SecretAuthority(),
            new InfisicalSecretAddress("project", "test", "/", "test-key"));

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(reference);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(401, SecretStatus.Denied)]
    [Arguments(403, SecretStatus.Denied)]
    [Arguments(404, SecretStatus.Absent)]
    [Arguments(429, SecretStatus.Throttled)]
    [Arguments(503, SecretStatus.Unavailable)]
    [Arguments(302, SecretStatus.Invalid)]
    public async Task ExpectedFailuresNeverBecomeAbsenceOrExposeBodies(int code, SecretStatus status)
    {
        string canary = NewMaterial();
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage((HttpStatusCode)code) { Content = new StringContent(canary) })));

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(status);
        await Assert.That(JsonSerializer.Serialize(outcome).Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(outcome.RetryAfter).IsNull();
    }

    [Test]
    public async Task InvalidJsonShapeProducesBoundedOutcome()
    {
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]") })));

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("\"secretKey\":\"test-key\",\"version\":7,\"secretValueHidden\":true,\"secretValueHidden\":false")]
    [Arguments("\"secretKey\":\"test-key\",\"version\":7,\"secretValueHidden\":true,\"secretValue\\u0048idden\":false")]
    [Arguments("\"secretValueHidden\":false,\"version\":7,\"secretKey\":\"other-key\",\"secretKey\":\"test-key\"")]
    [Arguments("\"secretValueHidden\":false,\"secretKey\":\"test-key\",\"version\":3,\"version\":7")]
    public async Task DuplicateResponsePropertiesCannotPublishMaterial(string conflictingFields)
    {
        string canary = NewMaterial();
        string body = $$$"""
            {"secret":{"secretValue":"{{{canary}}}",{{{conflictingFields}}}}}
            """;
        await using InfisicalClient client = Client(new WireHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            })));

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client, version: 7));
        using SecretRead? read = outcome.IsSuccess ? outcome.Value : null;

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
        await Assert.That(JsonSerializer.Serialize(outcome).Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task CancelledTokenAcquisitionStillDisposesAcquiredCopy()
    {
        using var cancellation = new CancellationTokenSource();
        using SecretMaterial copy = SecretMaterial.FromText(NewMaterial());
        var source = new TokenSource(_ =>
        {
            cancellation.Cancel();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new InfisicalAccessToken(copy)));
        });
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            throw new InvalidOperationException("Cancelled read dispatched.")), source);

        await Assert.That(async () => await client.ReadAsync(Reference(client), cancellation.Token))
            .Throws<OperationCanceledException>();

        await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task InFlightCancellationReachesTransportAndPropagates()
    {
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using InfisicalClient client = Client(new WireHandler(async (_, token) =>
        {
            entered.SetResult();
            try
            {
                return await response.Task.WaitAsync(token);
            }
            catch (OperationCanceledException)
            {
                cancelled.SetResult();
                throw;
            }
        }));
        Task<SecretOutcome<SecretRead>> pending = client.ReadAsync(Reference(client), cancellation.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();

        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Test]
    public async Task MetadataInventoryNeverExposesMaterialAndReportsTruncation()
    {
        string canary = NewMaterial();
        string? query = null;
        await using InfisicalClient client = Client(new WireHandler((request, _) =>
        {
            query = request.RequestUri!.Query;
            return Task.FromResult(Json(new
            {
                secrets = new[]
                {
                    new { secretKey = "one", secretValue = canary, version = 1 },
                    new { secretKey = "two", secretValue = canary, version = 2 }
                }
            }));
        }));

        SecretOutcome<SecretInventory> outcome = await client.InspectAsync(
            new InfisicalInventoryScope(client.Authority, "project", "test", "/", maximumItems: 1));

        await Assert.That(outcome.Value.Items.Count).IsEqualTo(1);
        await Assert.That(outcome.Value.IsComplete).IsFalse();
        await Assert.That(outcome.Value.IsPointInTime).IsFalse();
        await Assert.That(query!.Contains("viewSecretValue=false", StringComparison.Ordinal)).IsTrue();
        await Assert.That(JsonSerializer.Serialize(outcome.Value).Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ResponseBudgetFailsClosedBeforePublishingMaterial()
    {
        await using InfisicalClient client = Client(new WireHandler((_, _) =>
            Task.FromResult(Json(new { secret = new { secretValue = new string('x', 2048), version = 1 } }))),
            maximumResponseBytes: 1024);

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task SensitiveCoordinatesAreNotFormattedOrSerialized()
    {
        string canary = NewMaterial();
        var address = new InfisicalSecretAddress(canary, canary, "/" + canary, canary);

        string json = JsonSerializer.Serialize(address);

        await Assert.That(json.Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(address.ToString().Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    private static string NewMaterial() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static SecretReference Reference(InfisicalClient client, int? version = null) =>
        new(client.Authority, new InfisicalSecretAddress("project", "test", "/", "test-key", version));

    private static HttpResponseMessage Json<T>(T response) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(response), Encoding.UTF8, "application/json")
    };

    private static InfisicalClient Client(WireHandler transport, IInfisicalTokenSource? tokens = null,
        int maximumResponseBytes = 1024 * 1024, TimeProvider? time = null) =>
        new(new Uri("https://infisical.test"), tokens ?? new TokenSource(_ =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new InfisicalAccessToken(SecretMaterial.FromText(NewMaterial()))))),
            new InfisicalNetworkOptions { MaximumResponseBytes = maximumResponseBytes }, time, transport);

    private sealed class AdvancingTime(DateTimeOffset start) : TimeProvider
    {
        private long _ticks;
        public override DateTimeOffset GetUtcNow() => start.AddTicks(Interlocked.Add(ref _ticks, 2));
    }

    private sealed class TokenSource(
        Func<CancellationToken, ValueTask<SecretOutcome<InfisicalAccessToken>>> supply) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            supply(cancellationToken);
    }

    private sealed class WireHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) => send(request, cancellationToken);
    }
}
