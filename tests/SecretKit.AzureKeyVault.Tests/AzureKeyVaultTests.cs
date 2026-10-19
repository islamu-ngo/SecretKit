using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Tests;

public sealed class AzureKeyVaultTests
{
    private const string Version = "0123456789abcdef0123456789abcdef";
    private const string SecretJson =
        """{"value":"material-canary","id":"https://unit.vault.azure.net/secrets/name-canary/0123456789abcdef0123456789abcdef","attributes":{"enabled":true}}""";
    private static readonly Uri Vault = new("https://unit.vault.azure.net");

    [Test]
    [Arguments(401, SecretStatus.Denied)]
    [Arguments(403, SecretStatus.Denied)]
    [Arguments(404, SecretStatus.Absent)]
    [Arguments(429, SecretStatus.Throttled)]
    [Arguments(500, SecretStatus.Unavailable)]
    [Arguments(400, SecretStatus.Invalid)]
    [Arguments(409, SecretStatus.Conflict)]
    public async Task ProviderFailuresAreBoundedAndNeverRetried(int status, SecretStatus expected)
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(status,
            """{"error":{"code":"payload-canary","message":"material-canary name-canary"}}""")));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var outcome = await client.ReadAsync(Reference(client));
        await Assert.That(outcome.Status).IsEqualTo(expected);
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
        await Assert.That(JsonSerializer.Serialize(outcome).Contains("canary")).IsFalse();
        await Assert.That(outcome.ToString().Contains("canary")).IsFalse();
    }

    [Test]
    public async Task ActualSdkMapsNameVersionAndOwnsIndependentMaterial()
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, SecretJson)));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire, new FixedTime());
        var first = await client.ReadAsync(Reference(client));
        var second = await client.ReadAsync(Reference(client));
        await Assert.That(first.Status).IsEqualTo(SecretStatus.Success);
        using var read = first.Value;
        using var other = second.Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(wire.Requests[0].AbsolutePath).IsEqualTo($"/secrets/name-canary/{Version}");
        await Assert.That(wire.Requests[0].Query).IsEqualTo("?api-version=2025-07-01");
        await Assert.That(read.Observation.Version).IsEqualTo(Version);
        await Assert.That(read.Observation.ObservedAt).IsEqualTo(new FixedTime().GetUtcNow());
        read.Dispose();
        await Assert.That(other.Material.Reveal()).IsEqualTo("material-canary");
    }

    [Test]
    public async Task OversizedProviderResponseFailsClosedBeforeMaterialPublication()
    {
        string json = JsonSerializer.Serialize(new
        {
            value = new string('x', 1024 * 1024 + 100),
            id = $"https://unit.vault.azure.net/secrets/name-canary/{Version}",
            attributes = new { enabled = true }
        });
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, json)));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("https://other.vault.azure.net/secrets/name-canary/0123456789abcdef0123456789abcdef")]
    [Arguments("https://unit.vault.azure.net/secrets/another-name/0123456789abcdef0123456789abcdef")]
    [Arguments("https://unit.vault.azure.net/secrets/name-canary/ffffffffffffffffffffffffffffffff")]
    public async Task ReturnedCoordinatesCannotReplaceTheSelectedReference(string returnedId)
    {
        string json = JsonSerializer.Serialize(new
        {
            value = "nonproduction-material",
            id = returnedId,
            attributes = new { enabled = true }
        });
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, json)));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task UnknownLengthResponseIsBoundedWhileStreaming()
    {
        string json = JsonSerializer.Serialize(new
        {
            value = new string('x', 1024 * 1024 + 100),
            id = $"https://unit.vault.azure.net/secrets/name-canary/{Version}",
            attributes = new { enabled = true }
        });
        var wire = new WireTransport((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new UnknownLengthContent(json)
        }));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);

        SecretOutcome<SecretRead> outcome = await client.ReadAsync(Reference(client));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task InventoryCannotBindForeignVaultMetadataToLocalAuthority()
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200,
            """{"value":[{"id":"https://other.vault.azure.net/secrets/foreign","attributes":{"enabled":true}}]}""")));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);

        SecretOutcome<SecretInventory> outcome = await client.InspectAsync(new AzureInventoryScope(client.Authority));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ForeignAuthorityNeverReachesTransport()
    {
        var wire = new WireTransport((_, _) => throw new InvalidOperationException("Must not send."));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var read = await client.ReadAsync(new SecretReference(new SecretAuthority(), new AzureSecretAddress("same")));
        var list = await client.InspectAsync(new AzureInventoryScope(new SecretAuthority()));
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(list.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task InFlightReadCancellationPropagatesWithoutExceptionPayload()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var wire = new WireTransport(async (_, ct) =>
        {
            var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = ct.Register(() => cancelled.TrySetCanceled(ct));
            entered.TrySetResult();
            await cancelled.Task;
            throw new InvalidOperationException("Unreachable.");
        });
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        using var cancellation = new CancellationTokenSource();
        var pending = client.ReadAsync(Reference(client), cancellation.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<OperationCanceledException>();
    }

    [Test]
    [Arguments("""{"enabled":false}""", SecretStatus.Invalid)]
    [Arguments("""{"enabled":true,"nbf":2000000001}""", SecretStatus.Invalid)]
    [Arguments("""{"enabled":true,"exp":2000000000}""", SecretStatus.Expired)]
    [Arguments("""{}""", SecretStatus.Invalid)]
    public async Task InvalidMaterialIsNeverReturned(string attributes, SecretStatus expected)
    {
        var json = JsonSerializer.Serialize(new
        {
            value = "material-canary",
            id = $"https://unit.vault.azure.net/secrets/name-canary/{Version}",
            attributes = JsonSerializer.Deserialize<JsonElement>(attributes)
        });
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, json)));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire, new FixedTime());
        var outcome = await client.ReadAsync(Reference(client));
        await Assert.That(outcome.Status).IsEqualTo(expected);
        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task InventoryUsesOnlyMetadataAndReportsCollectionEvidence()
    {
        var wire = new WireTransport((request, _) => Task.FromResult(WireTransport.Json(200,
            request.RequestUri!.Query.Contains("skiptoken")
                ? """{"value":[{"id":"https://unit.vault.azure.net/secrets/second","attributes":{"enabled":false}}]}"""
                : """{"value":[{"id":"https://unit.vault.azure.net/secrets/name-canary","attributes":{"enabled":true,"exp":2000000000}}],"nextLink":"https://unit.vault.azure.net/secrets?api-version=2025-07-01&skiptoken=next"}""")));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire, new FixedTime());
        var outcome = await client.InspectAsync(new AzureInventoryScope(client.Authority));
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(outcome.Value.Items.Count).IsEqualTo(2);
        await Assert.That(outcome.Value.IsComplete).IsTrue();
        await Assert.That(outcome.Value.IsPointInTime).IsFalse();
        await Assert.That(outcome.Value.Items[0].Validity).IsEqualTo(SecretValidity.Expired);
        await Assert.That(outcome.Value.Items[1].Validity).IsEqualTo(SecretValidity.Disabled);
        await Assert.That(wire.Requests.All(uri => uri.AbsolutePath.TrimEnd('/') == "/secrets")).IsTrue();
        await Assert.That(JsonSerializer.Serialize(outcome.Value).Contains("canary")).IsFalse();
    }

    [Test]
    [Arguments(1, 10)]
    [Arguments(10, 1)]
    public async Task InventoryStopsAtPageOrItemBound(int pages, int items)
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200,
            """{"value":[{"id":"https://unit.vault.azure.net/secrets/first","attributes":{"enabled":true}},{"id":"https://unit.vault.azure.net/secrets/second","attributes":{"enabled":true}}],"nextLink":"https://unit.vault.azure.net/secrets?skiptoken=next"}""")));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var outcome = await client.InspectAsync(new AzureInventoryScope(client.Authority, pages, items));
        await Assert.That(outcome.Value.IsComplete).IsFalse();
        await Assert.That(outcome.Value.Items.Count).IsEqualTo(Math.Min(items, 2));
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task CrossOriginContinuationIsRejectedBeforeSending()
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200,
            """{"value":[],"nextLink":"https://other.vault.azure.net/secrets"}""")));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var outcome = await client.InspectAsync(new AzureInventoryScope(client.Authority));
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("https://unit.vault.azure.net/secrets?api-version=7.6&skiptoken=next")]
    [Arguments("https://unit.vault.azure.net/deletedsecrets?api-version=2025-07-01&skiptoken=next")]
    [Arguments("https://unit.vault.azure.net/secrets?skiptoken=next")]
    public async Task ContinuationCannotChangeInventoryOperationOrApiRevision(string nextLink)
    {
        string json = JsonSerializer.Serialize(new { value = Array.Empty<object>(), nextLink });
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, json)));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);

        SecretOutcome<SecretInventory> outcome = await client.InspectAsync(new AzureInventoryScope(client.Authority));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(403, SecretStatus.Denied)]
    [Arguments(404, SecretStatus.Absent)]
    public async Task InventoryFailureHasNoPayloadOrPartialSuccess(int status, SecretStatus expected)
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(status,
            """{"error":{"message":"material-canary"}}""")));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var outcome = await client.InspectAsync(new AzureInventoryScope(client.Authority));
        await Assert.That(outcome.Status).IsEqualTo(expected);
        await Assert.That(JsonSerializer.Serialize(outcome).Contains("canary")).IsFalse();
    }

    [Test]
    public async Task CancellationStopsInventoryBeforeTheNextPage()
    {
        using var cancellation = new CancellationTokenSource();
        var wire = new WireTransport((_, _) =>
        {
            cancellation.Cancel();
            return Task.FromResult(WireTransport.Json(200,
                """{"value":[],"nextLink":"https://unit.vault.azure.net/secrets?skiptoken=next"}"""));
        });
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        await Assert.That(async () => await client.InspectAsync(
            new AzureInventoryScope(client.Authority), cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task UnversionedReadSelectsLatestWithoutInventingAVersion()
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, SecretJson)));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var outcome = await client.ReadAsync(new SecretReference(client.Authority, new AzureSecretAddress("name-canary")));
        using var read = outcome.Value;
        await Assert.That(wire.Requests.Single().AbsolutePath).IsEqualTo("/secrets/name-canary/");
        await Assert.That(read.Observation.Version).IsEqualTo(Version);
    }

    [Test]
    public async Task TerminalOversizedPageIsTruthfullyIncomplete()
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200,
            """{"value":[{"id":"https://unit.vault.azure.net/secrets/first","attributes":{"enabled":true}},{"id":"https://unit.vault.azure.net/secrets/second","attributes":{"enabled":true}}]}""")));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var outcome = await client.InspectAsync(new AzureInventoryScope(client.Authority, maximumItems: 1));
        await Assert.That(outcome.Value.IsComplete).IsFalse();
        await Assert.That(outcome.Value.Items.Count).IsEqualTo(1);
    }

    [Test]
    public async Task TransportAndCredentialExceptionsCannotLeakPayloads()
    {
        var wire = new WireTransport((_, _) => throw new InvalidOperationException("material-canary name-canary"));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var read = await client.ReadAsync(Reference(client));
        var inventory = await client.InspectAsync(new AzureInventoryScope(client.Authority));
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(inventory.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(JsonSerializer.Serialize(read).Contains("canary")).IsFalse();
        await Assert.That(JsonSerializer.Serialize(inventory).Contains("canary")).IsFalse();
        var challengedWire = new WireTransport((_, _) => Task.FromResult(WireTransport.Challenge()));
        var failedCredentialClient = new AzureKeyVaultClient(Vault,
            new TestCredential { Fail = true }, challengedWire);
        var authentication = await failedCredentialClient.ReadAsync(Reference(failedCredentialClient));
        await Assert.That(authentication.IsSuccess).IsFalse();
        await Assert.That(JsonSerializer.Serialize(authentication).Contains("canary")).IsFalse();
        await Assert.That(challengedWire.Authorized.Any(authorized => authorized)).IsFalse();
    }

    [Test]
    public async Task CoordinatesAndMaterialStayOutOfJsonAndFormatting()
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, SecretJson)));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var reference = Reference(client);
        var scope = new AzureInventoryScope(client.Authority);
        var outcome = await client.ReadAsync(reference);
        using var read = outcome.Value;
        foreach (var value in new object[] { reference.Address, reference, scope, read, read.Observation, read.Material })
        {
            await Assert.That(JsonSerializer.Serialize(value).Contains("canary")).IsFalse();
            await Assert.That(JsonSerializer.Serialize(value).Contains(Version)).IsFalse();
            await Assert.That(value.ToString()!.Contains("canary")).IsFalse();
        }
    }

    [Test]
    public async Task ValidChallengeUsesCallerCredentialWithVerifiedResource()
    {
        var vault = new Uri($"https://valid-{Guid.NewGuid().ToString("N")[..16]}.vault.azure.net");
        string secretJson = SecretJson.Replace(Vault.Host, vault.Host, StringComparison.Ordinal);
        var credential = new TestCredential();
        var wire = new WireTransport((request, _) => Task.FromResult(
            request.Headers.Authorization is null ? WireTransport.Challenge() : WireTransport.Json(200, secretJson)));
        var client = new AzureKeyVaultClient(vault, credential, wire);
        var outcome = await client.ReadAsync(Reference(client));
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
        using var read = outcome.Value;
        await Assert.That(credential.Scopes.Single().Single()).IsEqualTo("https://vault.azure.net/.default");
        await Assert.That(wire.Authorized.SequenceEqual(new[] { false, true })).IsTrue();
    }

    [Test]
    public async Task ForgedChallengeCannotAcquireOrSendToken()
    {
        var vault = new Uri($"https://forged-{Guid.NewGuid().ToString("N")[..16]}.vault.azure.net");
        var credential = new TestCredential();
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Challenge("https://evil.example")));
        var client = new AzureKeyVaultClient(vault, credential, wire);
        var outcome = await client.ReadAsync(Reference(client));
        await Assert.That(outcome.IsSuccess).IsFalse();
        await Assert.That(credential.Scopes.Count).IsEqualTo(0);
        await Assert.That(wire.Authorized.Any(authorized => authorized)).IsFalse();
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task AzureSdkLoggingContentAndActivitiesAreDisabled()
    {
        using var events = new AzureEvents();
        var activities = new ConcurrentBag<string>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name.StartsWith("Azure.", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = activity => activities.Add(activity.OperationName)
        };
        ActivitySource.AddActivityListener(listener);
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, SecretJson)));
        var client = new AzureKeyVaultClient(Vault, new TestCredential(), wire);
        var outcome = await client.ReadAsync(Reference(client));
        using var read = outcome.Value;
        await Assert.That(events.Payloads.Any(text => text.Contains("canary") || text.Contains("unit.vault"))).IsFalse();
        await Assert.That(activities.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("http://unit.vault.azure.net")]
    [Arguments("https://evil.example")]
    [Arguments("https://unit.vault.azure.net/extra")]
    [Arguments("https://unit.vault.azure.net:8443")]
    [Arguments("https://user@unit.vault.azure.net")]
    public async Task UntrustedEndpointIsRejected(string endpoint)
    {
        await Assert.That(() => new AzureKeyVaultClient(new Uri(endpoint), new TestCredential()))
            .Throws<ArgumentException>();
    }

    private static SecretReference Reference(AzureKeyVaultClient client) =>
        new(client.Authority, new AzureSecretAddress("name-canary", Version));

    private sealed class AzureEvents : EventListener
    {
        public ConcurrentBag<string> Payloads { get; } = [];

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name.StartsWith("Azure-", StringComparison.Ordinal))
            {
                EnableEvents(eventSource, EventLevel.Verbose);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData.Payload is not null)
            {
                Payloads.Add(string.Join(" ", eventData.Payload));
            }
        }
    }

    private sealed class UnknownLengthContent(string json) : HttpContent
    {
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(Encoding.UTF8.GetBytes(json)).AsTask();

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromResult<Stream>(new MemoryStream(Encoding.UTF8.GetBytes(json)));
    }
}
