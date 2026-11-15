using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class InfisicalFailureResponseTests
{
    [Test]
    [Arguments(400, "BadRequest", SecretFailureReason.ValidationFailed)]
    [Arguments(422, "ValidationFailure", SecretFailureReason.ValidationFailed)]
    [Arguments(401, "UnauthorizedError", SecretFailureReason.AuthenticationRejected)]
    [Arguments(403, "PermissionDenied", SecretFailureReason.PermissionDenied)]
    [Arguments(403, "ForbiddenError", SecretFailureReason.PermissionDenied)]
    [Arguments(404, "NotFound", SecretFailureReason.NotFoundOrInaccessible)]
    [Arguments(403, "Unrecognized", SecretFailureReason.None)]
    public async Task PublicReadRetainsOnlyClosedEvidenceAndExplicitCorrelation(
        int status, string error, SecretFailureReason reason)
    {
        using var wire = new Wire(status, JsonSerializer.Serialize(new
        {
            reqId = "request-private-canary",
            statusCode = status,
            error,
            message = "material-and-coordinate-canary",
            details = new { value = "nested-private-canary" }
        }));
        await using var client = Client(wire);

        var result = await client.ReadNativeAsync(Reference(client));

        await Assert.That(result.Reason).IsEqualTo(reason);
        await Assert.That(result.CorrelationId!.Reveal()).IsEqualTo("request-private-canary");
        string implicitOutput = result + JsonSerializer.Serialize(result);
        await Assert.That(implicitOutput.Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("""{"reqId":"one","reqId":"two","error":"PermissionDenied"}""")]
    [Arguments("""{"reqId":"one","error":"PermissionDenied","err\u006fr":"BadRequest"}""")]
    [Arguments("""{"reqId":12,"error":"PermissionDenied"}""")]
    [Arguments("""{"reqId":"one","error":{}}""")]
    [Arguments("""{"reqId":"one","error":"PermissionDenied","statusCode":200}""")]
    [Arguments("""{"reqId":"one","error":"PermissionDenied","message":false}""")]
    [Arguments("not-json")]
    public async Task InvalidEnvelopeCannotSupplyFinerEvidence(string body)
    {
        using var wire = new Wire(403, body);
        await using var client = Client(wire);

        var result = await client.ReadAsync(Reference(client));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.None);
        await Assert.That(result.CorrelationId).IsNull();
    }

    [Test]
    [Arguments("")]
    [Arguments("project/key")]
    [Arguments("private\nid")]
    public async Task InvalidIdentifierIsRejectedWithoutLosingValidClosedClass(string identifier)
    {
        using var wire = new Wire(403, JsonSerializer.Serialize(new { reqId = identifier, error = "PermissionDenied" }));
        await using var client = Client(wire);
        var result = await client.ReadAsync(Reference(client));
        await Assert.That(result.CorrelationId).IsNull();
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.PermissionDenied);
    }

    [Test]
    [Arguments(429, "Rate limit exceeded. Please try again in 0 seconds", 0)]
    [Arguments(429, "Rate limit exceeded. Please try again in 90000 seconds", 86400)]
    [Arguments(429, "Rate limit exceeded. Please try again in -1 seconds", -1)]
    [Arguments(429, "Rate limit exceeded. Please try again in 9223372036854775808 seconds", -1)]
    [Arguments(429, "wait 42 seconds", -1)]
    [Arguments(503, "Rate limit exceeded. Please try again in 42 seconds", -1)]
    public async Task OnlyExactNonnegative429GrammarSuppliesAdvice(int status, string message, int seconds)
    {
        using var wire = new Wire(status, JsonSerializer.Serialize(new { message }));
        await using var client = Client(wire);
        var result = await client.ReadAsync(Reference(client));
        await Assert.That(result.RetryAfter).IsEqualTo(seconds < 0 ? null : (TimeSpan?)TimeSpan.FromSeconds(seconds));
        await Assert.That(wire.Requests).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ValidHeaderWinsAndOversizedDetailsCannotEraseRejection(bool oversized)
    {
        using var wire = new Wire(429, oversized ? new string('x', 2048) :
            """{"message":"Rate limit exceeded. Please try again in 42 seconds"}""")
        { Advice = TimeSpan.FromSeconds(7) };
        await using var client = Client(wire);
        var target = Reference(client);
        var receipt = client.CreateReceipt(target);
        using var value = SecretMaterial.FromText("value");

        var result = await client.CreateAsync(target, value, receipt);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Throttled);
        await Assert.That(result.RetryAfter).IsEqualTo(TimeSpan.FromSeconds(7));
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
    }

    [Test]
    public async Task ConcurrentFailuresKeepTheirOwnCorrelation()
    {
        using var wire = new ConcurrentWire();
        await using var client = new InfisicalClient(new("https://api.test"), new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var firstReference = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "test", "/", "first"));
        var secondReference = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "test", "/", "second"));
        var first = client.ReadAsync(firstReference).AsTask();
        var second = client.ReadNativeAsync(secondReference).AsTask();
        await wire.BothEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        wire.Release.TrySetResult();

        await Assert.That((await first).CorrelationId!.Reveal()).IsEqualTo("first");
        await Assert.That((await second).CorrelationId!.Reveal()).IsEqualTo("second");
    }

    private sealed class ConcurrentWire : HttpMessageHandler
    {
        private int _entered;
        internal TaskCompletionSource BothEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string id = request.RequestUri!.Segments[^1];
            if (Interlocked.Increment(ref _entered) == 2) BothEntered.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.Forbidden)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { reqId = id, error = "PermissionDenied" }))
            };
        }
    }

    private static InfisicalClient Client(Wire wire) => new(new("https://api.test"), new Tokens(),
        new InfisicalNetworkOptions { MaximumResponseBytes = 1024, Transport = InfisicalTransportOptions.HostControlled(wire) });

    private static SecretReference Reference(InfisicalClient client) => new(client.Authority,
        new InfisicalSecretAddress("project", "test", "/", "key"));

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("token"))));
    }

    private sealed class Wire(int status, string body) : HttpMessageHandler
    {
        internal int Requests;
        internal TimeSpan? Advice { get; init; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Requests);
            var response = new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body) };
            if (Advice is { } advice) response.Headers.RetryAfter = new RetryConditionHeaderValue(advice);
            return Task.FromResult(response);
        }
    }
}
