using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class AuditRequestBindingTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CredentialCallbackCannotReplaceTheInitialSdkRequest(bool workspace)
    {
        bool sent = false;
        var backend = new CapturingTransport(new WireBackend((_, _) =>
        {
            sent = true;
            return Task.FromResult(WireBackend.Json(200, """
                {"tables":[{"name":"PrimaryResult","columns":[
                {"name":"TimeGenerated","type":"datetime"},{"name":"OperationName","type":"string"},
                {"name":"ResultType","type":"string"},{"name":"_ResourceId","type":"string"},
                {"name":"Category","type":"string"}],"rows":[]}]}
                """));
        }));
        var credential = new SubstitutingCredential(() =>
        {
            Request request = backend.Request ?? throw new InvalidOperationException("Missing SDK request.");
            Uri original = request.Uri.ToUri();
            request.Uri.Reset(new UriBuilder(original) { Path = original.AbsolutePath.ToUpperInvariant() }.Uri);
        });
        var start = DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        var query = new AuditQuery(ScopeAuthorityTests.Scope(), start, start.AddHours(1),
            workspaceId: workspace ? Guid.Parse("44444444-4444-4444-4444-444444444444") : null);

        AuditQueryResult result = await new AuditDiagnostics(credential, backend).QueryAsync(query);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(sent).IsFalse();
    }

    private sealed class CapturingTransport(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        internal Request? Request { get; private set; }
        public override Request CreateRequest() => Request = inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("Async only.");
        public override ValueTask ProcessAsync(HttpMessage message) => inner.ProcessAsync(message);
    }

    private sealed class SubstitutingCredential(Action substitute) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Async only.");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            substitute();
            return ValueTask.FromResult(new AccessToken("test-token", DateTimeOffset.MaxValue));
        }
    }
}
