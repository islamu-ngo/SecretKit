using System.Net;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class NativeRequestIntentTests
{
    private static readonly Uri Origin = new("https://native.test");
    private const string Path = "/api/v1/dynamic-secrets";

    [Test]
    [Arguments("/api/v1/dynamic-secrets", "/api/v1/dynamic-secrets")]
    [Arguments("api/v1/dynamic-secrets", "/api/v1/dynamic-secrets")]
    [Arguments("https://native.test/api/v1/dynamic-secrets", "/api/v1/dynamic-secrets")]
    [Arguments("/api/v1/dynamic-secrets/caf%C3%A9%20name", "/api/v1/dynamic-secrets/caf%C3%A9%20name")]
    [Arguments("/api/v1/dynamic-secrets/a%2Fb", "/api/v1/dynamic-secrets/a%2Fb")]
    [Arguments("/api/v1/dynamic-secrets/a%252Fb", "/api/v1/dynamic-secrets/a%252Fb")]
    public async Task MatchingEscapedCoordinatesBindToTheConstructorOrigin(string destination, string path)
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, path);
        using var request = new HttpRequestMessage(HttpMethod.Get, destination);

        bool accepted = intent.TryBind(request, Origin);

        await Assert.That(accepted).IsTrue();
        await Assert.That(request.RequestUri!.IsAbsoluteUri).IsTrue();
        await Assert.That(request.RequestUri.AbsoluteUri).IsEqualTo("https://native.test" + path);
    }

    [Test]
    [Arguments("?path=%2Ffolder%20one&environmentSlug=prod&projectSlug=caf%C3%A9")]
    [Arguments("?projectSlug=caf%C3%A9&path=%2Ffolder%20one&environmentSlug=prod")]
    public async Task ScalarQueriesMatchDecodedValuesInEitherOrder(string query)
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path,
            new Dictionary<string, string>
            {
                ["projectSlug"] = "caf\u00e9",
                ["environmentSlug"] = "prod",
                ["path"] = "/folder one"
            });
        using var request = new HttpRequestMessage(HttpMethod.Get, Path + query);

        bool accepted = intent.TryBind(request, Origin);

        await Assert.That(accepted).IsTrue();
        await Assert.That(request.RequestUri!.Host).IsEqualTo("native.test");
    }

    [Test]
    [Arguments("http://native.test/api/v1/dynamic-secrets")]
    [Arguments("https://other.test/api/v1/dynamic-secrets")]
    [Arguments("https://native.test:8443/api/v1/dynamic-secrets")]
    [Arguments("https://user@native.test/api/v1/dynamic-secrets")]
    [Arguments("https://@native.test/api/v1/dynamic-secrets")]
    [Arguments("//other.test/api/v1/dynamic-secrets")]
    [Arguments("/api/v1/dynamic-secrets#fragment")]
    [Arguments("/api/v1/dynamic-secrets#")]
    [Arguments("/api/v1/other")]
    [Arguments("/api/v1/dynamic-secrets?extra=value")]
    [Arguments("/api/v1/x/../dynamic-secrets")]
    [Arguments("/api/v1/./dynamic-secrets")]
    [Arguments("/api/v1/%2E/dynamic-secrets")]
    [Arguments("/api/v1/x/%2e%2e/dynamic-secrets")]
    [Arguments("/api/v1/x%2F..%2Fdynamic-secrets")]
    [Arguments("/api/v1/x\\..\\dynamic-secrets")]
    [Arguments("/api/v1/dynamic-secrets?value=%")]
    public async Task MismatchedOrAmbiguousDestinationLeavesRequestUnbound(string destination)
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path);
        using var request = new HttpRequestMessage(HttpMethod.Get, destination);
        Uri original = request.RequestUri!;

        bool accepted = intent.TryBind(request, Origin);

        await Assert.That(accepted).IsFalse();
        await Assert.That(ReferenceEquals(request.RequestUri, original)).IsTrue();
    }

    [Test]
    [Arguments("/api/v1/dynamic-secrets/.")]
    [Arguments("/api/v1/dynamic-secrets/..")]
    [Arguments("/api/v1/dynamic-secrets/%2E%2E")]
    [Arguments("/api/v1/dynamic-secrets/a%2F..")]
    [Arguments("/api/v1/dynamic-secrets?x=y")]
    [Arguments("/api/v1/dynamic-secrets#fragment")]
    [Arguments("/api/v1/dynamic-secrets/%")]
    [Arguments("/api/v1/dynamic-secrets/%2")]
    [Arguments("/api/v1/dynamic-secrets/%GG")]
    [Arguments("/api/v1/dynamic-secrets/%41")]
    [Arguments("/api/v1/dynamic-secrets/%00")]
    [Arguments("/api/v1/dynamic-secrets/%5C")]
    [Arguments("api/v1/dynamic-secrets")]
    [Arguments("//native.test/api/v1/dynamic-secrets")]
    [Arguments("")]
    public async Task MalformedExpectedPathCannotAuthorizeItsNormalizedRequest(string path)
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, path);
        using var request = new HttpRequestMessage(HttpMethod.Get,
            path.Length == 0 ? Path : path);

        bool accepted = intent.TryBind(request, Origin);

        await Assert.That(accepted).IsFalse();
    }

    [Test]
    [Arguments("?key=one&key=one")]
    [Arguments("?key=one&%6Bey=one")]
    [Arguments("?key=two")]
    [Arguments("?key=one&extra=two")]
    [Arguments("?key=one&&")]
    [Arguments("?key=%")]
    [Arguments("")]
    public async Task ScalarQueryPollutionOrMismatchCannotBind(string query)
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path,
            new Dictionary<string, string> { ["key"] = "one" });
        using var request = new HttpRequestMessage(HttpMethod.Get, Path + query);

        bool accepted = intent.TryBind(request, Origin);

        await Assert.That(accepted).IsFalse();
        await Assert.That(request.RequestUri!.IsAbsoluteUri).IsFalse();
    }

    [Test]
    [Arguments("/api/v1/dynamic-secrets/a/b")]
    [Arguments("/api/v1/dynamic-secrets/a%252Fb")]
    public async Task EscapedSlashMustMatchTheExactSelectedSegment(string destination)
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path + "/a%2Fb");
        using var request = new HttpRequestMessage(HttpMethod.Get, destination);

        await Assert.That(intent.TryBind(request, Origin)).IsFalse();
    }

    [Test]
    [Arguments("%252F", "%2F")]
    [Arguments("%2B", "+")]
    [Arguments("+", "+")]
    [Arguments("%26%3D", "&=")]
    [Arguments("", "")]
    public async Task QueryComponentsDecodeExactlyOnceAfterSplitting(string encoded, string expected)
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path,
            new Dictionary<string, string> { ["key"] = expected });
        using var request = new HttpRequestMessage(HttpMethod.Get, Path + "?key=" + encoded);

        await Assert.That(intent.TryBind(request, Origin)).IsTrue();
    }

    [Test]
    public async Task IntentRetainsItsQuerySnapshotWhenCallerChangesTheDictionary()
    {
        var query = new Dictionary<string, string> { ["key"] = "selected" };
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path, query);
        query["key"] = "replacement";
        using var request = new HttpRequestMessage(HttpMethod.Get, Path + "?key=selected");

        await Assert.That(intent.TryBind(request, Origin)).IsTrue();
    }

    [Test]
    public async Task ScalarQueryRequiresAnExplicitValueSeparator()
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path,
            new Dictionary<string, string> { ["key"] = "" });
        using var request = new HttpRequestMessage(HttpMethod.Get, Path + "?key");

        await Assert.That(intent.TryBind(request, Origin)).IsFalse();
    }

    [Test]
    public async Task WrongMethodRejectsWithoutTakingOwnershipOfContent()
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path);
        var content = new DisposalContent();
        var request = new HttpRequestMessage(HttpMethod.Delete, Path) { Content = content };

        bool accepted = intent.TryBind(request, Origin);
        bool disposedBeforeCaller = content.Disposed;
        request.Dispose();

        await Assert.That(accepted).IsFalse();
        await Assert.That(disposedBeforeCaller).IsFalse();
        await Assert.That(content.Disposed).IsTrue();
    }

    [Test]
    public async Task MissingDestinationCannotBind()
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path);
        using var request = new HttpRequestMessage();

        await Assert.That(intent.TryBind(request, Origin)).IsFalse();
        await Assert.That(request.RequestUri).IsNull();
    }

    [Test]
    [Arguments("https://native.test/base")]
    [Arguments("https://native.test?scope=other")]
    [Arguments("https://native.test#fragment")]
    [Arguments("https://user@native.test")]
    [Arguments("https://native.test/base/..")]
    [Arguments("relative")]
    public async Task OnlyAnUnambiguousRootOriginCanBind(string origin)
    {
        var intent = new InfisicalNativeRequestIntent(HttpMethod.Get, Path);
        using var request = new HttpRequestMessage(HttpMethod.Get, Path);

        await Assert.That(intent.TryBind(request, new Uri(origin, UriKind.RelativeOrAbsolute))).IsFalse();
    }

    [Test]
    [Arguments("method")]
    [Arguments("origin")]
    [Arguments("path")]
    [Arguments("query")]
    [Arguments("userinfo")]
    [Arguments("fragment")]
    [Arguments("traversal")]
    [Arguments("escaped-separator")]
    public async Task MalformedRotationConstructionFailsBeforeCredentialsAndDisposesContent(string fault)
    {
        const string id = "f09e9561-8ad3-48a0-96fb-35472f72e564";
        string path = "/api/v2/secret-rotations/postgres-credentials/" + id + "/rotate-secrets";
        string destination = fault switch
        {
            "origin" => "https://other.test" + path,
            "path" => path + "/other",
            "query" => path + "?projectId=selected&%70rojectId=selected",
            "userinfo" => "https://user@native.test" + path,
            "fragment" => path + "#fragment",
            "traversal" => "/api/v2/secret-rotations/discard/../postgres-credentials/" + id + "/rotate-secrets",
            "escaped-separator" => path.Replace("/postgres-credentials/", "/postgres-credentials%2F", StringComparison.Ordinal),
            _ => path
        };
        var tokens = new ObservedTokens();
        using var wire = new ObservedWire();
        var authority = new SecretAuthority();
        using var client = new InfisicalRotationClient(Origin, authority,
            new(authority, tokens, "selected"),
            new() { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var address = new InfisicalRotationAddress("selected", "prod", "/",
            InfisicalRotationProfile.PostgresCredentials, id);
        var target = new SecretReference(authority, address);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        var content = new DisposalContent();

        SecretOutcome<System.Text.Json.JsonDocument> result = await client.SendConstructedAsync(address,
            _ => Task.FromResult(new HttpRequestMessage(fault == "method" ? HttpMethod.Get : HttpMethod.Post,
                destination)
            { Content = content }), target, InfisicalRotationAction.RotateSecrets,
            receipt, CancellationToken.None);
        if (result.IsSuccess) result.Value.Dispose();

        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Sent).IsFalse();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.NotDispatched);
        await Assert.That(content.Disposed).IsTrue();
    }

    [Test]
    [Arguments("method")]
    [Arguments("origin")]
    [Arguments("port")]
    [Arguments("path")]
    [Arguments("query")]
    [Arguments("fragment")]
    [Arguments("traversal")]
    [Arguments("escaped-separator")]
    public async Task MalformedDynamicConstructionFailsBeforeCredentialsAndDisposesContent(string fault)
    {
        string destination = fault switch
        {
            "origin" => "https://other.test" + Path,
            "port" => "https://native.test:8443" + Path,
            "path" => Path + "/other",
            "query" => Path + "?projectSlug=selected&%70rojectSlug=selected",
            "fragment" => Path + "#fragment",
            "traversal" => "/api/v1/discard/../dynamic-secrets",
            "escaped-separator" => "/api/v1%2Fdynamic-secrets",
            _ => Path
        };
        var tokens = new ObservedTokens();
        using var wire = new ObservedWire();
        await using var client = new InfisicalDynamicClient(Origin, tokens,
            new("selected", "prod", "/", Guid.NewGuid()),
            new() { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var receipt = new InfisicalDynamicMutationReceipt(client.Definition("selected"),
            InfisicalDynamicOperation.CreateDefinition);
        HttpContent? ownedContent = null;

        SecretOutcome<System.Text.Json.JsonDocument> result = await client.SendAsync(
            new(HttpMethod.Post, Path),
            (content, _, _) =>
            {
                ownedContent = content;
                return Task.FromResult(new HttpRequestMessage(fault == "method" ? HttpMethod.Get : HttpMethod.Post,
                    destination)
                { Content = content });
            }, _ => [123, 125], receipt, CancellationToken.None);
        if (result.IsSuccess) result.Value.Dispose();

        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Sent).IsFalse();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(async () => await ownedContent!.ReadAsByteArrayAsync()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task EscapedDynamicNamesPreserveDefinitionAndLeaseRouting()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        using var profile = new SecretKit.Infisical.Dynamic.NativeSqlDefinitionProfile(
            SecretKit.Infisical.Dynamic.NativeSqlEngine.Postgres, "database.test", 5432,
            DynamicWireFixture.Material(), DynamicWireFixture.Material(), "database", "CREATE {{username}}", "DROP {{username}}");
        InfisicalDynamicTarget target = client.Definition("caf\u00e9 /?#%2F");
        InfisicalDynamicDefinition definition = (await client.CreateDefinitionAsync(target, profile,
            new(TimeSpan.FromSeconds(60)), new(TimeSpan.FromSeconds(120)),
            new(target, InfisicalDynamicOperation.CreateDefinition))).Value;

        await Assert.That((await client.InspectDefinitionAsync(target)).Value.Id).IsEqualTo(definition.Id);
        await Assert.That((await client.ListDefinitionsAsync()).Value.Items.Single().Id).IsEqualTo(definition.Id);
        definition = (await client.UpdateDefinitionPolicyAsync(definition, new(TimeSpan.FromSeconds(60)),
            new(TimeSpan.FromSeconds(120)), new(target, InfisicalDynamicOperation.UpdateDefinition))).Value;
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        await Assert.That((await client.ListLeasesAsync(definition)).Value.Items.Single().Reference.Id)
            .IsEqualTo(lease.Reference.Id);
        await Assert.That((await client.InspectLeaseAsync(lease.Reference)).Value.Reference.Id).IsEqualTo(lease.Reference.Id);
        await Assert.That((await client.RenewAsync(lease, new(lease.Reference, InfisicalDynamicOperation.Renew))).IsSuccess)
            .IsTrue();
        await Assert.That((await client.RevokeAsync(lease, new(lease.Reference, InfisicalDynamicOperation.Revoke))).IsSuccess)
            .IsTrue();
        await Assert.That((await client.DeleteDefinitionAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.DeleteDefinition))).IsSuccess).IsTrue();
        await Assert.That(wire.DefinitionCount).IsEqualTo(0);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
    }

    private sealed class ObservedTokens : IInfisicalTokenSource
    {
        internal bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("synthetic-token"))));
        }
    }

    private sealed class ObservedWire : HttpMessageHandler
    {
        internal bool Sent { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });
        }
    }

    private sealed class DisposalContent : HttpContent
    {
        internal bool Disposed { get; private set; }
        protected override bool TryComputeLength(out long length) { length = 0; return true; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => Task.CompletedTask;
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
