using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIdentityAuthenticationFamilyTests
{
    [Test]
    public async Task RoleCleanupRejectsAReplacementIdUnderTheOwnedSlug()
    {
        await using var backend = new Backend("substituted-role");
        using NativeEnvironment environment = Environment(backend.Origin, Scope(issuers: true));
        var result = await RunAsync(environment, Definition("CloudIdentityAuthenticationOperations.GetAwsAuth", "selector.exact", "independent-effect"));
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete").Because(result.ReasonCode);
        await Assert.That(backend.ForeignRolePresent).IsTrue();
    }

    [Test]
    [Arguments("issue-ttl")]
    [Arguments("issue-max")]
    [Arguments("issue-limit")]
    [Arguments("issue-lifetime")]
    public async Task ConfigurationCannotHideIncorrectIssuedTokenPolicy(string mode)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin, Scope(issuers: true));
        var result = await RunAsync(environment, Definition("CloudIdentityAuthenticationOperations.UpdateAwsAuth",
            "WorkloadAuthTokenPolicy.accessTokenTTL.value", "independent-effect"));
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch").Because(result.ReasonCode);
        await Assert.That(backend.IdentityCount + backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("denied-revocation")]
    [Arguments("denied-replacement")]
    [Arguments("allowed-revocation")]
    public async Task ProofExchangesPreservePreexistingTokenState(string mode)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin, Scope(issuers: true));
        var result = await RunAsync(environment, Definition("CloudIdentityAuthenticationOperations.GetAwsAuth", "selector.exact", "independent-effect"));
        await Assert.That(result.ReasonCode).IsEqualTo(mode == "allowed-revocation" ?
            "effect-mismatch" : "missing-prerequisite").Because(result.ReasonCode);
        await Assert.That(backend.IdentityCount + backend.ProjectCount).IsEqualTo(0);
    }

    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Admin = "00000000-0000-0000-0000-000000000002";
    private const string Observer = "00000000-0000-0000-0000-000000000003";
    private const string Runtime = "00000000-0000-0000-0000-000000000004";
    private const string Date = "2026-10-12T00:00:00.000Z";

    [Test]
    public async Task SetupIdentityPublicFactoriesRoundTrip()
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin, Scope());
        ManagementClient client = environment.CreateManagementClient();
        using var request = IdentityOperations.CreateOrganizationIdentity(Org, "sk-auth-" + Guid.NewGuid().ToString("N"), "member");
        ManagementAuthority authority = environment.CreateManagementAuthority(client, NativeIdentityRole.Setup, Org);
        SecretOutcome<IdentitySummary> result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, request.Target), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        using var remove = IdentityOperations.DeleteOrganizationIdentity(Org, result.Value.Id);
        SecretOutcome<IdentitySummary> deleted = await client.ExecuteAsync(remove, authority,
            authority.IssueGrant(remove.OperationId, remove.Target), client.CreateReceipt(remove));
        await Assert.That(deleted.Status).IsEqualTo(SecretStatus.Success);
        ManagementClient observer = environment.CreateManagementClient();
        ManagementAuthority observerAuthority = environment.CreateManagementAuthority(observer, NativeIdentityRole.Observer, Org);
        using var read = IdentityOperations.GetOrganizationIdentity(Org, result.Value.Id);
        SecretOutcome<IdentitySummary> remaining = await observer.ExecuteAsync(read, observerAuthority,
            observerAuthority.IssueGrant(read.OperationId, read.Target));
        await Assert.That(remaining.Status).IsEqualTo(SecretStatus.Absent);
    }

    [Test]
    public async Task ExactAdmissionBindingsCannotPassWithoutInputsOrPrimaryContracts()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        NativeCaseDefinition[] expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => InfisicalIdentityAuthenticationFamilies.Owns(o.GetProperty("id").GetString()!))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        await Assert.That(expected.Length).IsEqualTo(4184);
        await Assert.That(expected.Select(d => d.Key.Operation).Distinct().Count()).IsEqualTo(68);
        await Assert.That(expected.Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(849);
        await Assert.That(expected.All(InfisicalIdentityAuthenticationFamilies.Valid)).IsTrue();
        await Assert.That(expected.Count(d => InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) is null)).IsEqualTo(3357);
        await Assert.That(expected.Count(d => InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) is not null)).IsEqualTo(827);
        await Assert.That(expected.Where(d => InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) is null)
            .Select(d => d.Key.Operation).Distinct().Count()).IsEqualTo(65);
        await Assert.That(expected.Where(d => InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) is null)
            .Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(682);
        using NativeEnvironment environment = Environment(new Uri("http://127.0.0.1:1/"), null);
        var registry = new NativeCaseRegistry();
        InfisicalIdentityAuthenticationFamilies.Register(registry, environment, expected);
        IReadOnlyList<NativeCaseResult> results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode is "missing-input" or "observer-unavailable")).IsTrue();
        await Assert.That(results.Count(r => r.ReasonCode == "observer-unavailable")).IsEqualTo(
            expected.Count(d => InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) is not null));
        Console.WriteLine($"Identity-auth ledger: {expected.Count(d => InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) is null)} implemented cases, " +
            $"{expected.Count(d => InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) is not null)} unavailable cases.");
        foreach (var group in expected.Where(d => InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) is not null)
            .GroupBy(InfisicalIdentityAuthenticationFamilies.UnavailableReason))
            Console.WriteLine($"Identity-auth unavailable: {group.Key}: {group.Count()} cases.");
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("provider")]
    [Arguments("scope")]
    public async Task BindingTamperingFailsBeforeSetup(string field)
    {
        NativeCaseDefinition good = Definition("IdentityAuthenticationOperations.CreateToken", "name.value", "selected-contract");
        NativeCaseDefinition bad = good with
        {
            Member = field == "member" ? good.Member + ".wrong" : good.Member,
            Key = good.Key with
            {
                Variant = field == "variant" ? "invented" : good.Key.Variant,
                Case = field == "case" ? "invented" : good.Key.Case,
                Provider = field == "provider" ? "wrong" : good.Key.Provider,
                Scope = field == "scope" ? "unselected" : good.Key.Scope
            }
        };
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin, new JsonObject());
        NativeCaseResult result = await RunAsync(environment, bad);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(field == "scope" ? "missing-input" : "contract-mismatch");
        await Assert.That(backend.RequestCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CloudIdentityAuthenticationOperations.AttachAwsAuth")]
    [Arguments("ExternalIdentityAuthenticationOperations.AttachOciAuth")]
    [Arguments("WorkloadIdentityAuthenticationOperations.AttachJwtAuth")]
    public async Task MissingIssuerCannotReachSetup(string operation)
    {
        await using var backend = new Backend("good");
        NativeCaseDefinition definition = Definition(operation, "response.known-fields", "independent-effect");
        using NativeEnvironment environment = Environment(backend.Origin, Scope());
        NativeCaseResult result = await RunAsync(environment, definition);
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.RequestCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task ConfigurationBoundariesObserveFreshResourcesAndNeverReplay(string caseName)
    {
        await using var backend = new Backend("good");
        NativeCaseDefinition definition = Definition("IdentityAuthenticationOperations.AttachTokenAuth", "response.known-fields", caseName);
        using NativeEnvironment environment = Environment(backend.Origin, Scope());
        NativeCaseResult result = await RunAsync(environment, definition);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(backend.AdministrativeConfigurations).IsEqualTo(caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        await Assert.That(backend.IdentityCount).IsEqualTo(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(0);
        await Assert.That(backend.SetupNames.Distinct().Count()).IsEqualTo(backend.SetupNames.Count);
    }

    [Test]
    [Arguments("drift", "effect-mismatch")]
    [Arguments("cleanup", "cleanup-incomplete")]
    [Arguments("wrong-coordinate", "contract-mismatch")]
    [Arguments("overgrant", "effect-mismatch")]
    public async Task AcknowledgementCannotHideWrongStateAccessOrCleanup(string mode, string reason)
    {
        await using var backend = new Backend(mode);
        NativeCaseDefinition definition = Definition("IdentityAuthenticationOperations.AttachTokenAuth", "response.known-fields", "independent-effect");
        using NativeEnvironment environment = Environment(backend.Origin, Scope());
        NativeCaseResult result = await RunAsync(environment, definition);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(backend.AdministrativeConfigurations).IsEqualTo(1);
    }

    [Test]
    public async Task FeasibleTypedOperationsUseIndependentStateAndIssuedConsumers()
    {
        string[] cases = ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"];
        int passed = 0;
        foreach ((string operation, IdentityAuthBinding binding) in InfisicalIdentityAuthenticationFamilies.Bindings)
        {
            string variant = binding.Variants.Contains("response.known-fields", StringComparer.Ordinal) ?
                "response.known-fields" : binding.Variants[0];
            foreach (string caseName in binding.Mutation ? cases : cases[..^1])
            {
                var definition = new NativeCaseDefinition(new("Infisical", operation, variant, "local", caseName), binding.Member);
                if (InfisicalIdentityAuthenticationFamilies.UnavailableReason(definition) is not null) continue;
                await using var backend = new Backend("good");
                await using InfisicalManagementTlsControl? tls = operation.Contains("TlsCert", StringComparison.Ordinal) ?
                    new(backend.IssueTls) : null;
                backend.TlsControl = tls;
                using NativeEnvironment environment = Environment(backend.Origin, tls is null ? Scope(issuers: true) :
                    InfisicalManagementTlsTests.Scope(tls, variant));
                NativeCaseResult result = await RunAsync(environment, definition, tls is null ? null : (_, handler) =>
                {
                    InfisicalManagementTlsTests.TrustControl(handler, tls);
                    return new(tls.Origin, handler);
                });
                if (!result.Passed) throw new InvalidOperationException(operation + "|" + variant + "|" + caseName + ":" + result.ReasonCode +
                    "; fixture-events=" + string.Join(",", backend.Events));
                await Assert.That(backend.IdentityCount).IsEqualTo(0);
                await Assert.That(backend.ProjectCount).IsEqualTo(0);
                passed++;
            }
        }
        await Assert.That(passed).IsGreaterThan(200);
    }

    [Test]
    [Arguments("TokenAuthConfigurationInput.accessTokenTTL.omitted")]
    [Arguments("TokenAuthConfigurationInput.accessTokenMaxTTL.omitted")]
    [Arguments("TokenAuthConfigurationInput.accessTokenNumUsesLimit.omitted")]
    [Arguments("tokenTTL.zero")]
    [Arguments("tokenMaxTTL.zero")]
    public async Task TokenPolicyVariantsPreserveOmissionAndNativeZero(string variant)
    {
        foreach (string method in new[] { "AttachTokenAuth", "UpdateTokenAuth" })
        {
            await using var backend = new Backend("good");
            using NativeEnvironment environment = Environment(backend.Origin, Scope());
            NativeCaseResult result = await RunAsync(environment, Definition("IdentityAuthenticationOperations." + method,
                variant, "independent-effect"));
            await Assert.That(result.Passed).IsTrue();
        }
    }

    [Test]
    public async Task ExplicitRejectedAttachmentsCannotDispatchAndHaveObservedAbsence()
    {
        int verified = 0;
        foreach ((string operation, IdentityAuthBinding binding) in InfisicalIdentityAuthenticationFamilies.Bindings)
            foreach (string variant in binding.Variants.Where(v => v.EndsWith(".rejected", StringComparison.Ordinal)))
                foreach (string caseName in new[] { "selected-contract", "denied-authority", "cancellation-boundary",
                    "independent-effect", "lost-response-no-replay" })
                {
                    await using var backend = new Backend("good");
                    using NativeEnvironment environment = Environment(backend.Origin, Scope());
                    NativeCaseResult result = await RunAsync(environment,
                        new(new("Infisical", operation, variant, "local", caseName), binding.Member));
                    await Assert.That(result.Passed).IsTrue();
                    await Assert.That(backend.AdministrativeConfigurations).IsEqualTo(0);
                    await Assert.That(backend.IdentityCount).IsEqualTo(0);
                    verified++;
                }
        await Assert.That(verified).IsEqualTo(50);
    }

    internal static NativeCaseDefinition Definition(string operation, string variant, string caseName) =>
        new(new("Infisical", "i.management." + operation, variant, "local", caseName),
            InfisicalIdentityAuthenticationFamilies.Bindings["i.management." + operation].Member);

    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment environment, NativeCaseDefinition definition,
        Func<Uri, SocketsHttpHandler, TlsCertificateProofChannel>? tlsChannel = null)
    {
        var registry = new NativeCaseRegistry();
        InfisicalIdentityAuthenticationFamilies.Register(registry, environment, [definition], tlsChannel);
        return (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
    }

    internal static NativeEnvironment Environment(Uri origin, JsonObject? scope)
    {
        var families = new JsonObject();
        if (scope is not null)
            foreach (string family in new[] { "IdentityAuthentication", "CloudIdentityAuthentication", "ExternalIdentityAuthentication",
                "WorkloadIdentityAuthentication", "OrganizationIdentityMemberships", "OrganizationMemberships" })
                families["C08-IM-" + family] = new JsonObject { ["scopes"] = new JsonObject { ["local"] = scope.DeepClone() } };
        using JsonDocument settings = JsonDocument.Parse(new JsonObject
        {
            ["origin"] = origin.ToString(),
            ["allowLoopbackDevelopmentHttp"] = true,
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = families
        }.ToJsonString());
        return NativeEnvironment.Create(settings.RootElement);
    }

    internal static JsonObject Scope(bool issuers = false)
    {
        var input = new JsonObject
        {
            ["organizationId"] = Org,
            ["administrativeIdentityId"] = Admin,
            ["observerIdentityId"] = Observer,
            ["runtimeIdentityId"] = Runtime,
            ["observerUserId"] = Observer,
            ["observerUsername"] = "observer",
            ["apiRevision"] = "AuthV1IdentitiesV1SecretsV4",
            ["organizationSlug"] = "owned",
            ["defaultTokenTTL"] = "300",
            ["defaultTokenMaxTTL"] = "1200",
            ["defaultTokenUses"] = "1000",
            ["defaultTokenPeriod"] = "0",
            ["defaultLockoutThreshold"] = "5",
            ["defaultLockoutDurationSeconds"] = "86400",
            ["defaultLockoutCounterResetSeconds"] = "3600"
        };
        if (!issuers) return input;
        var fixtures = new JsonObject();
        foreach (string strategy in new[] { "aws", "azure", "gcp", "alicloud", "jwt", "oidc", "kubernetes", "ldap", "oci", "spiffe" })
        {
            var configuration = new JsonObject
            {
                ["allowedArns"] = "owned-arn",
                ["allowedPrincipalArns"] = "owned-principal",
                ["allowedAccountIds"] = "owned-account",
                ["stsEndpoint"] = "https://issuer.invalid/",
                ["tenantId"] = "owned-tenant",
                ["resource"] = "owned-resource",
                ["allowedServicePrincipalIds"] = "owned-service",
                ["allowedServiceAccounts"] = "owned-service",
                ["allowedProjects"] = "owned-project",
                ["allowedZones"] = "owned-zone",
                ["jwksUrl"] = "https://issuer.invalid/jwks",
                ["publicKey"] = "owned-public-key",
                ["secondPublicKey"] = "second-owned-public-key",
                ["jwksCaCert"] = "owned-ca",
                ["boundIssuer"] = "owned-issuer",
                ["boundAudiences"] = "owned-audience",
                ["boundSubject"] = "owned-subject",
                ["oidcDiscoveryUrl"] = "https://issuer.invalid/discovery",
                ["caCert"] = "owned-ca",
                ["allowedNames"] = "owned-service",
                ["allowedNamespaces"] = "owned-namespace",
                ["allowedAudience"] = "owned-audience",
                ["kubernetesHost"] = "https://issuer.invalid/",
                ["gatewayId"] = Admin,
                ["gatewayPoolId"] = Observer,
                ["tenancyOcid"] = "owned-tenancy",
                ["allowedUsernames"] = "owned-user",
                ["url"] = "ldaps://issuer.invalid/",
                ["bindDN"] = "owned-bind",
                ["bindPass"] = "owned-bind-password",
                ["searchBase"] = "owned-base",
                ["searchFilter"] = "(uid={{username}})",
                ["templateId"] = Admin,
                ["trustDomain"] = "issuer.invalid",
                ["allowedSpiffeIds"] = "spiffe://issuer.invalid/owned",
                ["allowedAudiences"] = "owned-audience",
                ["bundle"] = "owned-bundle",
                ["endpointUrl"] = "https://issuer.invalid/bundle",
                ["defaultTTL"] = "300",
                ["defaultMaxTTL"] = "1200",
                ["defaultUses"] = "1000"
            };
            foreach (string field in configuration.Select(f => f.Key).ToArray())
                configuration["default-" + field] = configuration[field]!.DeepClone();
            JsonObject Proof(bool denied) => new()
            {
                ["jwt"] = denied ? "denied" : "allowed",
                ["iamRequestBody"] = denied ? "denied" : "allowed",
                ["iamRequestHeaders"] = "owned-headers",
                ["accessKeyId"] = "owned-access",
                ["signature"] = denied ? "denied" : "allowed",
                ["signatureNonce"] = "owned-nonce",
                ["timestamp"] = Date,
                ["version"] = "owned-version",
                ["username"] = "owned-user",
                ["password"] = denied ? "denied" : "allowed",
                ["userOcid"] = "owned-user",
                ["authorization"] = denied ? "denied" : "allowed",
                ["host"] = "issuer.invalid",
                ["date"] = Date
            };
            fixtures[strategy] = new JsonObject { ["configuration"] = configuration, ["allowed"] = Proof(false), ["denied"] = Proof(true) };
        }
        input["issuers"] = fixtures;
        return input;
    }

    // A local stateful HTTP authority is offline characterization, never an issuer
    // fixture or evidence about a live provider. Values never leave loopback.
    internal sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Task accepting;
        private readonly string mode;
        private readonly Dictionary<string, JsonObject> identities = [];
        private readonly Dictionary<string, JsonObject> projects = [];
        private readonly Dictionary<(string Project, string Id), JsonObject> roles = [];
        private const string ForeignRoleId = "00000000-0000-0000-0000-000000000099";
        internal bool ForeignRolePresent { get { lock (identities) return roles.Keys.Any(k => k.Id == ForeignRoleId); } }
        private readonly Dictionary<(string Identity, string Strategy), JsonObject> configurations = [];
        private readonly Dictionary<string, JsonObject> credentials = [];
        private readonly Dictionary<string, JsonObject> tokens = [];
        private readonly Dictionary<string, string> materials = [];
        private readonly Dictionary<(string Project, string Principal), string> members = [];
        private readonly Dictionary<(string Project, string Key), string> secrets = [];
        private readonly HashSet<(string Identity, string Strategy)> lockouts = [];
        private int requests, administrativeConfigurations;
        internal Uri Origin { get; }
        internal int RequestCount => requests;
        internal int AdministrativeConfigurations => administrativeConfigurations;
        internal int IdentityCount => identities.Count;
        internal int ProjectCount => projects.Count;
        internal int TlsTokenCount => tokens.Values.Count(t => Text(t, "authMethod") == "tls-cert-auth");
        internal List<string> SetupNames { get; } = [];
        internal List<string> Events { get; } = [];
        internal InfisicalManagementTlsControl? TlsControl { get; set; }

        internal JsonObject IssueTls(string identity, JsonObject configuration)
            => IssueProofToken(identity, "tls-cert", configuration);

        internal JsonObject IssueProofToken(string identity, string strategy, JsonObject configuration)
        {
            lock (identities)
            {
                (JsonObject _, string material) = Issue(identity, strategy, configuration);
                return new JsonObject
                {
                    ["accessToken"] = material,
                    ["tokenType"] = "Bearer",
                    ["expiresIn"] = configuration["accessTokenTTL"]!.DeepClone(),
                    ["accessTokenMaxTTL"] = configuration["accessTokenMaxTTL"]!.DeepClone()
                };
            }
        }

        internal void RetireProofTokens(IEnumerable<string> captured)
        {
            lock (identities)
                foreach (string material in captured)
                    if (materials.Remove(material, out string? id)) tokens.Remove(id);
        }

        internal Backend(string mode)
        {
            this.mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accepting = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                {
                    TcpClient client = await listener.AcceptTcpClientAsync(shutdown.Token);
                    connections.Add(HandleAsync(client));
                }
            }
            catch (OperationCanceledException) { }
        }

        private async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    using NetworkStream stream = client.GetStream();
                    using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                    string? first = await reader.ReadLineAsync(shutdown.Token);
                    if (first is null) return;
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    string? line;
                    while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(shutdown.Token)))
                    {
                        int split = line.IndexOf(':');
                        headers[line[..split]] = line[(split + 1)..].Trim();
                    }
                    int length = headers.TryGetValue("Content-Length", out string? value) ? int.Parse(value) : 0;
                    char[] buffer = new char[length];
                    if (length > 0) await reader.ReadBlockAsync(buffer, shutdown.Token);
                    var body = length == 0 ? new JsonObject() : JsonNode.Parse(new string(buffer))!.AsObject();
                    Array.Clear(buffer);
                    string[] request = first.Split(' ');
                    string bearer = headers.GetValueOrDefault("Authorization", "").Replace("Bearer ", "", StringComparison.Ordinal);
                    (int status, JsonNode response) result;
                    lock (identities)
                    {
                        requests++;
                        result = Respond(request[0], new(Origin, request[1]), body, bearer);
                        string[] path = new Uri(Origin, request[1]).AbsolutePath.Trim('/').Split('/');
                        Events.Add(request[0] + ":" + path[2] + ":" + path.Length + ":" + result.status);
                    }
                    byte[] bytes = Encoding.UTF8.GetBytes(result.response.ToJsonString());
                    byte[] head = Encoding.ASCII.GetBytes($"HTTP/1.1 {result.status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(head, shutdown.Token);
                    await stream.WriteAsync(bytes, shutdown.Token);
                }
                catch (Exception error) when (error is OperationCanceledException or IOException or SocketException) { }
            }
        }

        private (int, JsonNode) Respond(string method, Uri uri, JsonObject body, string bearer)
        {
            string[] path = uri.AbsolutePath.Trim('/').Split('/');
            string query(string name) => uri.Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2))
                .Where(p => p[0] == name).Select(p => Uri.UnescapeDataString(p[1])).FirstOrDefault() ?? "";
            if (bearer == "denied") return (403, new JsonObject());
            if (path.Length >= 4 && path[2] == "auth") return Authentication(method, path, body, bearer);
            if (path[2] == "identities")
            {
                if (path.Length == 3 && method == "GET")
                    return (200, new JsonObject
                    {
                        ["identities"] = new JsonArray(identities.Values.Select(IdentityMembership).ToArray()),
                        ["totalCount"] = identities.Count
                    });
                if (method == "POST")
                {
                    string id = Guid.NewGuid().ToString();
                    JsonObject identity = Base(id);
                    identity["orgId"] = Org; identity["name"] = body["name"]!.DeepClone();
                    identity["hasDeleteProtection"] = false; identity["authMethods"] = new JsonArray();
                    identity["activeLockoutAuthMethods"] = new JsonArray(); identity["metadata"] = new JsonArray();
                    identities[id] = identity;
                    SetupNames.Add(Text(identity, "name"));
                    JsonObject created = (JsonObject)identity.DeepClone();
                    created.Remove("activeLockoutAuthMethods");
                    return (200, Wrap("identity", created));
                }
                string selected = path[^1];
                if (!identities.TryGetValue(selected, out JsonObject? found)) return (404, new JsonObject());
                if (method == "DELETE")
                {
                    if (mode == "cleanup") return (500, new JsonObject());
                    identities.Remove(selected);
                    TlsControl?.DeleteOwner(selected);
                    foreach (string tokenId in tokens.Where(t => Text(t.Value, "identityId") == selected &&
                        Text(t.Value, "authMethod") == "tls-cert-auth").Select(t => t.Key).ToArray())
                    {
                        tokens.Remove(tokenId);
                        foreach (string material in materials.Where(m => m.Value == tokenId).Select(m => m.Key).ToArray())
                            materials.Remove(material);
                    }
                    foreach (var k in configurations.Keys.Where(k => k.Identity == selected).ToArray()) configurations.Remove(k);
                    JsonObject deleted = (JsonObject)found.DeepClone();
                    deleted.Remove("authMethods"); deleted.Remove("metadata"); deleted.Remove("activeLockoutAuthMethods");
                    return (200, Wrap("identity", deleted));
                }
                found["authMethods"] = new JsonArray(configurations.Keys.Where(k => k.Identity == selected)
                    .Select(k => (JsonNode?)JsonValue.Create(k.Strategy + "-auth")).ToArray());
                if (TlsControl?.Contains(selected) == true)
                    found["authMethods"]!.AsArray().Add("tls-cert-auth");
                found["activeLockoutAuthMethods"] = new JsonArray(lockouts.Where(k => k.Identity == selected)
                    .Select(k => (JsonNode?)JsonValue.Create(k.Strategy + "-auth")).ToArray());
                return (200, new JsonObject { ["identity"] = IdentityMembership(found, detailed: true) });
            }
            if (path[2] == "organizations")
            {
                if (path[^1] == "identity-memberships")
                {
                    JsonObject[] rows = identities.Values.Where(i => query("search").Length == 0 ||
                        Text(i, "name").Contains(query("search"), StringComparison.Ordinal)).Select(i =>
                    {
                        JsonObject row = Base(Guid.NewGuid().ToString());
                        row["orgId"] = Org; row["identityId"] = Text(i, "id"); row["role"] = "member";
                        row["identity"] = new JsonObject
                        {
                            ["orgId"] = Org,
                            ["id"] = Text(i, "id"),
                            ["name"] = Text(i, "name"),
                            ["authMethods"] = i["authMethods"]!.DeepClone()
                        };
                        return row;
                    }).ToArray();
                    return (200, new JsonObject { ["identityMemberships"] = new JsonArray(rows), ["totalCount"] = rows.Length });
                }
                return (200, new JsonObject
                {
                    ["users"] = new JsonArray(new JsonObject
                    {
                        ["id"] = Observer,
                        ["orgId"] = Org,
                        ["role"] = "member",
                        ["userId"] = Observer,
                        ["isActive"] = true,
                        ["user"] = new JsonObject { ["id"] = Observer, ["username"] = "observer" }
                    })
                });
            }
            if (path[2] == "projects")
            {
                if (method == "POST" && path.Length == 3)
                {
                    string id = Guid.NewGuid().ToString();
                    JsonObject project = Base(id);
                    project["_id"] = id; project["orgId"] = Org; project["name"] = body["projectName"]!.DeepClone();
                    project["slug"] = body["slug"]!.DeepClone(); project["type"] = "secret-manager"; project["hasDeleteProtection"] = false;
                    project["environments"] = new JsonArray(); project["deletedEnvironments"] = new JsonArray();
                    projects[id] = project;
                    return (200, Wrap("project", project));
                }
                string idOrSlug = path[3] == "slug" ? path[4] : path[3];
                JsonObject? found = path[3] == "slug" ? projects.Values.SingleOrDefault(p => Text(p, "slug") == idOrSlug) :
                    projects.GetValueOrDefault(idOrSlug);
                if (found is null) return (404, new JsonObject());
                string projectId = Text(found, "id");
                if (path.Length > 4 && path[4] == "roles")
                {
                    if (method == "POST")
                    {
                        JsonObject role = Base(Guid.NewGuid().ToString());
                        foreach (var f in body) role[f.Key] = f.Value?.DeepClone();
                        role["projectId"] = projectId;
                        roles[(projectId, Text(role, "id"))] = role;
                        if (mode == "substituted-role")
                        {
                            var foreign = role.DeepClone().AsObject();
                            foreign["id"] = ForeignRoleId; foreign["slug"] = "unrelated";
                            roles[(projectId, ForeignRoleId)] = foreign;
                        }
                        return (200, Wrap("role", role));
                    }
                    JsonObject? selectedRole = path[5] == "slug" ?
                        roles.Where(r => r.Key.Project == projectId && Text(r.Value, "slug") == path[6]).Select(r => r.Value).SingleOrDefault() :
                        roles.GetValueOrDefault((projectId, path[5]));
                    if (selectedRole is null) return (404, new JsonObject());
                    if (mode == "substituted-role" && path[5] == "slug")
                    {
                        if (!roles.ContainsKey((projectId, ForeignRoleId))) return (404, new JsonObject());
                        var foreign = selectedRole.DeepClone().AsObject();
                        foreign["id"] = ForeignRoleId;
                        return (200, Wrap("role", foreign));
                    }
                    if (method == "DELETE") roles.Remove((projectId, Text(selectedRole, "id")));
                    return (200, Wrap("role", selectedRole));
                }
                if (path.Length > 4 && path[4] == "memberships")
                {
                    members[(projectId, path[^1])] = body["role"]?.GetValue<string>() ??
                        body["roles"]![0]!["role"]!.GetValue<string>();
                    JsonObject member = Base(Guid.NewGuid().ToString());
                    member["identityId"] = path[^1]; member["projectId"] = projectId;
                    return (200, Wrap("identityMembership", member));
                }
                if (path.Length > 4 && path[4] == "environments")
                {
                    JsonObject env = Base(Guid.NewGuid().ToString());
                    env["projectId"] = projectId; env["name"] = body["name"]!.DeepClone(); env["slug"] = body["slug"]!.DeepClone();
                    env["position"] = 1;
                    return (200, new JsonObject { ["projectId"] = projectId, ["environment"] = env });
                }
                if (method == "DELETE")
                {
                    projects.Remove(projectId);
                    JsonObject deleted = (JsonObject)found.DeepClone();
                    deleted.Remove("_id"); deleted.Remove("environments"); deleted.Remove("deletedEnvironments");
                    return (200, Wrap("project", deleted));
                }
                return path[3] == "slug" ? (200, found.DeepClone()) : (200, Wrap("project", found));
            }
            if (path[2] == "secrets")
            {
                string project = method == "POST" ? Text(body, "projectId") : query("projectId");
                string secretKey = path[^1];
                string principal = materials.TryGetValue(bearer, out string? tokenId) ? Text(tokens[tokenId], "identityId") : "";
                bool issued = principal.Length != 0;
                bool AllowedByRole()
                {
                    if (!members.TryGetValue((project, principal), out string? role)) return false;
                    if (role is "viewer" or "admin") return true;
                    JsonObject? selectedRole = roles.Where(r => r.Key.Project == project &&
                        Text(r.Value, "slug") == role).Select(r => r.Value).SingleOrDefault();
                    return selectedRole?["permissions"]?.AsArray().Any(rule => rule?["subject"]?.GetValue<string>() == "secrets" &&
                        (rule["action"] is JsonArray actions ? actions.Any(a => a?.GetValue<string>() == "read") :
                            rule["action"]?.GetValue<string>() == "read")) == true;
                }
                bool allowed = bearer is "setup" or "observer" ||
                    issued && tokens[materials[bearer]]["isAccessTokenRevoked"]!.GetValue<bool>() == false &&
                    (AllowedByRole() || mode == "overgrant");
                if (!allowed) return (403, new JsonObject());
                if (method == "POST") secrets[(project, secretKey)] = Text(body, "secretValue");
                if (!secrets.TryGetValue((project, secretKey), out string? secret)) return (404, new JsonObject());
                return (200, new JsonObject
                {
                    ["secret"] = new JsonObject
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["secretKey"] = secretKey,
                        ["secretValue"] = secret,
                        ["secretValueHidden"] = false,
                        ["version"] = 1,
                        ["type"] = "shared",
                        ["projectId"] = project,
                        ["workspace"] = project,
                        ["environment"] = "witness",
                        ["secretPath"] = "/"
                    }
                });
            }
            return (404, new JsonObject());
        }

        private (int, JsonNode) Authentication(string method, string[] path, JsonObject body, string bearer)
        {
            string strategy = path[3][..^"-auth".Length];
            if (strategy == "tls-cert" && TlsControl is not null)
            {
                if (bearer == "administrative" && method != "GET") administrativeConfigurations++;
                return TlsControl.Configuration(method, path[^1], body, bearer);
            }
            string Envelope() => "identity" + (strategy == "tls-cert" ? "TlsCert" : strategy == "alicloud" ? "AliCloud" :
                char.ToUpperInvariant(strategy[0]) + strategy[1..]) + "Auth";
            if (path[^1] == "login")
            {
                string? identity = body["identityId"]?.GetValue<string>();
                JsonObject? credential = null;
                if (strategy == "universal")
                {
                    identity = configurations.Where(c => c.Key.Strategy == strategy &&
                        Text(c.Value, "clientId") == Text(body, "clientId")).Select(c => c.Key.Identity).SingleOrDefault();
                    credential = credentials.Values.FirstOrDefault(c => Text(c, "identity") == identity &&
                        Text(c, "material") == Text(body, "clientSecret") && !c["isClientSecretRevoked"]!.GetValue<bool>());
                }
                bool correct = strategy == "universal" ? credential is not null :
                    new[] { "jwt", "iamRequestBody", "Signature", "password" }.Any(k => body[k]?.GetValue<string>() == "allowed") ||
                    body["headers"]?["authorization"]?.GetValue<string>() == "allowed";
                if (identity is null || !configurations.TryGetValue((identity, strategy), out JsonObject? config) ||
                    lockouts.Contains((identity, strategy))) return (403, new JsonObject());
                if (!correct)
                {
                    if (mode == "denied-revocation")
                        foreach (var existing in tokens.Values.Where(t => Text(t, "identityId") == identity))
                            existing["isAccessTokenRevoked"] = true;
                    if (mode == "denied-replacement")
                    {
                        var previous = tokens.FirstOrDefault(t => Text(t.Value, "identityId") == identity);
                        if (previous.Value is not null)
                        {
                            var replacement = previous.Value.DeepClone().AsObject();
                            string replacementId = Guid.NewGuid().ToString();
                            replacement["id"] = replacementId;
                            tokens.Remove(previous.Key);
                            tokens[replacementId] = replacement;
                        }
                    }
                    if (config["lockoutEnabled"]?.GetValue<bool>() == true && config["lockoutThreshold"]?.GetValue<double>() == 1)
                        lockouts.Add((identity, strategy));
                    return (403, new JsonObject());
                }
                if (mode == "allowed-revocation")
                    foreach (var existing in tokens.Values.Where(t => Text(t, "identityId") == identity))
                        existing["isAccessTokenRevoked"] = true;
                (JsonObject row, string material) = Issue(identity, strategy, config);
                bool selectedPolicy = config["accessTokenTTL"]!.GetValue<double>() == 600;
                if (selectedPolicy && mode == "issue-ttl") row["accessTokenTTL"] = 1;
                if (selectedPolicy && mode == "issue-max") row["accessTokenMaxTTL"] = 1;
                if (selectedPolicy && mode == "issue-limit") row["accessTokenNumUsesLimit"] = 1;
                return (200, new JsonObject
                {
                    ["accessToken"] = material,
                    ["tokenType"] = "Bearer",
                    ["expiresIn"] = selectedPolicy && mode == "issue-lifetime" ? JsonValue.Create(1) : config["accessTokenTTL"]!.DeepClone(),
                    ["accessTokenMaxTTL"] = config["accessTokenMaxTTL"]!.DeepClone()
                });
            }
            if (strategy == "token" && path[4] == "tokens")
            {
                string id = path[5];
                if (!tokens.TryGetValue(id, out JsonObject? found)) return (404, new JsonObject());
                if (path[^1] == "revoke") { found["isAccessTokenRevoked"] = true; return (200, new JsonObject { ["message"] = "revoked" }); }
                if (method == "PATCH" && body["name"] is not null) found["name"] = body["name"]!.DeepClone();
                return (200, Wrap("token", found));
            }
            string selected = path[5];
            if (path.Length > 6 && path[6] == "clear-lockouts")
            {
                bool deleted = lockouts.Remove((selected, strategy));
                return (200, new JsonObject { ["deleted"] = deleted ? 1 : 0 });
            }
            if (path.Length > 6 && path[6] == "tokens")
            {
                if (method == "GET") return (200, new JsonObject
                { ["tokens"] = new JsonArray(tokens.Values.Where(t => Text(t, "identityId") == selected).Select(t => t.DeepClone()).ToArray()) });
                if (!configurations.TryGetValue((selected, strategy), out JsonObject? config)) return (403, new JsonObject());
                (JsonObject row, string material) = Issue(selected, strategy, config);
                row["name"] = body["name"]?.DeepClone();
                return (200, new JsonObject
                {
                    ["tokenData"] = row.DeepClone(),
                    ["accessToken"] = material,
                    ["tokenType"] = "Bearer",
                    ["expiresIn"] = config["accessTokenTTL"]!.DeepClone(),
                    ["accessTokenMaxTTL"] = config["accessTokenMaxTTL"]!.DeepClone()
                });
            }
            if (path.Length > 6 && path[6] == "client-secrets")
            {
                if (path.Length == 7 && method == "GET") return (200, new JsonObject
                { ["clientSecretData"] = new JsonArray(credentials.Values.Where(c => Text(c, "identity") == selected).Select(Credential).ToArray()) });
                if (path.Length == 7)
                {
                    if (!configurations.TryGetValue((selected, strategy), out JsonObject? config)) return (403, new JsonObject());
                    string id = Guid.NewGuid().ToString();
                    JsonObject credential = Base(id);
                    credential["identity"] = selected; credential["material"] = Guid.NewGuid().ToString("N");
                    credential["identityUAId"] = Text(config, "id"); credential["description"] = body["description"]?.DeepClone() ?? JsonValue.Create("");
                    credential["clientSecretPrefix"] = "fixture"; credential["clientSecretNumUses"] = 0;
                    credential["clientSecretNumUsesLimit"] = body["numUsesLimit"]?.DeepClone() ?? JsonValue.Create(1000);
                    credential["clientSecretTTL"] = body["ttl"]?.DeepClone() ?? JsonValue.Create(3600);
                    credential["isClientSecretRevoked"] = false;
                    credentials[id] = credential;
                    return (200, new JsonObject { ["clientSecretData"] = Credential(credential), ["clientSecret"] = Text(credential, "material") });
                }
                if (!credentials.TryGetValue(path[7], out JsonObject? existing)) return (404, new JsonObject());
                if (path[^1] == "revoke") existing["isClientSecretRevoked"] = true;
                return (200, new JsonObject { ["clientSecretData"] = Credential(existing) });
            }
            if (method == "POST")
            {
                JsonObject config = Base(Guid.NewGuid().ToString());
                config["identityId"] = selected; config["accessTokenTTL"] = 300; config["accessTokenMaxTTL"] = 1200;
                config["accessTokenNumUsesLimit"] = 1000;
                if (strategy is "universal" or "token" or "aws" or "azure" or "gcp" or "ldap" or "oci" or "jwt") config["accessTokenPeriod"] = 0;
                if (strategy == "universal")
                {
                    config["clientId"] = Guid.NewGuid().ToString("N"); config["lockoutEnabled"] = false;
                    config["lockoutThreshold"] = 5; config["lockoutDurationSeconds"] = 86400; config["lockoutCounterResetSeconds"] = 3600;
                }
                if (strategy is "aws" or "gcp" or "alicloud" or "oci") config["type"] = strategy == "gcp" ? "iam" : strategy;
                if (strategy == "jwt") config["publicKeys"] = new JsonArray();
                foreach (var field in body) config[field.Key] = field.Value?.DeepClone();
                if (strategy == "ldap") config.Remove("bindPass");
                configurations[(selected, strategy)] = config;
            }
            if (!configurations.TryGetValue((selected, strategy), out JsonObject? configuration)) return (404, new JsonObject());
            if (method == "PATCH") foreach (var field in body) configuration[field.Key] = field.Value?.DeepClone();
            if (bearer == "administrative" && method != "GET") administrativeConfigurations++;
            JsonObject response = (JsonObject)configuration.DeepClone();
            if (strategy == "ldap" && method != "GET") { response.Remove("bindDN"); response.Remove("ldapCaCertificate"); }
            if (strategy == "ldap" && method == "GET") response["bindDN"] = "owned-bind";
            if (mode == "wrong-coordinate" && bearer == "administrative") response["identityId"] = Admin;
            if (mode == "drift" && bearer == "observer") response["accessTokenTTL"] = 999;
            if (method == "DELETE")
            {
                configurations.Remove((selected, strategy));
                if (strategy is "jwt" or "oidc" or "kubernetes")
                    foreach (string field in new[] { "caCert", "jwksCaCert", "publicKeys", "tokenReviewerJwt" }) response.Remove(field);
            }
            return (200, new JsonObject { [Envelope()] = response });
        }

        private (JsonObject, string) Issue(string identity, string strategy, JsonObject config)
        {
            string id = Guid.NewGuid().ToString(), material = "issued-" + Guid.NewGuid().ToString("N");
            JsonObject row = Base(id);
            row["identityId"] = identity; row["authMethod"] = strategy + "-auth"; row["isAccessTokenRevoked"] = false;
            foreach (string field in new[] { "accessTokenTTL", "accessTokenMaxTTL", "accessTokenNumUsesLimit", "accessTokenPeriod" })
                if (config[field] is not null) row[field] = config[field]!.DeepClone();
            row["accessTokenNumUses"] = 0;
            tokens[id] = row; materials[material] = id;
            return (row, material);
        }

        private static JsonNode Credential(JsonObject credential)
        {
            JsonObject copy = (JsonObject)credential.DeepClone();
            copy.Remove("identity"); copy.Remove("material");
            return copy;
        }
        private static JsonNode IdentityMembership(JsonObject identity) => IdentityMembership(identity, false);
        private static JsonNode IdentityMembership(JsonObject identity, bool detailed)
        {
            JsonObject row = Base(Text(identity, "id"));
            row["identityId"] = Text(identity, "id"); row["orgId"] = Org; row["role"] = "member";
            var nested = new JsonObject
            {
                ["id"] = Text(identity, "id"),
                ["name"] = Text(identity, "name"),
                ["authMethods"] = identity["authMethods"]!.DeepClone(),
                ["hasDeleteProtection"] = false
            };
            if (detailed)
            {
                nested["orgId"] = Org;
                nested["activeLockoutAuthMethods"] = identity["activeLockoutAuthMethods"]!.DeepClone();
                row["metadata"] = new JsonArray();
            }
            row["identity"] = nested;
            return row;
        }
        private static JsonObject Base(string id) => new() { ["id"] = id, ["createdAt"] = Date, ["updatedAt"] = Date };
        private static string Text(JsonObject value, string field) => value[field]!.GetValue<string>();
        private static JsonObject Wrap(string name, JsonObject value) => new() { [name] = value.DeepClone() };
        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            try { await accepting; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }
    }
}
