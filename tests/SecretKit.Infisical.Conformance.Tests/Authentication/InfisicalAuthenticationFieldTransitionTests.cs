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

public sealed class InfisicalAuthenticationFieldTransitionTests
{
    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Admin = "00000000-0000-0000-0000-000000000002";
    private const string Observer = "00000000-0000-0000-0000-000000000003";
    private const string Runtime = "00000000-0000-0000-0000-000000000004";
    private const string Date = "2026-10-12T00:00:00.000Z";

    [Test]
    [Arguments("IdentityAuthenticationOperations.UpdateUniversalAuth", "UniversalAuthConfigurationInput.lockoutThreshold.value", "lockoutThreshold")]
    [Arguments("IdentityAuthenticationOperations.UpdateUniversalAuth", "UniversalAuthConfigurationInput.lockoutDurationSeconds.value", "lockoutDurationSeconds")]
    [Arguments("IdentityAuthenticationOperations.UpdateUniversalAuth", "UniversalAuthConfigurationInput.lockoutCounterResetSeconds.value", "lockoutCounterResetSeconds")]
    [Arguments("IdentityAuthenticationOperations.UpdateUniversalAuth", "UniversalAuthConfigurationInput.lockoutEnabled.true", "lockoutEnabled")]
    [Arguments("IdentityAuthenticationOperations.UpdateUniversalAuth", "UniversalAuthConfigurationInput.lockoutEnabled.false", "lockoutEnabled")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateLdapAuth", "LdapAuthSettings.lockoutThreshold.value", "lockoutThreshold")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateLdapAuth", "LdapAuthSettings.lockoutDurationSeconds.value", "lockoutDurationSeconds")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateLdapAuth", "LdapAuthSettings.lockoutCounterResetSeconds.value", "lockoutCounterResetSeconds")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateLdapAuth", "LdapAuthSettings.lockoutEnabled.true", "lockoutEnabled")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateLdapAuth", "LdapAuthSettings.lockoutEnabled.false", "lockoutEnabled")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateLdapAuth", "LdapAuthSettings.searchFilter.value", "searchFilter")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateOciAuth", "OciAuthConfigurationInput.allowedUsernames.value", "allowedUsernames")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateAwsAuth", "AwsAuthConfigurationInput.allowedPrincipalArns.value", "allowedPrincipalArns")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateAwsAuth", "AwsAuthConfigurationInput.allowedAccountIds.value", "allowedAccountIds")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateAwsAuth", "AwsAuthConfigurationInput.stsEndpoint.value", "stsEndpoint")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateAzureAuth", "AzureAuthConfigurationInput.tenantId.value", "tenantId")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateAzureAuth", "AzureAuthConfigurationInput.resource.value", "resource")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateAzureAuth", "AzureAuthConfigurationInput.allowedServicePrincipalIds.value", "allowedServicePrincipalIds")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateGcpAuth", "GcpAuthConfigurationInput.allowedServiceAccounts.value", "allowedServiceAccounts")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateGcpAuth", "GcpAuthConfigurationInput.allowedProjects.value", "allowedProjects")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateGcpAuth", "GcpAuthConfigurationInput.allowedZones.value", "allowedZones")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateGcpAuth", "GcpAuthConfigurationInput.type.Iam", "type")]
    [Arguments("CloudIdentityAuthenticationOperations.UpdateGcpAuth", "GcpAuthConfigurationInput.type.Gce", "type")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "JwtAuthConfigurationInput.jwksUrl.value", "jwksUrl")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "JwtAuthConfigurationInput.jwksCaCert.value", "jwksCaCert")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "JwtAuthConfigurationInput.boundIssuer.value", "boundIssuer")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "JwtAuthConfigurationInput.boundAudiences.value", "boundAudiences")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "JwtAuthConfigurationInput.boundSubject.value", "boundSubject")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "JwtAuthConfigurationInput.publicKeys.value", "publicKeys")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "publicKeys.multiple", "publicKeys")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "configurationType.Static", "configurationType")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "configurationType.Jwks", "configurationType")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateOidcAuth", "OidcAuthConfigurationInput.oidcDiscoveryUrl.value", "oidcDiscoveryUrl")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateOidcAuth", "OidcAuthConfigurationInput.boundIssuer.value", "boundIssuer")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateOidcAuth", "OidcAuthConfigurationInput.boundAudiences.value", "boundAudiences")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateOidcAuth", "OidcAuthConfigurationInput.boundSubject.value", "boundSubject")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateOidcAuth", "OidcAuthConfigurationInput.caCert.value", "caCert")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.allowedNames.value", "allowedNames")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.allowedNamespaces.value", "allowedNamespaces")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.allowedAudience.value", "allowedAudience")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.caCert.value", "caCert")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.kubernetesHost.value", "kubernetesHost")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.gatewayId.value", "gatewayId")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.gatewayPoolId.value", "gatewayPoolId")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.tokenReviewMode.Api", "tokenReviewMode")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.tokenReviewMode.Gateway", "tokenReviewMode")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.verifyTlsCertificate.true", "verifyTlsCertificate")]
    [Arguments("WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "KubernetesAuthConfigurationInput.verifyTlsCertificate.false", "verifyTlsCertificate")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "SpiffeAuthConfigurationInput.trustDomain.value", "trustDomain")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "SpiffeAuthConfigurationInput.allowedSpiffeIds.value", "allowedSpiffeIds")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "SpiffeAuthConfigurationInput.allowedAudiences.value", "allowedAudiences")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "SpiffeAuthConfigurationInput.trustBundleDistribution.value", "trustBundleDistribution.bundle")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "bundle.static", "trustBundleDistribution.profile")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "bundle.https_web_bundle", "trustBundleDistribution.profile")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "bundle.caCert.value", "trustBundleDistribution.caCert")]
    [Arguments("ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "refreshHintSeconds.value", "trustBundleDistribution.refreshHintSeconds")]
    public async Task SelectedFieldContrastsRejectNoOpsAndPreserveDeniedBaselines(string operation, string variant, string field)
    {
        foreach (string caseName in new[] { "selected-contract", "independent-effect", "lost-response-no-replay",
            "denied-authority", "cancellation-boundary" })
            foreach (string mode in new[] { "good", "ignore-selected" })
            {
                bool applied = caseName is not ("denied-authority" or "cancellation-boundary");
                await using var backend = new Backend(mode, field, authenticationTransition: !field.StartsWith("lockout",
                    StringComparison.Ordinal) && !field.EndsWith("refreshHintSeconds", StringComparison.Ordinal));
                using NativeEnvironment environment = Environment(backend.Origin, TransitionScope(variant));
                NativeCaseResult result = await RunAsync(environment, Definition(operation, variant, caseName));
                bool expected = mode == "good" || !applied;
                if (result.Passed != expected) throw new InvalidOperationException(
                    operation + "|" + variant + "|" + caseName + "|" + mode + ":" + result.ReasonCode);
                await Assert.That(backend.AdministrativeConfigurations).IsEqualTo(applied ? 1 : 0);
                await Assert.That(backend.IdentityCount).IsEqualTo(0);
                await Assert.That(backend.ProjectCount).IsEqualTo(0);
            }
    }

    [Test]
    [Arguments("missing-baseline")]
    [Arguments("same-baseline")]
    [Arguments("missing-proof")]
    [Arguments("indistinguishable-proof")]
    public async Task InvalidTransitionWitnessCannotAdmit(string mode)
    {
        const string variant = "AwsAuthConfigurationInput.allowedPrincipalArns.value";
        JsonObject scope = TransitionScope(variant);
        JsonObject issuer = scope["issuers"]!["aws"]!.AsObject();
        if (mode == "missing-baseline") issuer.Remove("baselineParameters");
        if (mode == "same-baseline")
            issuer["baselineParameters"]!["allowedPrincipalArns"] = issuer["configuration"]!["allowedPrincipalArns"]!.DeepClone();
        if (mode == "missing-proof") issuer.Remove("baselineAllowed");
        if (mode == "indistinguishable-proof") issuer["baselineAllowed"] = issuer["allowed"]!.DeepClone();
        await using var backend = new Backend("good", "allowedPrincipalArns", authenticationTransition: true);
        using NativeEnvironment environment = Environment(backend.Origin, scope);
        NativeCaseResult result = await RunAsync(environment, Definition("CloudIdentityAuthenticationOperations.UpdateAwsAuth",
            variant, "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.AdministrativeConfigurations).IsEqualTo(0);
    }

    [Test]
    public async Task UpdatedMetadataWithoutAuthenticationTransitionCannotAdmit()
    {
        await using var backend = new Backend("proof-no-op", "boundIssuer", authenticationTransition: true);
        using NativeEnvironment environment = Environment(backend.Origin, TransitionScope("JwtAuthConfigurationInput.boundIssuer.value"));
        NativeCaseResult result = await RunAsync(environment, Definition("WorkloadIdentityAuthenticationOperations.UpdateJwtAuth",
            "JwtAuthConfigurationInput.boundIssuer.value", "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.AdministrativeConfigurations).IsEqualTo(1);
    }

    [Test]
    [Arguments("AttachTokenAuth")]
    [Arguments("UpdateTokenAuth")]
    [Arguments("AttachUniversalAuth")]
    [Arguments("UpdateUniversalAuth")]
    public async Task IssuedTokenPolicyMustFollowTheObservedConfiguration(string operation)
    {
        foreach (string mode in new[] { "good", "issued-policy-no-op", "login-lifetime-no-op" })
        {
            await using var backend = new Backend(mode);
            using NativeEnvironment environment = Environment(backend.Origin, Scope());
            NativeCaseResult result = await RunAsync(environment, Definition("IdentityAuthenticationOperations." + operation,
                "response.known-fields", "independent-effect"));
            await Assert.That(result.Passed).IsEqualTo(mode == "good");
            await Assert.That(backend.AdministrativeConfigurations).IsEqualTo(1);
        }
    }

    private static JsonObject TransitionScope(string variant)
    {
        JsonObject scope = Scope(issuers: true);
        foreach (var entry in scope["issuers"]!.AsObject())
        {
            JsonObject issuer = entry.Value!.AsObject();
            issuer["baselineParameters"] = new JsonObject
            {
                ["allowedPrincipalArns"] = "baseline-principal",
                ["allowedAccountIds"] = "baseline-account",
                ["stsEndpoint"] = "https://baseline.invalid/sts",
                ["tenantId"] = "baseline-tenant",
                ["resource"] = "baseline-resource",
                ["allowedServicePrincipalIds"] = "baseline-principal",
                ["allowedServiceAccounts"] = "baseline-service",
                ["allowedProjects"] = "baseline-project",
                ["allowedZones"] = "baseline-zone",
                ["type"] = variant.EndsWith(".Iam", StringComparison.Ordinal) ? "gce" : "iam",
                ["jwksUrl"] = "https://baseline.invalid/jwks",
                ["jwksCaCert"] = "baseline-ca",
                ["boundIssuer"] = "baseline-issuer",
                ["boundAudiences"] = "baseline-audiences",
                ["boundSubject"] = "baseline-subject",
                ["publicKey"] = "baseline-public-key",
                ["configurationType"] = variant.EndsWith(".Static", StringComparison.Ordinal) ? "jwks" : "static",
                ["oidcDiscoveryUrl"] = "https://baseline.invalid/discovery",
                ["caCert"] = "baseline-ca",
                ["allowedNames"] = "baseline-name",
                ["allowedNamespaces"] = "baseline-namespace",
                ["allowedAudience"] = "baseline-audience",
                ["kubernetesHost"] = "https://baseline.invalid/",
                ["gatewayId"] = Runtime,
                ["gatewayPoolId"] = Runtime,
                ["tokenReviewMode"] = variant.EndsWith(".Api", StringComparison.Ordinal) ? "gateway" : "api",
                ["verifyTlsCertificate"] = variant.EndsWith(".true", StringComparison.Ordinal) ? "false" : "true",
                ["allowedUsernames"] = "baseline-user",
                ["searchFilter"] = "(cn={{username}})",
                ["trustDomain"] = "baseline.invalid",
                ["allowedSpiffeIds"] = "spiffe://baseline.invalid/owned",
                ["allowedAudiences"] = "baseline-audience",
                ["bundle"] = "baseline-bundle",
                ["bundleProfile"] = variant == "bundle.static" ? "https_web_bundle" : "static"
            };
            JsonObject proof = issuer["allowed"]!.DeepClone().AsObject();
            foreach (string field in new[] { "jwt", "iamRequestBody", "signature", "password", "authorization" })
                proof[field] = "baseline-allowed";
            issuer["baselineAllowed"] = proof;
        }
        return scope;
    }

    private static NativeCaseDefinition Definition(string operation, string variant, string caseName) =>
        new(new("Infisical", "i.management." + operation, variant, "local", caseName),
            InfisicalIdentityAuthenticationFamilies.Bindings["i.management." + operation].Member);

    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment environment, NativeCaseDefinition definition)
    {
        var registry = new NativeCaseRegistry();
        InfisicalIdentityAuthenticationFamilies.Register(registry, environment, [definition]);
        return (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
    }

    private static NativeEnvironment Environment(Uri origin, JsonObject? scope)
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

    private static JsonObject Scope(bool issuers = false)
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
    private sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Task accepting;
        private readonly string mode;
        private readonly string selectedField;
        private readonly bool authenticationTransition;
        private JsonNode? baselineSelected;
        private readonly Dictionary<string, JsonObject> identities = [];
        private readonly Dictionary<string, JsonObject> projects = [];
        private readonly Dictionary<(string Project, string Id), JsonObject> roles = [];
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
        internal List<string> SetupNames { get; } = [];
        internal List<string> Events { get; } = [];

        internal Backend(string mode, string selectedField = "", bool authenticationTransition = false)
        {
            this.mode = mode;
            this.selectedField = selectedField;
            this.authenticationTransition = authenticationTransition;
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
                    foreach (var k in configurations.Keys.Where(k => k.Identity == selected).ToArray()) configurations.Remove(k);
                    JsonObject deleted = (JsonObject)found.DeepClone();
                    deleted.Remove("authMethods"); deleted.Remove("metadata"); deleted.Remove("activeLockoutAuthMethods");
                    return (200, Wrap("identity", deleted));
                }
                found["authMethods"] = new JsonArray(configurations.Keys.Where(k => k.Identity == selected)
                    .Select(k => (JsonNode?)JsonValue.Create(k.Strategy + "-auth")).ToArray());
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
                        return (200, Wrap("role", role));
                    }
                    JsonObject? selectedRole = path[5] == "slug" ?
                        roles.Where(r => r.Key.Project == projectId && Text(r.Value, "slug") == path[6]).Select(r => r.Value).SingleOrDefault() :
                        roles.GetValueOrDefault((projectId, path[5]));
                    if (selectedRole is null) return (404, new JsonObject());
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
                if (identity is null || !configurations.TryGetValue((identity, strategy), out JsonObject? config) ||
                    lockouts.Contains((identity, strategy))) return (403, new JsonObject());
                string accepted = authenticationTransition &&
                    (mode == "proof-no-op" || JsonNode.DeepEquals(Selected(config), baselineSelected)) ? "baseline-allowed" : "allowed";
                bool correct = strategy == "universal" ? credential is not null :
                    new[] { "jwt", "iamRequestBody", "Signature", "password" }.Any(k => body[k]?.GetValue<string>() == accepted) ||
                    body["headers"]?["authorization"]?.GetValue<string>() == accepted;
                if (!correct)
                {
                    if (config["lockoutEnabled"]?.GetValue<bool>() == true && config["lockoutThreshold"]?.GetValue<double>() == 1)
                        lockouts.Add((identity, strategy));
                    return (403, new JsonObject());
                }
                (JsonObject row, string material) = Issue(identity, strategy, config);
                return (200, new JsonObject
                {
                    ["accessToken"] = material,
                    ["tokenType"] = "Bearer",
                    ["expiresIn"] = mode == "login-lifetime-no-op" && administrativeConfigurations > 0 ? JsonValue.Create(300) :
                        config["accessTokenPeriod"]?.GetValue<double>() > 0 ? config["accessTokenPeriod"]!.DeepClone() :
                            config["accessTokenTTL"]!.DeepClone(),
                    ["accessTokenMaxTTL"] = config["accessTokenPeriod"]?.GetValue<double>() > 0 ? JsonValue.Create(0) :
                        config["accessTokenMaxTTL"]!.DeepClone()
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
                    ["expiresIn"] = mode == "login-lifetime-no-op" && administrativeConfigurations > 0 ?
                        JsonValue.Create(300) : config["accessTokenTTL"]!.DeepClone(),
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
                if (strategy is "universal" or "token" or "aws" or "azure" or "gcp" or "ldap" or "oci" or "jwt") config["accessTokenPeriod"] = 0d;
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
                baselineSelected = Selected(config)?.DeepClone();
            }
            if (!configurations.TryGetValue((selected, strategy), out JsonObject? configuration)) return (404, new JsonObject());
            if (method == "PATCH") foreach (var field in body)
            {
                if (mode == "ignore-selected" && field.Key == selectedField) continue;
                JsonNode? prior = Selected(configuration)?.DeepClone();
                configuration[field.Key] = field.Value?.DeepClone();
                string[] selectedPath = selectedField.Split('.');
                if (mode == "ignore-selected" && selectedPath.Length == 2 && field.Key == selectedPath[0])
                    configuration[field.Key]![selectedPath[1]] = prior;
            }
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
            if (mode == "issued-policy-no-op" && administrativeConfigurations > 0) row["accessTokenTTL"] = 300;
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
        private JsonNode? Selected(JsonObject configuration)
        {
            if (selectedField.Length == 0) return null;
            string[] path = selectedField.Split('.');
            return path.Length == 1 ? configuration[path[0]] : configuration[path[0]]?[path[1]];
        }
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
