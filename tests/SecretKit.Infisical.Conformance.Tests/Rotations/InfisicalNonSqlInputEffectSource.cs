using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// The HTTP source API is open/arm/complete/observe/close. Private profiles are
// expectations only: committed state and original validation come from the wire.
internal sealed class InfisicalNonSqlInputEffectSource(InfisicalNonSqlInputEffectFixture fixture) : HttpMessageHandler
{
    private NonSqlInputRootAttempt? root;
    private NonSqlInputBinding? binding;
    private NonSqlInputArm? pending;
    private NonSqlInputFence? fence;
    private JsonObject? packet;
    private JsonObject? baseline;
    private JsonObject? selected;
    private bool registered;
    internal int Opens { get; private set; }
    internal int Observations { get; private set; }
    internal int Closes { get; private set; }
    internal int Registrations => (registered ? 1 : 0) + (pending is null ? 0 : 1);
    internal bool PrivateCopiesDestroyed => packet is null && baseline is null && selected is null;

    internal InfisicalNonSqlInputObserver CreateObserver() => new(
        new(new(new("https://controlled.invalid/private/"), "controlled-source-token", "nonsql-source", 30), this),
        "nonsql-source", NonSqlInputSource.ControlledFixture);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
        JsonObject command;
        try { command = JsonNode.Parse(bytes)!.AsObject(); } finally { Array.Clear(bytes); }
        object facts = request.RequestUri!.Segments.Last() switch
        {
            "open" => Open(command),
            "arm" => Arm(command),
            "complete" => Complete(command),
            "observe" => Observe(command),
            "close" => Close(command),
            _ => throw new InvalidOperationException("controlled-source-command")
        };
        string nonce = command["nonce"]!.GetValue<string>();
        command.Clear();
        return new(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                schemaVersion = 1,
                nonce,
                observerIdentity = "nonsql-source",
                observedAt = DateTimeOffset.UtcNow,
                facts
            }, options: InfisicalNonSqlInputEffectTests.Options)
        };
    }

    private NonSqlInputBinding Open(JsonObject command)
    {
        root = command["attempt"]!.Deserialize<NonSqlInputRootAttempt>(InfisicalNonSqlInputEffectTests.Options)!;
        packet = command["profiles"]!.DeepClone().AsObject();
        baseline = MapPacket(packet["baseline"]!.AsObject());
        selected = MapPacket(packet["selected"]!.AsObject());
        bool absent = !registered && fixture.DefinitionCount == 0;
        registered = true;
        long sequence = fixture.Tick();
        binding = new(root, Guid.NewGuid().ToString(), "nonsql-source",
            "provider-application-clock", "controlled-epoch", fixture.Now, sequence, registered, absent,
            !JsonNode.DeepEquals(baseline, selected), true, true, true, true);
        Opens++;
        return fixture.Mode switch
        {
            "foreign-source" => binding with { SourceIdentity = "foreign-source" },
            "foreign-profile" => binding with { Attempt = root with { SourceProfile = "foreign-profile" } },
            "foreign-provider" => binding with { Attempt = root with { Provider = InfisicalDynamicProvider.SqlDatabase } },
            "foreign-epoch" => binding with { ClockAuthority = "foreign-clock" },
            "foreign-attempt" => binding with { Attempt = root with { Id = "foreign-attempt" } },
            _ => binding
        };
    }

    private NonSqlInputArm Arm(JsonObject command)
    {
        var attempt = command["attempt"]!.Deserialize<NonSqlInputAttempt>(InfisicalNonSqlInputEffectTests.Options)!;
        long cursor = fixture.Tick();
        pending = new(attempt, Guid.NewGuid().ToString(), cursor, fixture.Now, true);
        return pending;
    }

    private NonSqlInputFence Complete(JsonObject command)
    {
        var arm = command["arm"]!.Deserialize<NonSqlInputArm>(InfisicalNonSqlInputEffectTests.Options)!;
        var receipt = command["receipt"]!.Deserialize<DispatchEvidence>(InfisicalNonSqlInputEffectTests.Options);
        bool read = arm.Attempt.Operation is "InspectDefinitionAsync" or "ListDefinitionsAsync";
        var actual = fixture.Requests.Where(r => r.Sequence > arm.Cursor &&
            (r.Name == arm.Attempt.OriginalName || arm.Attempt.Operation == "ListDefinitionsAsync" && r.Name == "")).ToArray();
        int commits = actual.Count(r => r.Applied);
        Guid? id = actual.LastOrDefault(r => r.DefinitionId is not null)?.DefinitionId ?? arm.Attempt.DefinitionId;
        bool absent = fixture.Snapshot(id) is null;
        long sequence = fixture.Tick();
        fence = new(arm, receipt, Guid.NewGuid().ToString(),
            actual.Length == 0 ? null : "native-request-" + actual[0].Sequence, sequence, fixture.Now,
            actual.Length, commits, commits != 0 && !read, id, true, absent,
            fixture.Mode != "late-commit", fixture.Mode != "late-commit",
            actual.Length <= 1, fixture.PendingActions == 0, fixture.PendingActions);
        pending = null;
        return fixture.Mode == "foreign-epoch-after-open" ?
            fence with
            {
                Arm = arm with
                {
                    Attempt = arm.Attempt with
                    { Binding = arm.Attempt.Binding with { ClockEpoch = "foreign-epoch" } }
                }
            } : fence;
    }

    private NonSqlInputObservation Observe(JsonObject command)
    {
        Guid? id = command["definitionId"]?.GetValue<Guid>();
        var configuration = command["configuration"]!.Deserialize<NonSqlInputConfiguration>(InfisicalNonSqlInputEffectTests.Options);
        string phase = command["phase"]!.GetValue<string>();
        var saved = fixture.Snapshot(id);
        var original = fixture.Validations.LastOrDefault(v => v.DefinitionId == id) ??
            fixture.Validations.FirstOrDefault();
        // Read/delete reuse the original validation sequence; GET/DELETE never
        // fabricate a new administrative session or a local transformation.
        bool selectedConfiguration = configuration == NonSqlInputConfiguration.Selected;
        var expected = baseline!.DeepClone().AsObject();
        string operation = packet!["options"]!["operation"]!.GetValue<string>();
        string variant = packet["options"]!["variant"]!.GetValue<string>();
        if (selectedConfiguration && operation == "CreateDefinitionAsync") expected = selected!.DeepClone().AsObject();
        else if (selectedConfiguration && operation == "UpdateDefinitionAsync" && variant != "inputs.omitted")
        {
            foreach (var pair in selected!) expected[pair.Key] = pair.Value?.DeepClone();
            if (selected["gatewayId"]?.GetValue<string>() is { Length: > 0 }) expected["gatewayPoolId"] = null;
            else if (selected["gatewayPoolId"]?.GetValue<string>() is { Length: > 0 }) expected["gatewayId"] = null;
            if (fixture.Provider == InfisicalDynamicProvider.Oauth2 && expected["clientAuth"] is JsonObject auth &&
                !auth.ContainsKey("clientSecret"))
                auth["clientSecret"] = baseline["clientAuth"]!["clientSecret"]?.DeepClone();
        }
        ExpectedDefaults(expected, fixture.Provider);
        bool local = root!.ValidationKind == NonSqlValidationKind.LocalValidation;
        JsonObject? committed = saved?.Inputs.DeepClone().AsObject();
        if (fixture.Provider == InfisicalDynamicProvider.Ssh && committed is not null)
        { committed.Remove("caPrivateKey"); committed.Remove("caPublicKey"); }
        bool storage = configuration == NonSqlInputConfiguration.Absent ? saved is null :
            committed is not null && JsonNode.DeepEquals(committed, expected);
        var settings = packet["options"]!.AsObject();
        bool optionsChanged = fence!.Applied && fence.Arm.Attempt.Variant != "seed" &&
            fence.Arm.Attempt.Operation is "CreateDefinitionAsync" or "UpdateDefinitionAsync";
        JsonNode? expectedMetadata = optionsChanged &&
            variant != "options.omitted" && variant != "metadata.omitted" ?
            variant == "metadata.value" ? settings["metadata"] : new JsonArray() : null;
        JsonNode? expectedUsername = optionsChanged && variant == "usernameTemplate.value" ?
            settings["usernameTemplate"] : null;
        bool options = saved is null || JsonNode.DeepEquals(saved.Metadata, expectedMetadata) &&
            JsonNode.DeepEquals(saved.UsernameTemplate, expectedUsername);
        bool validation = original is not null && original.Accepted &&
            (saved is null || saved.ValidationSequence == original.Sequence);
        bool admin = !local && original is not null && original.Principal == Principal(expected) &&
            original.Target == Target(expected);
        bool transport = original is not null && original.Trust == Text(expected, "ca") &&
            original.Route == (fixture.Provider == InfisicalDynamicProvider.IbmApiConnect ? "direct" :
                Text(expected, "gatewayId") + "/" + Text(expected, "gatewayPoolId"));
        var wrong = expected.DeepClone().AsObject();
        PoisonSecret(wrong);
        bool wrongRejected = !local && !fixture.AuthorityAccepted(wrong);
        var keys = fixture.Keys.Where(k => k.DefinitionId == (id ?? original?.DefinitionId)).ToArray();
        bool lineage = fixture.Provider == InfisicalDynamicProvider.Ssh && keys.Length != 0 &&
            keys.Zip(keys.Skip(1)).All(pair => (pair.First.Algorithm == pair.Second.Algorithm) ==
                (pair.First.Lineage == pair.Second.Lineage)) &&
            (saved is null || InfisicalNonSqlInputEffectFixture.Text(saved.Inputs, "caPrivateKey") ==
                "controlled-private-" + keys[^1].Lineage);
        long sequence = fixture.Tick();
        Observations++;
        return new(binding!, id, configuration, phase, Guid.NewGuid().ToString(), sequence, fixture.Now,
            true, storage, options, root.ValidationKind,
            local ? null : original?.Action, local ? null : original?.Principal, local ? null : original?.Target,
            !local && admin, wrongRejected,
            local && storage && fixture.Mode != "ignored-local", local && lineage,
            !local && admin && transport,
            !local && admin && original?.DeploymentIdentity == "controlled-deployment-identity",
            validation, fixture.BorrowedRootIntact);
    }

    private NonSqlInputCleanup Close(JsonObject command)
    {
        var attempt = command["attempt"]!.Deserialize<NonSqlInputRootAttempt>(InfisicalNonSqlInputEffectTests.Options)!;
        // This is an explicit event-driven controlled clock delivery, not forced
        // deletion or a shortened native lifetime. Unexpiring orphans stay active.
        fixture.DeliverNaturalExpiry();
        bool settled = fixture.PendingActions == 0 && fixture.Mode != "late-commit";
        registered = false;
        pending = null;
        packet?.Clear(); packet = null;
        baseline?.Clear(); baseline = null;
        selected?.Clear(); selected = null;
        foreach (var validation in fixture.Validations) validation.Inputs.Clear();
        Closes++;
        return new(attempt, true, !registered, fixture.BorrowedRootIntact, fixture.DefinitionCount == 0,
            PrivateCopiesDestroyed, settled, settled, fixture.ActiveResources == 0,
            fixture.ActiveMaterials == 0, fixture.PendingActions, Registrations, settled ? 0 : 1);
    }

    private JsonObject MapPacket(JsonObject data) => Map(fixture.Provider,
        data["profile"]?.Deserialize<InfisicalDynamicProfileInput>(InfisicalNonSqlInputEffectTests.Options),
        data["alternative"]?.Deserialize<InfisicalDynamicAlternativeProfileInput>(InfisicalNonSqlInputEffectTests.Options),
        data["alternativeVariant"]?.GetValue<string>());

    // Independent mapping from closed private inputs. It never invokes profile
    // WriteInputs, captures a submitted body, or uses metadata as storage proof.
    internal static JsonObject Map(InfisicalDynamicProvider provider, InfisicalDynamicProfileInput? profile,
        InfisicalDynamicAlternativeProfileInput? alternative, string? alternativeVariant)
    {
        JsonObject root = JsonSerializer.SerializeToNode((object?)profile ?? alternative!,
            InfisicalNonSqlInputEffectTests.Options)!.AsObject();
        var data = root.Single(pair => pair.Value is not null).Value!.DeepClone().AsObject();
        RemoveNulls(data);
        Rename("creation", "creationStatement"); Rename("revocation", "revocationStatement");
        Rename("renewal", "renewStatement"); Rename("masterCreation", "masterCreationStatement");
        if (data.Remove("gateway", out var gatewayNode) && gatewayNode is JsonObject gateway)
        {
            foreach (string field in new[] { "gatewayId", "gatewayPoolId" })
            {
                if (gateway.ContainsKey(field)) data[field] = gateway[field]?.DeepClone();
                if (gateway["clear" + char.ToUpperInvariant(field[0]) + field[1..]]?.GetValue<bool>() == true)
                    data[field] = null;
            }
        }
        if (data.Remove("passwordRequirements", out var passwordNode) && passwordNode is JsonObject policy)
        {
            data["passwordRequirements"] = new JsonObject
            {
                ["length"] = policy["length"]?.DeepClone(),
                ["required"] = new JsonObject
                {
                    ["lowercase"] = policy["lowercase"]?.DeepClone(),
                    ["uppercase"] = policy["uppercase"]?.DeepClone(),
                    ["digits"] = policy["digits"]?.DeepClone(),
                    ["symbols"] = policy["symbols"]?.DeepClone()
                }
            };
            if (policy.ContainsKey("allowedSymbols"))
                data["passwordRequirements"]!["allowedSymbols"] = policy["allowedSymbols"]?.DeepClone();
        }
        if (data.Remove("options", out var options) && options is JsonObject optionFields)
            foreach (var pair in optionFields) data[pair.Key] = pair.Value?.DeepClone();
        switch (provider)
        {
            case InfisicalDynamicProvider.Snowflake: Rename("organizationId", "orgId"); break;
            case InfisicalDynamicProvider.AwsIam:
                string method = Text(data, "authentication");
                data["method"] = method == "AssumeRole" ? "assume-role" : method == "Irsa" ? "irsa" : "access-key";
                data["credentialType"] = Text(data, "credentialKind") == "Temporary" ? "temporary-credentials" : "iam-user";
                data.Remove("authentication"); data.Remove("credentialKind");
                break;
            case InfisicalDynamicProvider.AwsMemorydb:
                Nest("auth", "type", "iam", "accessKeyId", "secretAccessKey"); break;
            case InfisicalDynamicProvider.Github: Rename("applicationId", "appId"); break;
            case InfisicalDynamicProvider.MongoDb:
                if (data["clearPort"]?.GetValue<bool>() == true) data["port"] = null;
                if (data["clearCa"]?.GetValue<bool>() == true) data["ca"] = null;
                data.Remove("clearPort"); data.Remove("clearCa"); break;
            case InfisicalDynamicProvider.ElasticSearch:
                Nest("auth", "type", alternative is null ? "user" : "api-key",
                    alternative is null ? "username" : "apiKeyId", alternative is null ? "password" : "apiKey");
                break;
            case InfisicalDynamicProvider.RabbitMq:
                data["virtualHost"] = new JsonObject
                {
                    ["name"] = data["virtualHost"]?.DeepClone(),
                    ["permissions"] = new JsonObject
                    {
                        ["configure"] = data["configurePermission"]?.DeepClone(),
                        ["write"] = data["writePermission"]?.DeepClone(),
                        ["read"] = data["readPermission"]?.DeepClone()
                    }
                };
                data.Remove("configurePermission"); data.Remove("writePermission"); data.Remove("readPermission");
                break;
            case InfisicalDynamicProvider.Kubernetes:
                Rename("nameSpace", "namespace");
                data["credentialType"] = alternative is null ? "dynamic" : "static";
                if (alternative is null) data["roleType"] = data["clusterRole"]!.GetValue<bool>() ? "cluster-role" : "role";
                data.Remove("clusterRole");
                if (data.Remove("authentication", out var authentication))
                    data["authMethod"] = authentication!.GetValue<string>() == "Api" ? "api" : "gateway";
                data["sslRejectUnauthorized"] = true;
                break;
            case InfisicalDynamicProvider.Ldap:
                Rename("bindDn", "binddn"); Rename("bindPassword", "bindpass");
                data["credentialType"] = alternative is null ? "dynamic" : "static"; break;
            case InfisicalDynamicProvider.Totp:
                data["configType"] = alternative is null ? "url" : "manual";
                if (alternative is null) Rename("provisioningUrl", "url");
                else data["algorithm"] = Text(data, "algorithm").ToLowerInvariant();
                break;
            case InfisicalDynamicProvider.Ssh:
                foreach (string field in new[] { "keyAlgorithm", "caKeyAlgorithm" })
                    if (data[field] is { } algorithm) data[field] = algorithm.GetValue<string>() switch
                    {
                        "Rsa2048" => "RSA_2048",
                        "Rsa4096" => "RSA_4096",
                        "EcPrime256v1" => "EC_prime256v1",
                        "EcSecp384r1" => "EC_secp384r1",
                        "Ed25519" => "ED25519",
                        _ => throw new InvalidOperationException("controlled-key-algorithm")
                    };
                break;
            case InfisicalDynamicProvider.IbmApiConnect:
                Rename("applicationId", "appId"); Rename("organizationId", "orgId");
                Rename("consumerOrganizationId", "consumerOrgId"); break;
            case InfisicalDynamicProvider.Oauth2:
                Nest("clientAuth", "method", Text(data, "method") == "Basic" ? "client_secret_basic" : "client_secret_post", "clientSecret");
                data.Remove("method"); data["grantType"] = "client-credentials";
                Rename("extraParameters", "extraParams"); break;
            case InfisicalDynamicProvider.Tailscale:
                bool oauth = alternativeVariant?.EndsWith(".oauth", StringComparison.Ordinal) == true;
                Nest("auth", "method", oauth ? "oauth" : "api_key", oauth ? "clientId" : "apiKey", oauth ? "clientSecret" : "");
                data["authType"] = alternativeVariant?.Split('.')[1] ?? "auth_keys"; break;
            case InfisicalDynamicProvider.Couchbase:
                Nest("auth", null, null, "apiKey"); Rename("organizationId", "orgId");
                if (data.Remove("buckets", out var buckets) && buckets is JsonObject choices)
                    data["buckets"] = (choices["text"] ?? choices["buckets"])?.DeepClone();
                break;
        }
        return data;
        void Rename(string from, string to)
        {
            if (data.Remove(from, out var value)) data[to] = value;
        }
        void Nest(string field, string? discriminator, string? value, params string[] children)
        {
            var nested = new JsonObject();
            if (discriminator is not null) nested[discriminator] = value;
            foreach (string child in children)
                if (child.Length != 0 && data.Remove(child, out var property)) nested[child] = property;
            data[field] = nested;
        }
    }

    private static void RemoveNulls(JsonNode node)
    {
        if (node is JsonObject obj)
            foreach (var pair in obj.ToArray())
                if (pair.Value is null) obj.Remove(pair.Key); else RemoveNulls(pair.Value);
        else if (node is JsonArray array)
            foreach (var value in array) if (value is not null) RemoveNulls(value);
    }

    private static void ExpectedDefaults(JsonObject expected, InfisicalDynamicProvider provider)
    {
        if (expected["gatewayId"]?.GetValue<string>() is { Length: > 0 }) expected["gatewayPoolId"] = null;
        else if (expected["gatewayPoolId"]?.GetValue<string>() is { Length: > 0 }) expected["gatewayId"] = null;
        if (provider == InfisicalDynamicProvider.AzureSqlDatabase && !expected.ContainsKey("masterDatabase")) expected["masterDatabase"] = "master";
        if (provider == InfisicalDynamicProvider.Milvus)
        {
            if (!expected.ContainsKey("database")) expected["database"] = "default";
            if (!expected.ContainsKey("privileges")) expected["privileges"] = new JsonArray();
        }
        if (provider == InfisicalDynamicProvider.GcpIam && !expected.ContainsKey("tokenScopes"))
            expected["tokenScopes"] = new JsonArray("https://www.googleapis.com/auth/cloud-platform");
        if (provider == InfisicalDynamicProvider.RabbitMq && !expected.ContainsKey("tags")) expected["tags"] = new JsonArray();
        if (provider == InfisicalDynamicProvider.Couchbase && !expected.ContainsKey("buckets")) expected["buckets"] = "*";
        if (provider == InfisicalDynamicProvider.Tailscale)
        {
            if (!expected.ContainsKey("tailnet")) expected["tailnet"] = "-";
            if (!expected.ContainsKey("tags")) expected["tags"] = new JsonArray();
            if (Text(expected, "authType") == "auth_keys")
            {
                if (!expected.ContainsKey("reusable")) expected["reusable"] = false;
                if (!expected.ContainsKey("preauthorized")) expected["preauthorized"] = false;
            }
        }
        if (provider == InfisicalDynamicProvider.Ssh)
        {
            if (!expected.ContainsKey("keyAlgorithm")) expected["keyAlgorithm"] = "RSA_2048";
            if (!expected.ContainsKey("caKeyAlgorithm")) expected["caKeyAlgorithm"] = "RSA_2048";
        }
        if (provider == InfisicalDynamicProvider.Totp)
        {
            if (Text(expected, "configType") == "url")
            {
                var query = new Uri(Text(expected, "url")).Query[1..].Split('&').Select(x => x.Split('=', 2));
                foreach (var pair in query)
                {
                    if (pair[0] == "secret") expected["secret"] = Uri.UnescapeDataString(pair[1]).Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
                    if (pair[0] == "algorithm") expected["algorithm"] = pair[1].ToLowerInvariant();
                    if (pair[0] is "digits" or "period") expected[pair[0]] = int.Parse(pair[1]);
                }
            }
            else expected["secret"] = Text(expected, "secret").Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
            if (!expected.ContainsKey("algorithm")) expected["algorithm"] = "sha1";
            if (!expected.ContainsKey("digits")) expected["digits"] = 6;
            if (!expected.ContainsKey("period")) expected["period"] = 30;
        }
    }

    internal static string Principal(JsonObject inputs)
    {
        string direct = First(inputs, "username", "binddn", "serviceAccountEmail", "applicationId", "appId",
            "adminPublicKey", "clientId", "accessKey", "accessKeyId", "roleArn");
        return direct != "controlled-deployment-authority" ? direct :
            inputs["auth"] is JsonObject auth ? First(auth, "username", "apiKeyId", "clientId", "accessKeyId") : direct;
    }
    internal static string Target(JsonObject inputs) => inputs.ContainsKey("authType") ?
        inputs["tailnet"]?.GetValue<string>() ?? "-" :
        First(inputs, "host", "url", "instanceUrl", "tokenUrl", "region", "tenantId",
            "installationId", "serviceAccountEmail", "groupId", "orgId", "namespace");
    internal static string Secret(JsonObject inputs)
    {
        string direct = First(inputs, "password", "bindpass", "clientSecret", "secretAccessKey",
            "privateKey", "adminPrivateKey", "apiKey", "clusterToken");
        return direct != "controlled-deployment-authority" ? direct :
            (inputs["clientAuth"] ?? inputs["auth"]) is JsonObject auth ?
                First(auth, "password", "apiKey", "secretAccessKey", "clientSecret") : direct;
    }
    private static string First(JsonObject inputs, params string[] names)
    {
        foreach (string name in names)
            if (inputs[name] is { } value) return value is JsonValue scalar && scalar.TryGetValue<string>(out var text) ?
                text : value.ToJsonString();
        return "controlled-deployment-authority";
    }
    private static void PoisonSecret(JsonObject inputs)
    {
        if (inputs.ContainsKey("serviceAccountEmail"))
        { inputs["serviceAccountEmail"] = "wrong@foreign.test"; return; }
        foreach (string name in new[] { "password", "bindpass", "clientSecret", "secretAccessKey", "privateKey",
            "adminPrivateKey", "apiKey", "clusterToken", "clientAuth", "auth" })
            if (inputs.ContainsKey(name)) { inputs[name] = "wrong-authority"; return; }
        if (inputs.ContainsKey("username"))
        { inputs["username"] = "wrong-authority"; return; }
        inputs["roleArn"] = "wrong-authority";
    }
    private static string Text(JsonObject inputs, string key) => InfisicalNonSqlInputEffectFixture.Text(inputs, key);
    internal static string Action(InfisicalDynamicProvider provider, JsonObject inputs) => provider switch
    {
        InfisicalDynamicProvider.Clickhouse => "clickhouse.select-1",
        InfisicalDynamicProvider.Cassandra => "cassandra.system-schema-keyspaces",
        InfisicalDynamicProvider.SapAse => "sap-ase.master-and-selected-version",
        InfisicalDynamicProvider.SapHana => "sap-hana.select-1-dummy",
        InfisicalDynamicProvider.Redis => "redis.auth-ping",
        InfisicalDynamicProvider.Vertica => "vertica.select-version",
        InfisicalDynamicProvider.AzureSqlDatabase => "azure-sql.selected-database-select-1",
        InfisicalDynamicProvider.Snowflake => "snowflake.connect-is-valid",
        InfisicalDynamicProvider.AwsIam => Text(inputs, "credentialType") == "iam-user" ?
            "iam.get-user" : "sts.session-token-or-assume-role",
        InfisicalDynamicProvider.AwsElasticache => "elasticache.describe-replication-groups",
        InfisicalDynamicProvider.AwsMemorydb => "memorydb.describe-clusters",
        InfisicalDynamicProvider.AzureEntraId => "entra.client-token-exchange",
        InfisicalDynamicProvider.GcpIam => "gcp.impersonation-token",
        InfisicalDynamicProvider.Github => "github.installation-token",
        InfisicalDynamicProvider.Milvus => "milvus.describe-user",
        InfisicalDynamicProvider.MongoDb => "mongodb.database-ping",
        InfisicalDynamicProvider.ElasticSearch => inputs["auth"]?["type"]?.GetValue<string>() == "api-key" ?
            "elasticsearch.info-api-key" : "elasticsearch.info-user",
        InfisicalDynamicProvider.RabbitMq => "rabbitmq.whoami",
        InfisicalDynamicProvider.Kubernetes => Text(inputs, "credentialType") == "static" ?
            "kubernetes.static-account-get" : "kubernetes.test-account-binding-token-delete",
        InfisicalDynamicProvider.Ldap => "ldap.admin-bind",
        InfisicalDynamicProvider.Totp => "totp.local-normalize",
        InfisicalDynamicProvider.Ssh => "ssh.local-ca",
        InfisicalDynamicProvider.IbmApiConnect => "ibm.api-token",
        InfisicalDynamicProvider.Oauth2 => "oauth.token-ttl-revoke",
        InfisicalDynamicProvider.Tailscale => inputs["auth"]?["method"]?.GetValue<string>() == "oauth" ?
            "tailscale.oauth-exchange" : "tailscale.api-list",
        InfisicalDynamicProvider.Couchbase => "couchbase.organization-get",
        InfisicalDynamicProvider.MongoDbAtlas => "atlas.digest-database-users-list",
        _ => throw new ArgumentException("controlled-provider")
    };
}
