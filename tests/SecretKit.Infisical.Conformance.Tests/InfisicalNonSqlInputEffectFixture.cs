using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled native service. Only this wire commits definitions. The private
// source reads this store and the independent validation/action inventories.
internal sealed class InfisicalNonSqlInputEffectFixture : IAsyncDisposable
{
    internal static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    internal const string ProjectId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    internal const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Dictionary<string, (string Name, string Path)> folders = [];
    private readonly Dictionary<string, Saved> definitions = [];
    private readonly List<JsonObject> authorities = [];
    private readonly Dictionary<string, SecretMaterial> upstreamMaterials = [];
    private readonly Dictionary<string, Guid> upstreamResources = [];
    private readonly Dictionary<string, string> borrowed = new() { ["administrative-account"] = "original", ["root"] = "/borrowed" };
    private readonly Task accept;
    private long sequence;
    private DateTimeOffset clock = Epoch;
    internal Uri Origin { get; }
    internal InfisicalDynamicProvider Provider { get; }
    internal string Variant { get; }
    internal string Mode { get; }
    internal InfisicalDynamicProfileInput? Baseline { get; }
    internal InfisicalDynamicProfileInput? Selected { get; }
    internal InfisicalDynamicAlternativeProfileInput? BaselineAlternative { get; }
    internal InfisicalDynamicAlternativeProfileInput? SelectedAlternative { get; }
    internal string? AlternativeVariant { get; }
    internal string? BaselineAlternativeVariant { get; }
    internal InfisicalNonSqlInputEffectSource Source { get; }
    internal List<RequestEvent> Requests { get; } = [];
    internal List<ValidationEvent> Validations { get; } = [];
    internal List<UpstreamAction> Actions { get; } = [];
    internal List<KeyEvent> Keys { get; } = [];
    internal bool BorrowedRootIntact => borrowed.Count == 2 &&
        borrowed.GetValueOrDefault("administrative-account") == "original" && borrowed.GetValueOrDefault("root") == "/borrowed";
    internal long Sequence => sequence;
    internal DateTimeOffset Now => clock;
    internal int DefinitionCount => definitions.Count;
    internal int ResidualCount => definitions.Count + folders.Count + ActiveMaterials + ActiveResources;
    internal int ActiveMaterials => upstreamMaterials.Count;
    internal int ActiveResources => upstreamResources.Count;
    internal int PendingActions => Actions.Count(a => !a.Settled);
    internal long Tick() { lock (folders) { clock = clock.AddTicks(1); return ++sequence; } }

    internal InfisicalNonSqlInputEffectFixture(InfisicalDynamicProvider provider,
        string variant, string mode = "good", string? alternativeVariant = null)
    {
        Provider = provider;
        Variant = variant;
        Mode = mode;
        AlternativeVariant = alternativeVariant ??
            (InfisicalDynamicAlternativeProfileInputs.TryProvider(variant, out _) ? variant : null);
        BaselineAlternativeVariant = AlternativeVariant;
        if (AlternativeVariant is { } alternative)
        {
            var sample = InfisicalDynamicAlternativeProfileInputTests.Sample(alternative, 1);
            using var unused = sample.Profile;
            BaselineAlternative = Contrast(sample.Input, false, variant);
            SelectedAlternative = Contrast(sample.Input, true);
            if (provider == InfisicalDynamicProvider.Totp)
            {
                var baselineAlgorithm = alternative == "Totp.manual.Sha1" ? NativeTotpAlgorithm.Sha256 : NativeTotpAlgorithm.Sha1;
                BaselineAlternativeVariant = "Totp.manual." + baselineAlgorithm;
                BaselineAlternative = BaselineAlternative with
                {
                    TotpManualSecret =
                    BaselineAlternative.TotpManualSecret! with { Secret = "JBSWY3DPEHPK3PXP", Algorithm = baselineAlgorithm, Digits = 6, Period = 30 }
                };
                SelectedAlternative = SelectedAlternative with
                {
                    TotpManualSecret =
                    SelectedAlternative.TotpManualSecret! with { Secret = "KRSXG5DSNFXGOIDB" }
                };
            }
        }
        else
        {
            var input = InfisicalDynamicNestedProfileOptionTests.Sample(provider);
            if (provider == InfisicalDynamicProvider.Totp)
                input = new(Totp: new("otpauth://totp/owned?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=45"));
            if (provider == InfisicalDynamicProvider.AwsIam && !variant.Contains("sessionPolicy", StringComparison.Ordinal))
                input = input with
                {
                    AwsIam = input.AwsIam! with
                    {
                        AccessKey = "access-canary",
                        SecretAccessKey = "secret-canary",
                        Authentication = DynamicAwsAuthentication.AccessKey,
                        RoleArn = null,
                        Options = input.AwsIam.Options! with { SessionPolicyArns = null, SessionPolicyDocument = null }
                    }
                };
            if (variant.StartsWith("AwsIam.", StringComparison.Ordinal) && !InfisicalDynamicNestedProfileOptions.Supports(variant))
            {
                string[] parts = variant.Split('.');
                input = input with
                {
                    AwsIam = input.AwsIam! with
                    {
                        Authentication = parts[1] == "access-key" ? DynamicAwsAuthentication.AccessKey :
                        parts[1] == "assume-role" ? DynamicAwsAuthentication.AssumeRole : DynamicAwsAuthentication.Irsa,
                        AccessKey = parts[1] == "access-key" ? "access-canary" : null,
                        SecretAccessKey = parts[1] == "access-key" ? "secret-canary" : null,
                        RoleArn = parts[1] == "assume-role" ? "arn:aws:iam::123456789012:role/owned-role" : null,
                        CredentialKind = Enum.Parse<NativeAwsCredentialKind>(parts[2])
                    }
                };
            }
            if (variant == "Couchbase.buckets.text")
                input = input with { Couchbase = input.Couchbase! with { Buckets = new(Text: "owned-bucket") } };
            Baseline = Contrast(input, false, variant);
            Selected = Contrast(input, true);
            if (provider == InfisicalDynamicProvider.Totp)
                Selected = new(Totp: new("otpauth://totp/owned?secret=KRSXG5DSNFXGOIDB&algorithm=SHA256&digits=8&period=45"));
        }
        // Provisioned targets are independent of requests and source Open/Arm.
        authorities.Add(InfisicalNonSqlInputEffectSource.Map(provider, Baseline, BaselineAlternative, BaselineAlternativeVariant));
        try
        {
            var selected = Selection();
            var expected = InfisicalNonSqlInputEffectSource.Map(provider, selected.Profile, selected.Alternative, AlternativeVariant);
            authorities.Add(expected);
            var merged = authorities[0].DeepClone().AsObject();
            foreach (var pair in expected) merged[pair.Key] = pair.Value?.DeepClone();
            authorities.Add(merged);
        }
        catch (ArgumentException) { /* Deliberately invalid private selections have no selected authority. */ }
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        accept = AcceptAsync();
    }

    internal (InfisicalDynamicProfileInput? Profile, InfisicalDynamicAlternativeProfileInput? Alternative) Selection()
    {
        if (Variant.StartsWith("gatewayId.", StringComparison.Ordinal) ||
            Variant.StartsWith("gatewayPoolId.", StringComparison.Ordinal))
        {
            string[] parts = Variant.Split('.');
            string alias = parts[1] == "null" ?
                "NativeGatewayOptions.clear" + char.ToUpperInvariant(parts[0][0]) + parts[0][1..] + ".true" :
                "NativeGatewayOptions." + Variant;
            return (InfisicalDynamicNestedProfileOptions.Select(alias, Provider, Selected!), null);
        }
        if (Variant is "passwordRequirements.omitted" or "passwordRequirements.value")
        {
            string name = Provider switch
            {
                InfisicalDynamicProvider.Clickhouse => "NativeClickhouseDefinitionProfile",
                InfisicalDynamicProvider.Vertica => "NativeVerticaDefinitionProfile",
                InfisicalDynamicProvider.AzureSqlDatabase => "NativeAzureSqlDefinitionProfile",
                InfisicalDynamicProvider.Couchbase => "NativeCouchbaseDefinitionProfile",
                _ => throw new ArgumentException("controlled-password-provider")
            };
            return (InfisicalDynamicProfileVariants.Select(name + "." + Variant, Selected!), null);
        }
        if (InfisicalDynamicNestedProfileOptions.Supports(Variant))
            return AlternativeVariant is { } alternative ?
                (null, InfisicalDynamicNestedProfileOptions.SelectAlternative(Variant, alternative, SelectedAlternative!)) :
                (InfisicalDynamicNestedProfileOptions.Select(Variant, Provider, Selected!), null);
        if (InfisicalDynamicProfileVariants.TryProvider(Variant, out _))
            return (InfisicalDynamicProfileVariants.Select(Variant, Selected!), null);
        return (Selected, SelectedAlternative);
    }

    internal InfisicalDynamicProfile Create(bool selected)
    {
        var inputs = selected ? Selection() : (Baseline, BaselineAlternative);
        return inputs.Item2 is null ? InfisicalDynamicProfileInputs.Create(Provider, inputs.Item1!) :
            InfisicalDynamicAlternativeProfileInputs.Create((selected ? AlternativeVariant : BaselineAlternativeVariant)!, inputs.Item2);
    }

    internal InfisicalDynamicClientEffects.DynamicInput PrivateInput(bool witness = true) => new(
        new(ProjectId, "project-slug", "env", EnvironmentId, "/borrowed"), null,
        60, 300, 120, "owned-selected", [new("marker", "selected")], [], [],
        Selected, SelectedAlternative,
        InfisicalDynamicNestedProfileOptions.Supports(Variant) ? Provider : null,
        InfisicalDynamicNestedProfileOptions.Supports(Variant) ? AlternativeVariant : null,
        NonSqlInputWitness: witness ? new("controlled-nonsql", "controlled-fixture",
            Guid.NewGuid().ToString("N"), 15, Baseline, BaselineAlternative, BaselineAlternativeVariant) : null);

    internal JsonObject Input(bool witness = true) => JsonSerializer.SerializeToNode(PrivateInput(witness),
        InfisicalNonSqlInputEffectTests.Options)!.AsObject();

    // Change actual protected coordinates, not merely metadata. Enum names and
    // fixed schema strings are preserved; all copies remain private fixture data.
    private static T Contrast<T>(T input, bool selected, string variant = "")
    {
        var node = JsonSerializer.SerializeToNode(input, InfisicalNonSqlInputEffectTests.Options)!;
        Change(node);
        return node.Deserialize<T>(InfisicalNonSqlInputEffectTests.Options)!;
        void Change(JsonNode value)
        {
            if (value is JsonObject obj)
                foreach (var pair in obj.ToArray())
                {
                    if (pair.Value is JsonValue text && text.TryGetValue<string>(out var s))
                    {
                        if (!selected && pair.Key is "keyAlgorithm" or "caKeyAlgorithm")
                            obj[pair.Key] = variant.EndsWith(".Rsa2048", StringComparison.Ordinal) ? "Ed25519" : "Rsa2048";
                        else if (!selected && pair.Key == "authentication" && s is "Api" or "Gateway")
                            obj[pair.Key] = variant.EndsWith(".Api", StringComparison.Ordinal) ? "Gateway" : "Api";
                        else if (!selected && pair.Key == "credentialKind")
                            obj[pair.Key] = s == "IamUser" ? "Temporary" : "IamUser";
                        else obj[pair.Key] = s.Replace("canary", selected ? "selected" : "baseline", StringComparison.Ordinal)
                            .Replace("offline.test", selected ? "selected.test" : "baseline.test", StringComparison.Ordinal)
                            .Replace("url.test", selected ? "selected.test" : "baseline.test", StringComparison.Ordinal)
                            .Replace("owned-role", selected ? "selected-role" : "baseline-role", StringComparison.Ordinal);
                    }
                    else if (!selected && pair.Value is JsonValue flag && flag.TryGetValue<bool>(out _) &&
                        pair.Key is "sslEnabled" or "reusable" or "preauthorized")
                        obj[pair.Key] = variant.EndsWith(".false", StringComparison.Ordinal) ||
                            variant.EndsWith(".omitted", StringComparison.Ordinal);
                    else if (!selected && pair.Key == "port" && pair.Value is JsonValue number &&
                        number.TryGetValue<int>(out var port)) obj[pair.Key] = port + 1000;
                    else if (!selected && pair.Key == "passwordRequirements" && pair.Value is JsonObject policy)
                    {
                        policy["length"] = 20; policy["lowercase"] = 1; policy["uppercase"] = 1;
                        policy["digits"] = 1; policy["symbols"] = 1; policy["allowedSymbols"] = "!";
                    }
                    else if (pair.Value is not null) Change(pair.Value);
                }
            else if (value is JsonArray array)
                for (int i = 0; i < array.Count; i++)
                    if (array[i] is JsonValue text && text.TryGetValue<string>(out var s))
                        array[i] = s + (selected ? "-selected" : "-baseline");
                    else if (array[i] is { } child) Change(child);
        }
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
                connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }

    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            try
            {
                var stream = socket.GetStream();
                var headers = new List<byte>();
                byte[] one = new byte[1];
                while (headers.Count < 32768)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    headers.Add(one[0]);
                    if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                }
                string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                string[] request = lines[0].Split(' ');
                string role = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                    .Split(' ').Last() ?? "";
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':')[1] ?? "0");
                if (length is < 0 or > 1048576) throw new InvalidOperationException("offline-budget");
                byte[] bytes = new byte[length];
                await stream.ReadExactlyAsync(bytes, shutdown.Token);
                var body = length == 0 ? new JsonObject() : JsonNode.Parse(bytes)!.AsObject();
                (int Status, object Payload) result;
                lock (folders) result = Handle(request[0], new(Origin, request[1]), role, body);
                Array.Clear(bytes);
                body.Clear();
                byte[] response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"),
                    shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
                Array.Clear(response);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }
    }

    private (int, object) Handle(string method, Uri uri, string role, JsonObject body)
    {
        string path = uri.AbsolutePath;
        if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal))
        {
            if (role == "denied") return (403, new { });
            if (method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                folders.Add(id, (Text(body, "name"), Text(body, "path").TrimEnd('/') + "/" + Text(body, "name")));
                return (200, new { folder = Folder(id) });
            }
            if (path == "/api/v2/folders") return (200, new { folders = folders.Keys.Select(Folder).ToArray() });
            string selector = Uri.UnescapeDataString(path.Split('/').Last());
            string? found = folders.Keys.SingleOrDefault(id => id == selector || folders[id].Name == selector);
            if (found is null) return (404, new { });
            object folder = Folder(found);
            if (method == "DELETE")
            {
                folders.Remove(found);
                if (Mode == "borrowed-state-damage") borrowed["administrative-account"] = "damaged";
            }
            return (200, new { folder });
        }
        if (!path.StartsWith("/api/v1/dynamic-secrets", StringComparison.Ordinal)) return (404, new { });
        if (path.EndsWith("/leases", StringComparison.Ordinal))
            return (200, new { leases = Array.Empty<object>() });
        string name = path == "/api/v1/dynamic-secrets" ? Text(body, "name") : Uri.UnescapeDataString(path.Split('/').Last());
        long dispatch = Tick();
        if (role == "denied")
        {
            Requests.Add(new(dispatch, name, method, false, null));
            return (403, new { });
        }
        if (method == "GET")
        {
            Requests.Add(new(dispatch, name, method, false, definitions.GetValueOrDefault(name)?.Id));
            return path == "/api/v1/dynamic-secrets" ?
                (200, new { dynamicSecrets = definitions.Values.Select(Projection).ToArray() }) :
                definitions.TryGetValue(name, out var read) ? (200, new { dynamicSecret = Projection(read) }) : (404, new { });
        }
        if (method == "POST")
        {
            var candidate = body["provider"]!["inputs"]!.DeepClone().AsObject();
            Guid id = Guid.NewGuid();
            var validation = Validate(candidate, id, name);
            bool committed = validation.Accepted && Mode != "uncommitted-save" &&
                !Mode.StartsWith("uncommitted-", StringComparison.Ordinal);
            var saved = new Saved(id, name, folders.Single(f => f.Value.Path == Text(body, "path")).Key,
                Text(body["provider"]!.AsObject(), "type"), Text(body, "defaultTTL"),
                body["maxTTL"]?.GetValue<string>(), candidate, body["metadata"]?.DeepClone(),
                body["usernameTemplate"]?.DeepClone(), validation.Sequence);
            if (committed) definitions.Add(name, saved);
            Requests.Add(new(Tick(), name, method, committed, committed ? id : null));
            return validation.Accepted ? (200, new { dynamicSecret = Projection(saved) }) : (400, new { });
        }
        if (!definitions.TryGetValue(name, out var original)) return (404, new { });
        if (method == "PATCH")
        {
            var data = body["data"]!.AsObject();
            var candidate = original.Inputs.DeepClone().AsObject();
            if (data["inputs"] is JsonObject patch && Mode != "ignored-protected-field")
            {
                foreach (var pair in patch) candidate[pair.Key] = pair.Value?.DeepClone();
                if (patch["gatewayId"]?.GetValue<string>() is { Length: > 0 }) candidate["gatewayPoolId"] = null;
                else if (patch["gatewayPoolId"]?.GetValue<string>() is { Length: > 0 }) candidate["gatewayId"] = null;
            }
            // OAuth alone restores an omitted nested client secret.
            if (Provider == InfisicalDynamicProvider.Oauth2 && candidate["clientAuth"] is JsonObject auth &&
                !auth.ContainsKey("clientSecret"))
                auth["clientSecret"] = original.Inputs["clientAuth"]!["clientSecret"]?.DeepClone();
            var validation = Validate(candidate, original.Id, name);
            bool committed = validation.Accepted && Mode != "uncommitted-save" &&
                !Mode.StartsWith("uncommitted-", StringComparison.Ordinal);
            var changed = original with
            {
                Name = data["newName"]?.GetValue<string>() ?? name,
                Inputs = candidate,
                DefaultTtl = data["defaultTTL"]?.GetValue<string>() ?? original.DefaultTtl,
                MaximumTtl = data.ContainsKey("maxTTL") ? data["maxTTL"]?.GetValue<string>() : original.MaximumTtl,
                Metadata = Mode == "ignored-options" ? original.Metadata :
                    data.ContainsKey("metadata") ? data["metadata"]?.DeepClone() : original.Metadata,
                UsernameTemplate = Mode == "ignored-options" ? original.UsernameTemplate :
                    data.ContainsKey("usernameTemplate") ? data["usernameTemplate"]?.DeepClone() : original.UsernameTemplate,
                ValidationSequence = validation.Sequence
            };
            if (committed) { definitions.Remove(name); definitions[changed.Name] = changed; }
            Requests.Add(new(Tick(), name, method, committed, original.Id));
            if (Mode == "replay") Requests.Add(new(Tick(), name, method, committed, original.Id));
            return validation.Accepted ? (200, new { dynamicSecret = Projection(changed) }) : (400, new { });
        }
        if (method == "DELETE")
        {
            definitions.Remove(name);
            original.Inputs.Clear();
            Requests.Add(new(Tick(), name, method, true, original.Id));
            return (200, new { dynamicSecret = Projection(original) });
        }
        return (404, new { });
    }

    private ValidationEvent Validate(JsonObject inputs, Guid id, string name)
    {
        bool local = Provider is InfisicalDynamicProvider.Totp or InfisicalDynamicProvider.Ssh;
        bool accepted = local || AuthorityAccepted(inputs);
        string action = InfisicalNonSqlInputEffectSource.Action(Provider, inputs);
        string principal = InfisicalNonSqlInputEffectSource.Principal(inputs);
        string target = InfisicalNonSqlInputEffectSource.Target(inputs);
        if (Mode == "ignored-admin") principal = "foreign-admin";
        if (!local)
        {
            bool material = Provider is InfisicalDynamicProvider.Github or InfisicalDynamicProvider.GcpIam or
                InfisicalDynamicProvider.AzureEntraId or InfisicalDynamicProvider.IbmApiConnect or
                InfisicalDynamicProvider.Oauth2 || Provider == InfisicalDynamicProvider.Tailscale &&
                inputs["auth"]?["method"]?.GetValue<string>() == "oauth" ||
                Provider == InfisicalDynamicProvider.AwsIam && Text(inputs, "method") != "access-key";
            bool resource = Provider == InfisicalDynamicProvider.Kubernetes && Text(inputs, "credentialType") == "dynamic";
            if (material || resource)
            {
                string actionId = "original-action-" + Tick();
                if (material) upstreamMaterials.Add(actionId, SecretMaterial.FromText("controlled-validation-token-" + Guid.NewGuid().ToString("N")));
                if (resource) upstreamResources.Add(actionId, id);
                bool disposed = resource && !Mode.Contains("orphan-resource", StringComparison.Ordinal) ||
                    Provider == InfisicalDynamicProvider.Oauth2 && !Mode.Contains("orphan-material", StringComparison.Ordinal);
                if (disposed)
                {
                    upstreamResources.Remove(actionId);
                    if (upstreamMaterials.Remove(actionId, out var revoked)) revoked.Dispose();
                }
                Actions.Add(new(actionId, sequence, id, name, material, resource, Mode != "pending-admin", disposed,
                    Mode.Contains("orphan-material", StringComparison.Ordinal) ? DateTimeOffset.MaxValue : clock.AddSeconds(10)));
            }
        }
        Normalize(inputs, id);
        string route = Provider == InfisicalDynamicProvider.IbmApiConnect ? "direct" :
            Text(inputs, "gatewayId") + "/" + Text(inputs, "gatewayPoolId");
        string trust = Text(inputs, "ca");
        string deployment = "controlled-deployment-identity";
        if (Mode == "ignored-transport") { route = "direct"; trust = ""; }
        if (Mode == "retained-wrong-authority") deployment = "foreign-deployment-identity";
        var result = new ValidationEvent(Tick(), id, name, action, principal, target, accepted,
            local, route, trust, deployment, inputs.DeepClone().AsObject());
        Validations.Add(result);
        return result;
    }

    // Native normalization runs on the candidate before commitment. The source
    // has a separate expectation implementation; neither reads an SDK response.
    private void Normalize(JsonObject data, Guid id)
    {
        if (data["gatewayId"] is JsonValue gateway && gateway.TryGetValue<string>(out var g) && g.Length != 0)
            data["gatewayPoolId"] = null;
        else if (data["gatewayPoolId"] is JsonValue pool && pool.TryGetValue<string>(out var p) && p.Length != 0)
            data["gatewayId"] = null;
        switch (Provider)
        {
            case InfisicalDynamicProvider.AzureSqlDatabase: data["masterDatabase"] ??= "master"; break;
            case InfisicalDynamicProvider.Milvus:
                data["database"] ??= "default"; data["privileges"] ??= new JsonArray(); break;
            case InfisicalDynamicProvider.GcpIam:
                data["tokenScopes"] ??= new JsonArray("https://www.googleapis.com/auth/cloud-platform"); break;
            case InfisicalDynamicProvider.RabbitMq: data["tags"] ??= new JsonArray(); break;
            case InfisicalDynamicProvider.Couchbase: data["buckets"] ??= "*"; break;
            case InfisicalDynamicProvider.Tailscale:
                data["tailnet"] ??= "-"; data["tags"] ??= new JsonArray();
                if (Text(data, "authType") == "auth_keys") { data["reusable"] ??= false; data["preauthorized"] ??= false; }
                break;
            case InfisicalDynamicProvider.Totp when Mode != "ignored-local":
                if (Text(data, "configType") == "url")
                {
                    var uri = new Uri(Text(data, "url"));
                    var query = uri.Query.TrimStart('?').Split('&').Select(v => v.Split('=', 2))
                        .ToDictionary(v => v[0], v => Uri.UnescapeDataString(v[1]));
                    data["secret"] = query["secret"].Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
                    data["algorithm"] = query.GetValueOrDefault("algorithm", "SHA1").ToLowerInvariant();
                    data["digits"] = int.Parse(query.GetValueOrDefault("digits", "6"));
                    data["period"] = int.Parse(query.GetValueOrDefault("period", "30"));
                }
                else
                {
                    data["secret"] = Text(data, "secret").Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
                    data["digits"] ??= 6; data["period"] ??= 30;
                }
                break;
            case InfisicalDynamicProvider.Ssh when Mode != "ignored-local":
                data["keyAlgorithm"] ??= "RSA_2048"; data["caKeyAlgorithm"] ??= "RSA_2048";
                var previous = Keys.LastOrDefault(k => k.DefinitionId == id);
                string algorithm = Text(data, "caKeyAlgorithm");
                string lineage = previous is not null && previous.Algorithm == algorithm ?
                    previous.Lineage : Guid.NewGuid().ToString("N");
                data["caPrivateKey"] = "controlled-private-" + lineage;
                data["caPublicKey"] = "controlled-public-" + lineage;
                Keys.Add(new(Tick(), id, algorithm, lineage));
                break;
        }
    }

    internal bool AuthorityAccepted(JsonObject candidate) => authorities.Any(owned =>
        InfisicalNonSqlInputEffectSource.Principal(owned) == InfisicalNonSqlInputEffectSource.Principal(candidate) &&
        InfisicalNonSqlInputEffectSource.Target(owned) == InfisicalNonSqlInputEffectSource.Target(candidate) &&
        InfisicalNonSqlInputEffectSource.Secret(owned) == InfisicalNonSqlInputEffectSource.Secret(candidate));

    internal Saved? Snapshot(Guid? id) => id is null ? null : definitions.Values.SingleOrDefault(d => d.Id == id);
    internal void DeliverNaturalExpiry()
    {
        var expiring = Actions.Where(a => a.Material && !a.Disposed && a.ExpiresAt != DateTimeOffset.MaxValue).ToArray();
        if (expiring.Length != 0) clock = expiring.Max(a => a.ExpiresAt);
        foreach (var action in expiring)
            if (clock >= action.ExpiresAt && upstreamMaterials.Remove(action.Id, out var expired)) expired.Dispose();
    }

    private object Folder(string id) => new
    {
        id,
        envId = EnvironmentId,
        name = folders[id].Name,
        path = folders[id].Path,
        projectId = ProjectId,
        environment = new { envSlug = "env" },
        createdAt = Epoch,
        updatedAt = Epoch
    };
    private static object Projection(Saved saved) => new
    {
        id = saved.Id,
        name = saved.Name,
        folderId = saved.FolderId,
        type = saved.Type,
        defaultTTL = saved.DefaultTtl,
        maxTTL = saved.MaximumTtl,
        version = 1,
        createdAt = Epoch,
        updatedAt = Epoch,
        status = (string?)null
    };
    internal static string Text(JsonObject data, string field) => data[field]?.GetValue<string>() ?? "";
    public async ValueTask DisposeAsync()
    {
        await shutdown.CancelAsync();
        try { await accept; } finally { listener.Stop(); }
        await Task.WhenAll(connections);
        foreach (var saved in definitions.Values) saved.Inputs.Clear();
        foreach (var owned in authorities) owned.Clear();
        foreach (var validation in Validations) validation.Inputs.Clear();
        // Destroy host-private copies only. An orphan still failed source cleanup;
        // disposal is not a modeled upstream revoke or inventory removal.
        foreach (var material in upstreamMaterials.Values) material.Dispose();
        shutdown.Dispose();
    }

    internal sealed record Saved(Guid Id, string Name, string FolderId, string Type, string DefaultTtl,
        string? MaximumTtl, JsonObject Inputs, JsonNode? Metadata, JsonNode? UsernameTemplate, long ValidationSequence);
    internal sealed record RequestEvent(long Sequence, string Name, string Method, bool Applied, Guid? DefinitionId);
    internal sealed record ValidationEvent(long Sequence, Guid DefinitionId, string Name, string Action,
        string Principal, string Target, bool Accepted, bool Local, string Route, string Trust,
        string DeploymentIdentity, JsonObject Inputs);
    internal sealed record UpstreamAction(string Id, long Sequence, Guid DefinitionId, string Name,
        bool Material, bool Resource, bool Settled, bool Disposed, DateTimeOffset ExpiresAt);
    internal sealed record KeyEvent(long Sequence, Guid DefinitionId, string Algorithm, string Lineage);
}
