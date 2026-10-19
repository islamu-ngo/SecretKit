using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent executable provider/backend/scheduler, not a native provider.
// No SDK response projection creates material. The provider writes its own
// journals; the source reads them through the separate private channel.
internal sealed class InfisicalRotationMutationFixture : IAsyncDisposable
{
    internal const string Project = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    internal const string Rotation = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    internal static readonly DateTimeOffset Clock = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    internal static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    { IgnoreReadOnlyProperties = false };
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<long, OwnedSet> material = [];
    private readonly Dictionary<long, BackendCredential> backend = [];
    private readonly Dictionary<string, (SecretMaterial Material, int Version)> mapped = new(StringComparer.Ordinal);
    private readonly HashSet<string> ownedIdentities = new(StringComparer.Ordinal);
    private readonly HashSet<string> ownedResources = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> pending = new(StringComparer.Ordinal);
    private readonly TaskCompletionSource releaseOriginal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource releaseLate = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task original = Task.CompletedTask;
    private Task late = Task.CompletedTask;
    private RotationMutationRoot? root;
    private bool setup;
    private bool armed;
    private bool fenced;
    private bool lateViolation;
    private bool enabled;
    private bool borrowed = true;
    private long generation = 7;
    private int commits;
    private int queuedDeliveries;
    private string attributedAttempt = "";
    internal InfisicalRotationProfile Profile { get; }
    internal RotationMaterialKind Kind { get; }
    internal string Mode { get; }
    internal string[] NativeFields { get; }
    internal bool NativeOverlap { get; }
    internal Uri Origin { get; }
    internal HttpMessageHandler Transport { get; }
    internal InfisicalRotationMutationFixtureSource Source { get; }
    internal List<(string Attempt, string Method, bool Denied)> RequestJournal { get; } = [];
    internal List<(string Attempt, bool Enabled)> ConfigurationJournal { get; } = [];
    internal List<(string Attempt, long Generation, bool Queued)> BackendJournal { get; } = [];
    internal List<(string Attempt, long Before, long After)> SchedulerJournal { get; } = [];
    internal List<string> MappingJournal { get; } = [];
    internal List<string> ReadJournal { get; } = [];
    internal List<(bool Accepted, string Action)> AuthenticationJournal { get; } = [];
    internal List<bool> SetupAuthenticationJournal { get; } = [];
    internal List<(long Generation, bool Accepted)> CleanupAuthenticationJournal { get; } = [];
    internal List<(long Generation, bool Wrong, bool Accepted)> HistoryAuthenticationJournal { get; } = [];
    internal List<string> TerminalJournal { get; } = [];
    internal int Residual { get { lock (gate) return mapped.Count + ownedIdentities.Count + ownedResources.Count + (setup ? 1 : 0); } }
    internal bool BorrowedPreserved => borrowed;
    internal bool PrivateDestroyed => material.Count == 0;
    internal long Generation => generation;
    internal bool Enabled => enabled;
    internal int OriginalCommits => commits;
    internal int OriginalDeliveries => BackendJournal.Count(r => !r.Queued);
    internal int QueuedDeliveries => queuedDeliveries;
    internal int Pending => pending.Count;
    internal bool OriginalTerminal => original.IsCompletedSuccessfully && late.IsCompletedSuccessfully;
    internal bool ExcludesLateWork => fenced && !lateViolation && pending.Count == 0;
    internal string AttributedAttempt => attributedAttempt;
    internal long OpportunityBaseline => SchedulerJournal.Count == 0 ? generation : SchedulerJournal[^1].Before;
    internal bool HistoryComplete => material.Keys.Order().SequenceEqual(Enumerable.Range(6, checked((int)generation - 5)).Select(g => (long)g)) &&
        ProbeCaptured(generation) && !ProbeCaptured(generation, wrong: true) && ProbeCaptured(generation);
    internal bool PreviousAccepted => ProbeCaptured(generation - 1);
    internal bool OverwrittenRetired => material.Keys.Where(g => g < generation - 1).All(g => !ProbeCaptured(g)) &&
        ProbeCaptured(generation) && !ProbeCaptured(generation, wrong: true) && ProbeCaptured(generation);
    internal bool IdentityInventoryQualified => backend.Values.Where(s => s.Accepted).All(s =>
        ownedIdentities.Contains(s.Identity) && ownedResources.Contains(s.Resource)) &&
        (Profile is not (InfisicalRotationProfile.RedisCredentials or InfisicalRotationProfile.OpenaiServiceAccount) ||
            backend.Values.Where(s => !s.Accepted).All(s => !ownedIdentities.Contains(s.Identity)));

    private sealed class OwnedSet(long generation, string identity, RotationMaterialFieldInput[] fields) : IDisposable
    {
        internal long Generation { get; } = generation;
        internal string Identity { get; } = identity;
        internal RotationMaterialFieldInput[] Fields { get; } = fields;
        internal Dictionary<string, SecretMaterial> Values { get; } = fields.ToDictionary(f => f.Field,
            f => SecretMaterial.FromText(f.Value), StringComparer.Ordinal);
        public void Dispose() { foreach (var value in Values.Values) value.Dispose(); }
    }

    private sealed class BackendCredential(OwnedSet issued, string resource) : IDisposable
    {
        internal string Identity { get; } = issued.Identity;
        internal string Resource { get; } = resource;
        internal Dictionary<string, SecretMaterial> Values { get; } = issued.Values.ToDictionary(v => v.Key,
            v => v.Value.Copy(), StringComparer.Ordinal);
        internal bool Accepted { get; set; } = true;
        public void Dispose() { foreach (var value in Values.Values) value.Dispose(); }
    }

    internal InfisicalRotationMutationFixture(InfisicalRotationProfile profile, string mode = "good")
    {
        Profile = profile;
        Mode = mode;
        // This native fixture schema is independent of RotationMaterialProfile.
        NativeFields = profile switch
        {
            InfisicalRotationProfile.Auth0ClientSecret or InfisicalRotationProfile.AzureClientSecret or
                InfisicalRotationProfile.OktaClientSecret or InfisicalRotationProfile.DatabricksServicePrincipalSecret =>
                ["clientId", "clientSecret"],
            InfisicalRotationProfile.AwsIamUserSecret or InfisicalRotationProfile.CloudflareR2AccessKey =>
                ["accessKeyId", "secretAccessKey"],
            InfisicalRotationProfile.CloudflareApiToken => ["tokenId", "apiToken"],
            InfisicalRotationProfile.DatadogApiKey => ["apiKeyId", "apiKey"],
            InfisicalRotationProfile.DatadogApplicationKeySecret => ["applicationKeyId", "applicationKey"],
            InfisicalRotationProfile.ConvexAccessKey => ["accessKey"],
            InfisicalRotationProfile.DbtServiceToken => ["serviceToken"],
            InfisicalRotationProfile.FireworksApiKey or InfisicalRotationProfile.LitellmApiKey or
                InfisicalRotationProfile.OpenRouterApiKey or InfisicalRotationProfile.OpenaiServiceAccount or
                InfisicalRotationProfile.StripeApiKey or InfisicalRotationProfile.SupabaseApiKey => ["apiKey"],
            InfisicalRotationProfile.GcpServiceAccountKey => ["serviceAccountKey"],
            InfisicalRotationProfile.LdapPassword => ["dn", "password"],
            InfisicalRotationProfile.SalesforceOauthCredentials => ["consumerKey", "consumerSecret"],
            InfisicalRotationProfile.SnowflakeUserKeyPair => ["privateKey", "publicKey"],
            InfisicalRotationProfile.HpIloLocalAccount or InfisicalRotationProfile.MongodbCredentials or
                InfisicalRotationProfile.MssqlCredentials or InfisicalRotationProfile.MysqlCredentials or
                InfisicalRotationProfile.OracledbCredentials or InfisicalRotationProfile.PostgresCredentials or
                InfisicalRotationProfile.RedisCredentials or InfisicalRotationProfile.UnixLinuxLocalAccount or
                InfisicalRotationProfile.WindowsLocalAccount => ["username", "password"],
            _ => throw new InvalidOperationException("fixture-profile")
        };
        Kind = NativeFields[0] switch
        {
            "username" => RotationMaterialKind.AccountPassword,
            "dn" => RotationMaterialKind.DirectoryPassword,
            "clientId" or "consumerKey" => RotationMaterialKind.ClientSecret,
            "accessKeyId" => RotationMaterialKind.AccessKey,
            "tokenId" or "apiKeyId" or "applicationKeyId" => RotationMaterialKind.IdentifiedToken,
            "serviceAccountKey" => RotationMaterialKind.JsonKey,
            "privateKey" => RotationMaterialKind.PemKey,
            _ => RotationMaterialKind.Token
        };
        NativeOverlap = profile is not (InfisicalRotationProfile.Auth0ClientSecret or InfisicalRotationProfile.LdapPassword or
            InfisicalRotationProfile.HpIloLocalAccount or InfisicalRotationProfile.UnixLinuxLocalAccount or
            InfisicalRotationProfile.WindowsLocalAccount);
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Transport = new MutationHandler(this);
        Source = new(this);
        accept = AcceptAsync();
    }

    internal RotationMutationInput Input(bool selectedEnabled = true) => new(new("controlled-mutation",
        "rotation-mutation-source", "mutation-clock-epoch", RotationMaterialSource.ControlledFixture, Project,
        "testing", "/owned-mutation", Rotation, Profile, Kind, 7, Fields(7), "private-mutation-setup",
        ["read"], ["write"], 128, 15), selectedEnabled, 16);

    internal RotationMaterialFieldInput[] Fields(long selectedGeneration) =>
        NativeFields.Select((field, index) => new RotationMaterialFieldInput(field, "mutation-" + field,
            (selectedGeneration * 10 + index).ToString(System.Globalization.CultureInfo.InvariantCulture),
            Value(field, selectedGeneration))).ToArray();

    private string Value(string field, long g)
    {
        // The target identity in a GCP key file stays immutable. keyId is an
        // ownership coordinate inside the complete key, not another mapping.
        if (field == "serviceAccountKey")
            return JsonSerializer.Serialize(new
            {
                type = "service_account",
                project_id = "controlled-project",
                private_key_id = "owned-key-" + g,
                private_key = "controlled-private-key-" + g,
                client_email = Mode == "changed-target" && g > 7 ? "other@controlled.invalid" : "owned@controlled.invalid",
                client_id = "owned-service-account",
                auth_uri = "https://auth.invalid/",
                token_uri = "https://token.invalid/",
                auth_provider_x509_cert_url = "https://cert.invalid/",
                client_x509_cert_url = "https://cert.invalid/owned"
            });
        if (field == "privateKey") return "-----BEGIN PRIVATE KEY-----\ncontrolled-" + g + "\n-----END PRIVATE KEY-----";
        if (field == "publicKey") return "-----BEGIN PUBLIC KEY-----\ncontrolled-" + g + "\n-----END PUBLIC KEY-----";
        if (field == "dn") return "cn=owned,dc=controlled";
        if (field is "clientId" or "consumerKey") return "owned-client";
        if (field == "username")
            return Profile is InfisicalRotationProfile.MongodbCredentials or InfisicalRotationProfile.MssqlCredentials or
                InfisicalRotationProfile.MysqlCredentials or InfisicalRotationProfile.OracledbCredentials or
                InfisicalRotationProfile.PostgresCredentials ? "owned-account-" + g % 2 :
                Profile == InfisicalRotationProfile.RedisCredentials ? "owned-user-" + g : "owned-account";
        return Profile + "-" + field + "-generation-" + g;
    }

    private string Identity(long g) => Profile switch
    {
        InfisicalRotationProfile.MongodbCredentials or InfisicalRotationProfile.MssqlCredentials or
            InfisicalRotationProfile.MysqlCredentials or InfisicalRotationProfile.OracledbCredentials or
            InfisicalRotationProfile.PostgresCredentials => "existing-account-" + g % 2,
        InfisicalRotationProfile.RedisCredentials or InfisicalRotationProfile.OpenaiServiceAccount => "created-identity-" + g,
        _ => "selected-existing-identity"
    };

    internal void Provision(RotationMutationRoot originalRoot, JsonElement baseline, string capability)
    {
        lock (gate)
        {
            root = originalRoot; // Retain original cleanup root before any setup.
            var r = root.Material;
            Need(!setup && capability == "private-mutation-setup" && r.Profile == Profile && r.Kind == Kind &&
                r.ProjectId == Project && r.RotationId == Rotation && r.Environment == "testing" &&
                r.Folder == "/owned-mutation" && r.Generation == 7 &&
                r.DeploymentId == "controlled-mutation" && r.SourceIdentity == "rotation-mutation-source" &&
                r.ClockEpoch == "mutation-clock-epoch" && r.ProviderVersion == "v0.166.3" &&
                r.Source == RotationMaterialSource.ControlledFixture);
            AddSet(6);
            AddSet(7);
            backend[6].Accepted = NativeOverlap;
            Need(Exact(baseline, 7), "effect-mismatch");
            SetupAuthenticationJournal.Add(OwnerAuthenticate(capability));
            SetupAuthenticationJournal.Add(OwnerAuthenticate("wrong-private-mutation-setup"));
            SetupAuthenticationJournal.Add(OwnerAuthenticate(capability));
            setup = true;
            enabled = root.Action == InfisicalRotationAction.DisableAutomaticRotation;
            ownedResources.Add("selected-backend-resource");
            Publish(7);
        }
    }

    private void AddSet(long g)
    {
        material.Add(g, new(g, Identity(g), Fields(g)));
        string resource = Kind is RotationMaterialKind.AccountPassword or RotationMaterialKind.DirectoryPassword &&
            Profile != InfisicalRotationProfile.RedisCredentials ? "selected-backend-resource" : "credential-resource-" + g;
        backend.Add(g, new(material[g], resource));
        ownedResources.Add(resource);
        ownedIdentities.Add(Identity(g));
    }

    private void Publish(long g)
    {
        foreach (var value in mapped.Values) value.Material.Dispose();
        mapped.Clear();
        foreach (var field in material[g].Fields)
            mapped.Add(field.Destination, (material[g].Values[field.Field].Copy(), int.Parse(field.Version)));
        MappingJournal.Add(root!.AttemptId + "/" + g);
    }

    internal void Arm(RotationMutationRoot originalRoot)
    {
        lock (gate) { Need(root == originalRoot && !armed && !fenced); armed = true; }
    }

    private void Change(string attempt, bool queued = false)
    {
        lock (gate)
        {
            if (fenced) lateViolation = true;
            generation++;
            AddSet(generation);
            foreach (var set in backend)
                set.Value.Accepted = set.Key == generation || NativeOverlap && set.Key == generation - 1 ||
                    Mode == "retained-overwritten" && set.Key == 6;
            foreach (var retired in backend.Values.Where(s => !s.Accepted))
            {
                if (Profile is InfisicalRotationProfile.RedisCredentials or InfisicalRotationProfile.OpenaiServiceAccount)
                    ownedIdentities.Remove(retired.Identity);
                if (retired.Resource != "selected-backend-resource") ownedResources.Remove(retired.Resource);
            }
            Publish(generation);
            BackendJournal.Add((attempt, generation, queued));
            attributedAttempt = Mode == "unrelated-event" ? "unrelated-attempt" : attempt;
            if (queued) queuedDeliveries++;
        }
    }

    internal bool Exact(JsonElement packet, long g)
    {
        if (packet.GetProperty("profile").GetInt32() != (int)Profile ||
            packet.GetProperty("kind").GetInt32() != (int)Kind ||
            packet.GetProperty("generation").GetInt64() != g || !material.TryGetValue(g, out var set)) return false;
        var fields = packet.GetProperty("fields").EnumerateArray().ToArray();
        return fields.Length == NativeFields.Length && fields.Select((f, i) =>
            f.GetProperty("field").GetString() == set.Fields[i].Field &&
            f.GetProperty("destination").GetString() == set.Fields[i].Destination &&
            f.GetProperty("version").GetString() == set.Fields[i].Version &&
            Equal(set.Values[set.Fields[i].Field], f.GetProperty("value").GetString()!)).All(v => v);
    }

    internal bool Authenticate(JsonElement packet, bool wrong, string action = "")
    {
        lock (gate)
        {
            var fields = packet.GetProperty("fields").EnumerateArray().ToArray();
            bool accepted = backend.Values.Any(set => set.Accepted && ownedIdentities.Contains(set.Identity) &&
                ownedResources.Contains(set.Resource) &&
                fields.Length == set.Values.Count &&
                fields.All(f => set.Values.TryGetValue(f.GetProperty("field").GetString()!, out var value) &&
                    Equal(value, f.GetProperty("value").GetString()!)));
            if (Mode == "wrong-accepted" && wrong) accepted = true;
            if (Mode == "valid-outage" && !wrong) accepted = false;
            if (action.Length != 0) accepted &= action == "read" || Mode == "overbroad-grants";
            AuthenticationJournal.Add((accepted, action));
            return accepted;
        }
    }

    private bool ProbeCaptured(long g, bool wrong = false)
    {
        var supplied = material[g];
        bool accepted = backend.Values.Any(candidate => candidate.Accepted &&
            ownedIdentities.Contains(candidate.Identity) && ownedResources.Contains(candidate.Resource) &&
            SuppliedMatches(candidate, supplied, wrong));
        if (Mode == "wrong-accepted" && wrong) accepted = true;
        if (Mode == "valid-outage" && !wrong) accepted = false;
        HistoryAuthenticationJournal.Add((g, wrong, accepted));
        return accepted;
    }

    private bool SuppliedMatches(BackendCredential candidate, OwnedSet supplied, bool wrong)
    {
        int contrast = Kind == RotationMaterialKind.PemKey ? 0 : NativeFields.Length - 1;
        for (int i = 0; i < NativeFields.Length; ++i)
        {
            string field = NativeFields[i];
            if (!candidate.Values.TryGetValue(field, out var expected)) return false;
            char[] actual = supplied.Values[field].ExportCharacters();
            char[] wanted = [];
            try
            {
                if (wrong && i == contrast) actual[0] = actual[0] == '!' ? '?' : '!';
                wanted = expected.ExportCharacters();
                if (!actual.AsSpan().SequenceEqual(wanted)) return false;
            }
            finally { Array.Clear(actual); Array.Clear(wanted); }
        }
        return true;
    }

    internal async ValueTask SettleOriginalAsync(RotationMutationRoot originalRoot, CancellationToken token)
    {
        Need(root == originalRoot);
        releaseOriginal.TrySetResult();
        await original.WaitAsync(token);
        lock (gate)
        {
            if ((Mode == "queued-after-disable" && commits == 1 || Mode == "unknown-nonapplied-queued") &&
                root!.Action == InfisicalRotationAction.DisableAutomaticRotation)
                Change("preexisting-queue", queued: true);
            if (commits == 1 && root!.Action != InfisicalRotationAction.RotateSecrets)
            {
                long before = generation;
                // An explicitly injected opportunity, not native time acceleration
                // or a public manual SDK call substituted for scheduled work.
                if (enabled && Mode is not ("no-backend-change" or "no-opportunity")) Change(root.AttemptId);
                if (Mode != "no-opportunity") SchedulerJournal.Add((root.AttemptId, before, generation));
                attributedAttempt = Mode == "unrelated-event" ? "unrelated-attempt" : root.AttemptId;
            }
            fenced = true;
            TerminalJournal.Add(originalRoot.AttemptId);
        }
    }

    internal async ValueTask<RotationMutationCleanup> CleanupAsync(RotationMutationRoot originalRoot, CancellationToken token)
    {
        Need(root == originalRoot, "cleanup-incomplete");
        releaseOriginal.TrySetResult();
        releaseLate.TrySetResult();
        await Task.WhenAll(original, late).WaitAsync(token);
        lock (gate)
        {
            fenced = true;
            foreach (var value in mapped.Values) value.Material.Dispose();
            mapped.Clear();
            setup = false;
            bool incomplete = Mode == "incomplete-cleanup";
            if (!incomplete)
            {
                foreach (var credential in backend.Values) credential.Dispose();
                backend.Clear();
                ownedIdentities.Clear();
                ownedResources.Clear();
            }
            if (Mode == "borrowed-damage") borrowed = false;
            // Fresh acceptance probes use every captured supplied set, against
            // backend state independent of the now-removed rotation/mapping.
            foreach (var set in material.Values)
                CleanupAuthenticationJournal.Add((set.Generation, backend.Values.Any(b => b.Accepted &&
                    ownedIdentities.Contains(b.Identity) && ownedResources.Contains(b.Resource) &&
                    set.Values.All(v => b.Values.TryGetValue(v.Key, out var supplied) &&
                        Same(supplied, v.Value)))));
            bool retired = CleanupAuthenticationJournal.All(p => !p.Accepted) &&
                OwnerAuthenticate("private-mutation-setup") && !OwnerAuthenticate("wrong-private-mutation-setup") &&
                OwnerAuthenticate("private-mutation-setup");
            foreach (var set in material.Values) set.Dispose();
            material.Clear();
            return new(originalRoot, OriginalTerminal, ExcludesLateWork, Mode != "incomplete-inventory",
                retired, ownedIdentities.Count == 0, ownedResources.Count == 0, !setup,
                mapped.Count == 0, borrowed, PrivateDestroyed, 0,
                Mode == "pending-delivery" ? 1 : pending.Count, Mode == "pending-work" ? 1 : 0);
        }
    }

    internal InfisicalClient Consumer(NativeEnvironment env, NativeIdentityRole role) =>
        new(Origin, env.Tokens(role), new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });

    private sealed class MutationHandler(InfisicalRotationMutationFixture fixture) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            string wire = string.Concat(fixture.Profile.ToString().Select((c, i) =>
                char.IsUpper(c) && i != 0 ? "-" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
            string expected = "/api/v2/secret-rotations/" + wire + "/" + Rotation;
            bool manual = fixture.root!.Action == InfisicalRotationAction.RotateSecrets;
            Need(fixture.armed && !fixture.fenced &&
                request.RequestUri!.AbsolutePath == expected + (manual ? "/rotate-secrets" : "") &&
                request.Method == (manual ? HttpMethod.Post : HttpMethod.Patch));
            bool selected = fixture.root.Action == InfisicalRotationAction.EnableAutomaticRotation;
            if (!manual)
            {
                byte[] body = await request.Content!.ReadAsByteArrayAsync(token);
                try
                {
                    using var document = JsonDocument.Parse(body);
                    Need(document.RootElement.GetProperty("isAutoRotationEnabled").GetBoolean() == selected);
                }
                finally { CryptographicOperations.ZeroMemory(body); }
            }
            bool denied = request.Headers.Authorization?.Parameter == "denied";
            lock (fixture.gate)
            {
                fixture.RequestJournal.Add((fixture.root.AttemptId, request.Method.Method, denied));
                if (!denied && fixture.Mode is not ("unknown-nonapplied" or "unknown-nonapplied-queued"))
                {
                    if (fixture.Mode != "unknown-partial") fixture.commits++;
                    if (!manual)
                    {
                        if (fixture.Mode != "ignored-setting") fixture.enabled = selected;
                        fixture.ConfigurationJournal.Add((fixture.root.AttemptId, fixture.enabled));
                    }
                    else if (fixture.Mode != "no-backend-change")
                    {
                        if (fixture.Mode == "deferred-original")
                        {
                            fixture.pending.Add("original-delivery", fixture.root.AttemptId);
                            fixture.original = DeliverOriginal(fixture);
                        }
                        else fixture.Change(fixture.root.AttemptId);
                        if (fixture.Mode == "replay") fixture.Change(fixture.root.AttemptId);
                        if (fixture.Mode == "late-work")
                        {
                            fixture.pending.Add("late-delivery", fixture.root.AttemptId);
                            fixture.late = DeliverLate(fixture);
                        }
                    }
                }
            }
            if (denied) return new(HttpStatusCode.Forbidden) { Content = new StringContent("{}") };
            var projection = new
            {
                id = Rotation,
                projectId = Project,
                type = wire,
                environment = new { slug = "testing" },
                folder = new { path = "/owned-mutation" },
                rotationStatus = "success",
                isAutoRotationEnabled = manual ? fixture.enabled : selected,
                lastRotationAttemptedAt = Clock,
                lastRotatedAt = Clock,
                nextRotationAt = (string?)null
            };
            return new(HttpStatusCode.OK)
            { Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(new { secretRotation = projection })) };
        }

        private static async Task DeliverOriginal(InfisicalRotationMutationFixture fixture)
        {
            await fixture.releaseOriginal.Task;
            fixture.Change(fixture.root!.AttemptId);
            lock (fixture.gate) fixture.pending.Remove("original-delivery");
        }
        private static async Task DeliverLate(InfisicalRotationMutationFixture fixture)
        {
            await fixture.releaseLate.Task;
            fixture.Change(fixture.root!.AttemptId);
            lock (fixture.gate) fixture.pending.Remove("late-delivery");
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
            byte[] response = [];
            try
            {
                var stream = socket.GetStream();
                var bytes = new List<byte>();
                byte[] one = new byte[1];
                while (bytes.Count < 32768)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    bytes.Add(one[0]);
                    if (bytes.Count >= 4 && bytes.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                }
                string[] headers = Encoding.ASCII.GetString(bytes.ToArray()).Split("\r\n");
                string role = headers.FirstOrDefault(h => h.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                    .Split(' ').Last() ?? "";
                string destination = Uri.UnescapeDataString(new Uri(Origin, headers[0].Split(' ')[1]).AbsolutePath.Split('/').Last());
                object payload = new { };
                int status = 404;
                lock (gate)
                {
                    if (mapped.TryGetValue(destination, out var selected))
                    {
                        ReadJournal.Add(role + "/" + destination);
                        status = role == "denied" && Mode != "denied-material-accepted" ? 403 : 200;
                        string value = selected.Material.Reveal();
                        if (Mode == "wrong-material" && role == "runtime") value = "wrong-" + value;
                        int version = selected.Version + (Mode == "mixed-generation" && destination == "mutation-" + NativeFields[^1] ? 1 : 0);
                        payload = new { secret = new { secretKey = destination, secretValue = value, secretValueHidden = false, version } };
                    }
                }
                response = JsonSerializer.SerializeToUtf8Bytes(payload);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"),
                    shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally { CryptographicOperations.ZeroMemory(response); }
        }
    }

    private static bool Equal(SecretMaterial material, string value)
    {
        char[] chars = material.ExportCharacters();
        try { return chars.AsSpan().SequenceEqual(value.AsSpan()); }
        finally { Array.Clear(chars); }
    }
    private static bool Same(SecretMaterial left, SecretMaterial right)
    {
        char[] a = left.ExportCharacters();
        char[] b = [];
        try { b = right.ExportCharacters(); return a.AsSpan().SequenceEqual(b); }
        finally { Array.Clear(a); Array.Clear(b); }
    }
    private bool OwnerAuthenticate(string capability) => borrowed && capability == "private-mutation-setup";
    private static void Need(bool condition, string code = "observer-unavailable") => RotationMaterialTrial.Require(condition, code);

    public async ValueTask DisposeAsync()
    {
        releaseOriginal.TrySetResult();
        releaseLate.TrySetResult();
        await Task.WhenAll(original, late);
        await shutdown.CancelAsync();
        listener.Stop();
        await accept;
        await Task.WhenAll(connections);
        foreach (var set in material.Values) set.Dispose();
        foreach (var credential in backend.Values) credential.Dispose();
        foreach (var value in mapped.Values) value.Material.Dispose();
        Source.Dispose();
        Transport.Dispose();
        shutdown.Dispose();
    }
}
