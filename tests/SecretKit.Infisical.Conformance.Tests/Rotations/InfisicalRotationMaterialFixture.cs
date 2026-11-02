using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// An independent executable authoring provider, never native qualification.
// The SDK sees only metadata and mapped secrets. Source/private material, secret
// storage, backend authentication, setup/read windows and terminal inventories
// are separate journals; no returned metadata creates backend state.
internal sealed class InfisicalRotationMaterialFixture : IAsyncDisposable
{
    internal const string Project = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    internal const string Rotation = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    internal static readonly DateTimeOffset Clock = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    internal static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    { IgnoreReadOnlyProperties = false };
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<string, SecretMaterial> materialJournal = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (SecretMaterial Value, int Version)> secretJournal = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SecretMaterial> backendJournal = new(StringComparer.Ordinal);
    private readonly object gate = new();
    private bool setupExists;
    private bool backendExists;
    private long generation = 7;
    private long configurationRevision = 1;
    private long mappingRevision = 1;
    internal InfisicalRotationProfile Profile { get; }
    internal RotationMaterialKind MaterialKind { get; }
    internal string Mode { get; }
    internal Uri Origin { get; }
    internal List<string> SetupJournal { get; } = [];
    internal List<string> ReadJournal { get; } = [];
    internal List<(bool Accepted, string Action)> AuthenticationJournal { get; } = [];
    internal List<(string Root, int Secrets, int Resources, bool Borrowed)> TerminalJournal { get; } = [];
    internal bool BorrowedPreserved { get; private set; } = true;
    internal int Residual { get { lock (gate) return (setupExists ? 1 : 0) + secretJournal.Count + (backendExists ? 1 : 0); } }
    internal long Generation { get { lock (gate) return generation; } }
    internal long ConfigurationRevision { get { lock (gate) return configurationRevision; } }
    internal long MappingRevision { get { lock (gate) return mappingRevision; } }
    internal bool PrivateDestroyed { get { lock (gate) return materialJournal.Count == 0; } }
    internal int MappedCount { get { lock (gate) return secretJournal.Count; } }
    internal int MetadataReads { get; private set; }
    internal RotationMaterialFieldInput[] Fields { get; }
    internal InfisicalRotationMaterialFixtureSource Source { get; }
    internal HttpMessageHandler MetadataTransport { get; }

    internal InfisicalRotationMaterialFixture(InfisicalRotationProfile profile, string mode = "good")
    {
        Profile = profile;
        Mode = mode;
        // Independent native fixture schema: do not derive native storage from
        // the packet contract being calibrated.
        string[] nativeFields = profile switch
        {
            InfisicalRotationProfile.Auth0ClientSecret or InfisicalRotationProfile.AzureClientSecret or
                InfisicalRotationProfile.OktaClientSecret or InfisicalRotationProfile.DatabricksServicePrincipalSecret =>
                ["clientId", "clientSecret"],
            InfisicalRotationProfile.AwsIamUserSecret or InfisicalRotationProfile.CloudflareR2AccessKey =>
                ["accessKeyId", "secretAccessKey"],
            InfisicalRotationProfile.CloudflareApiToken => ["tokenId", "apiToken"],
            InfisicalRotationProfile.ConvexAccessKey => ["accessKey"],
            InfisicalRotationProfile.DatadogApiKey => ["apiKeyId", "apiKey"],
            InfisicalRotationProfile.DatadogApplicationKeySecret => ["applicationKeyId", "applicationKey"],
            InfisicalRotationProfile.DbtServiceToken => ["serviceToken"],
            InfisicalRotationProfile.FireworksApiKey or InfisicalRotationProfile.LitellmApiKey or
                InfisicalRotationProfile.OpenRouterApiKey or InfisicalRotationProfile.OpenaiServiceAccount or
                InfisicalRotationProfile.StripeApiKey or InfisicalRotationProfile.SupabaseApiKey => ["apiKey"],
            InfisicalRotationProfile.LdapPassword => ["dn", "password"],
            InfisicalRotationProfile.SalesforceOauthCredentials => ["consumerKey", "consumerSecret"],
            InfisicalRotationProfile.SnowflakeUserKeyPair => ["privateKey", "publicKey"],
            InfisicalRotationProfile.GcpServiceAccountKey => ["serviceAccountKey"],
            InfisicalRotationProfile.HpIloLocalAccount or InfisicalRotationProfile.MongodbCredentials or
                InfisicalRotationProfile.MssqlCredentials or InfisicalRotationProfile.MysqlCredentials or
                InfisicalRotationProfile.OracledbCredentials or InfisicalRotationProfile.PostgresCredentials or
                InfisicalRotationProfile.RedisCredentials or InfisicalRotationProfile.UnixLinuxLocalAccount or
                InfisicalRotationProfile.WindowsLocalAccount => ["username", "password"],
            _ => throw new InvalidOperationException("fixture-profile")
        };
        MaterialKind = nativeFields.FirstOrDefault() switch
        {
            "username" => RotationMaterialKind.AccountPassword,
            "dn" => RotationMaterialKind.DirectoryPassword,
            "clientId" or "consumerKey" => RotationMaterialKind.ClientSecret,
            "accessKeyId" => RotationMaterialKind.AccessKey,
            "tokenId" or "apiKeyId" or "applicationKeyId" => RotationMaterialKind.IdentifiedToken,
            "privateKey" => RotationMaterialKind.PemKey,
            "serviceAccountKey" => RotationMaterialKind.JsonKey,
            _ => RotationMaterialKind.Token
        };
        Fields = nativeFields.Select((field, index) => new RotationMaterialFieldInput(field,
            "owned-" + field, (index + 11).ToString(System.Globalization.CultureInfo.InvariantCulture),
            field == "serviceAccountKey" ?
                "{\"type\":\"service_account\",\"private_key_id\":\"controlled-key-id\",\"private_key\":\"controlled-key\",\"client_email\":\"owned@example.invalid\"}" :
                profile + "-" + field + "-protected-material")).ToArray();
        // Independent protected/native input journal exists before source Open.
        foreach (var field in Fields) materialJournal.Add(field.Field, SecretMaterial.FromText(field.Value));
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        MetadataTransport = new MetadataHandler(this);
        Source = new(this);
        accept = AcceptAsync();
    }

    internal RotationMaterialInput Input() => new("controlled-rotation", "rotation-material-source",
        "rotation-clock-epoch", RotationMaterialSource.ControlledFixture, Project, "testing", "/owned-material",
        Rotation, Profile, MaterialKind, 7, Fields, "private-setup-capability",
        ["read"], ["write"], 128, 15);

    internal void Provision(RotationMaterialRoot root, JsonElement material, string capability)
    {
        lock (gate)
        {
            RotationMaterialTrial.Require(!setupExists && capability == "private-setup-capability");
            RotationMaterialTrial.Require(Exact(material), "effect-mismatch");
            setupExists = true;
            backendExists = true;
            foreach (var field in Fields)
            {
                secretJournal.Add(field.Destination, (materialJournal[field.Field].Copy(), int.Parse(field.Version)));
                backendJournal.Add(field.Field, materialJournal[field.Field].Copy());
            }
            SetupJournal.Add(root.Id); // Owned never-enabled setup settles here.
        }
    }

    internal bool Exact(JsonElement packet)
    {
        if (!packet.TryGetProperty("profile", out var profile) || profile.GetInt32() != (int)Profile ||
            packet.GetProperty("kind").GetInt32() != (int)MaterialKind ||
            packet.GetProperty("generation").GetInt64() != generation) return false;
        var fields = packet.GetProperty("fields").EnumerateArray().ToArray();
        return fields.Length == Fields.Length && fields.Select((field, i) =>
            field.GetProperty("field").GetString() == Fields[i].Field &&
            field.GetProperty("destination").GetString() == Fields[i].Destination &&
            field.GetProperty("version").GetString() == Fields[i].Version &&
            Equal(materialJournal[Fields[i].Field], field.GetProperty("value").GetString()!)).All(v => v);
    }

    internal bool BackendAuthenticate(JsonElement packet, bool wrong, string action = "")
    {
        lock (gate)
        {
            bool accepted = backendExists;
            var fields = packet.GetProperty("fields").EnumerateArray().ToArray();
            accepted &= fields.Length == backendJournal.Count && fields.All(field =>
                backendJournal.TryGetValue(field.GetProperty("field").GetString()!, out var value) &&
                Equal(value, field.GetProperty("value").GetString()!));
            if (Mode == "wrong-accepted" && wrong) accepted = true;
            if (Mode == "valid-outage" && !wrong) accepted = false;
            if (action.Length != 0) accepted &= action == "read" || Mode == "overbroad-grants";
            AuthenticationJournal.Add((accepted, action));
            return accepted;
        }
    }

    internal (bool Setup, bool Secrets, bool Backend, bool Retired) Cleanup(RotationMaterialRoot root)
    {
        lock (gate)
        {
            setupExists = false;
            foreach (var secret in secretJournal.Values) secret.Value.Dispose();
            secretJournal.Clear();
            bool incomplete = Mode == "incomplete-cleanup";
            if (!incomplete)
            {
                foreach (var value in backendJournal.Values) value.Dispose();
                backendJournal.Clear();
                backendExists = false;
            }
            if (Mode == "borrowed-damage") BorrowedPreserved = false;
            TerminalJournal.Add((root.Id, secretJournal.Count, backendJournal.Count, BorrowedPreserved));
            foreach (var material in materialJournal.Values) material.Dispose();
            materialJournal.Clear();
            return (!setupExists, secretJournal.Count == 0, !backendExists, backendJournal.Count == 0);
        }
    }

    internal InfisicalClient Consumer(NativeEnvironment environment, NativeIdentityRole role) =>
        new(Origin, environment.Tokens(role), new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });

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
            byte[] responseBytes = [];
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
                string path = new Uri(Origin, headers[0].Split(' ')[1]).AbsolutePath;
                string destination = Uri.UnescapeDataString(path.Split('/').Last());
                object payload = new { };
                int status = 404;
                lock (gate)
                {
                    if (path.StartsWith("/api/v4/secrets/", StringComparison.Ordinal) &&
                        secretJournal.TryGetValue(destination, out var secret))
                    {
                        ReadJournal.Add(role + "/" + destination);
                        status = role == "denied" && Mode != "denied-material-accepted" ? 403 : 200;
                        string value = secret.Value.Reveal();
                        if (Mode == "wrong-material" && role == "runtime") value = "wrong-" + value;
                        int version = secret.Version + (Mode == "mixed-generation" && destination == Fields[^1].Destination ? 1 : 0);
                        payload = new
                        {
                            secret = new
                            {
                                secretKey = destination,
                                secretValue = value,
                                secretValueHidden = false,
                                version
                            }
                        };
                    }
                }
                responseBytes = JsonSerializer.SerializeToUtf8Bytes(payload);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {responseBytes.Length}\r\nConnection: close\r\n\r\n"),
                    shutdown.Token);
                await stream.WriteAsync(responseBytes, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally { CryptographicOperations.ZeroMemory(responseBytes); }
        }
    }

    private sealed class MetadataHandler(InfisicalRotationMaterialFixture owner) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (owner.gate)
            {
                RotationMaterialTrial.Require(request.Method == HttpMethod.Get && owner.setupExists);
                owner.MetadataReads++;
                if (owner.Mode == "read-mutation") owner.generation++;
                if (owner.Mode == "configuration-mutation") owner.configurationRevision++;
                if (owner.Mode == "mapping-mutation") owner.mappingRevision++;
                if (request.Headers.Authorization?.Parameter == "denied")
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent("{}") });
                string wire = string.Concat(owner.Profile.ToString().Select((c, i) =>
                    char.IsUpper(c) && i != 0 ? "-" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
                object projection = new
                {
                    id = Rotation,
                    projectId = Project,
                    type = wire,
                    environment = new { slug = "testing" },
                    folder = new { path = "/owned-material" },
                    rotationStatus = "success",
                    isAutoRotationEnabled = false,
                    lastRotationAttemptedAt = Clock,
                    lastRotatedAt = Clock,
                    nextRotationAt = (string?)null
                };
                object payload = request.RequestUri!.AbsolutePath.EndsWith("/" + Rotation, StringComparison.Ordinal) ?
                    new { secretRotation = projection } : new { secretRotations = new[] { projection } };
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(payload)) });
            }
        }
    }

    private static bool Equal(SecretMaterial material, string value)
    {
        char[] chars = material.ExportCharacters();
        try { return chars.AsSpan().SequenceEqual(value.AsSpan()); }
        finally { Array.Clear(chars); }
    }

    public async ValueTask DisposeAsync()
    {
        await shutdown.CancelAsync();
        listener.Stop();
        await accept;
        await Task.WhenAll(connections);
        foreach (var value in materialJournal.Values) value.Dispose();
        foreach (var value in backendJournal.Values) value.Dispose();
        foreach (var value in secretJournal.Values) value.Value.Dispose();
        Source.Dispose();
        MetadataTransport.Dispose();
        shutdown.Dispose();
    }
}
