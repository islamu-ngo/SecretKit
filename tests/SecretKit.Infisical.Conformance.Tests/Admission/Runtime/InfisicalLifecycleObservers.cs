using System.Buffers;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// This is a client for a separately operated fixture service, not a provider
// transport replacement. No configuration or service acknowledgement qualifies
// an effect; the family still checks the returned measurements.
internal sealed class InfisicalLifecycleObservers :
    IInfisicalDynamicBackendObserver, IInfisicalDynamicUsernameObserver,
    IInfisicalSessionLifetimeObserver, IInfisicalRotationBackendObserver, IInfisicalRotationCredentialObserver,
    IInfisicalRotationIdentityCatalogObserver
{
    private readonly Settings settings;
    private readonly HttpMessageHandler? transport;
    private readonly Func<int, byte[]> allocate;
    private readonly InfisicalPostgresRoleCatalog? roleCatalog;
    private readonly InfisicalMysqlIdentityCatalog? mysqlCatalog;
    private readonly InfisicalMssqlIdentityCatalog? mssqlCatalog;
    private readonly InfisicalMysqlConsumerAuthentication? mysqlConsumerAuthentication;
    private readonly InfisicalPostgresConsumerAuthentication? postgresConsumerAuthentication;

    internal sealed record Settings(Uri Endpoint, string Token, string Identity, int TimeoutSeconds)
    {
        public override string ToString() => "[LifecycleObserverSettings]";
    }

    internal InfisicalLifecycleObservers(Settings settings, HttpMessageHandler? transport = null,
        Func<int, byte[]>? allocate = null, InfisicalPostgresRoleCatalog? roleCatalog = null,
        InfisicalMysqlIdentityCatalog? mysqlCatalog = null, InfisicalMssqlIdentityCatalog? mssqlCatalog = null,
        InfisicalMysqlConsumerAuthentication? mysqlConsumerAuthentication = null,
        InfisicalPostgresConsumerAuthentication? postgresConsumerAuthentication = null)
    {
        if (!settings.Endpoint.IsAbsoluteUri || settings.Endpoint.Scheme != Uri.UriSchemeHttps ||
            settings.Endpoint.UserInfo.Length != 0 || settings.Endpoint.Query.Length != 0 ||
            settings.Endpoint.Fragment.Length != 0 || !settings.Endpoint.AbsolutePath.EndsWith('/') ||
            settings.Token.Length is 0 or > 16384 || settings.Token.Any(char.IsControl) ||
            settings.Identity.Length is 0 or > 128 || settings.Identity.Any(char.IsControl) ||
            settings.TimeoutSeconds is < 1 or > 300)
            throw new NativeCaseFailureException("missing-input");
        this.settings = settings;
        this.transport = transport;
        this.allocate = allocate ?? (static length => new byte[length]);
        this.roleCatalog = roleCatalog;
        this.mysqlCatalog = mysqlCatalog;
        this.mssqlCatalog = mssqlCatalog;
        this.mysqlConsumerAuthentication = mysqlConsumerAuthentication;
        this.postgresConsumerAuthentication = postgresConsumerAuthentication;
    }

    internal static InfisicalLifecycleObservers? FromInputs(NativeEnvironment environment, string family,
        HttpMessageHandler? transport = null, InfisicalPostgresRoleCatalog.QueryProcess? process = null,
        InfisicalMysqlIdentityCatalog.QueryProcess? mysqlProcess = null,
        InfisicalMssqlIdentityCatalog.QueryProcess? mssqlProcess = null,
        InfisicalMysqlConsumerAuthentication.AuthenticationProcess? mysqlAuthenticationProcess = null,
        InfisicalPostgresConsumerAuthentication.AuthenticationProcess? postgresAuthenticationProcess = null)
    {
        JsonElement input = environment.RequireFamilyInput(family);
        bool native = input.TryGetProperty("postgresRoleCatalog", out JsonElement catalog);
        bool mysql = input.TryGetProperty("mysqlIdentityCatalog", out JsonElement mysqlInput);
        bool mssql = input.TryGetProperty("mssqlIdentityCatalog", out JsonElement mssqlInput);
        bool mysqlAuthentication = input.TryGetProperty("mysqlConsumerAuthentication", out JsonElement authenticationInput);
        bool postgresAuthentication = input.TryGetProperty("postgresConsumerAuthentication", out JsonElement postgresAuthenticationInput);
        if (!input.TryGetProperty("observer", out JsonElement observer))
        {
            if (native || mysql || mssql || mysqlAuthentication || postgresAuthentication)
                throw new NativeCaseFailureException("missing-input");
            return null;
        }
        try
        {
            Settings settings = observer.Deserialize<Settings>(InfisicalLifecycleFamilies.Options)
                ?? throw new NativeCaseFailureException("missing-input");
            return new(settings, transport, roleCatalog: native ? new(catalog, process) : null,
                mysqlCatalog: mysql ? new(mysqlInput, mysqlProcess) : null,
                mssqlCatalog: mssql ? new(mssqlInput, mssqlProcess) : null,
                mysqlConsumerAuthentication: mysqlAuthentication ? new(authenticationInput, mysqlAuthenticationProcess) : null,
                postgresConsumerAuthentication: postgresAuthentication ? new(postgresAuthenticationInput, postgresAuthenticationProcess) : null);
        }
        catch (JsonException) { throw new NativeCaseFailureException("missing-input"); }
    }

    public ValueTask<DynamicBackendFacts> MeasureAsync(DynamicBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token) =>
        PostAsync<DynamicBackendFacts>("dynamic/measure", writer =>
        {
            Write(writer, "coordinate", coordinate);
            writer.WriteString("username", username.Reveal());
            writer.WriteString("password", password.Reveal());
        }, token);

    public async ValueTask<DynamicUsernameFacts> InspectUsernamesAsync(DynamicUsernameCoordinate coordinate,
        IReadOnlyList<string> usernames, CancellationToken token)
    {
        if (roleCatalog is not null)
            return await roleCatalog.InspectUsernamesAsync(coordinate, usernames, token).ConfigureAwait(false);
        DynamicUsernameFacts facts = await PostAsync<DynamicUsernameFacts>("dynamic/usernames", writer =>
        {
            Write(writer, "coordinate", coordinate);
            Write(writer, "usernames", usernames);
        }, token);
        if (facts.Coordinate != coordinate || !facts.IsComplete ||
            facts.RequestedUsernames is null || !facts.RequestedUsernames.SequenceEqual(usernames) ||
            facts.ExistingUsernames is null ||
            facts.ExistingUsernames.Distinct(StringComparer.Ordinal).Count() != facts.ExistingUsernames.Length ||
            facts.ExistingUsernames.Any(name => !usernames.Contains(name, StringComparer.Ordinal)))
            throw new NativeCaseFailureException("observer-unavailable");
        return facts;
    }

    public ValueTask<SessionLifetimeFacts> MeasureAsync(SecretMaterial token, CancellationToken cancellationToken) =>
        PostAsync<SessionLifetimeFacts>("session/measure", writer =>
            writer.WriteString("token", token.Reveal()), cancellationToken);

    public async ValueTask ExpiredAsync(SecretMaterial token, InfisicalTokenLifetimeEvidence previous,
        CancellationToken cancellationToken)
    {
        Expiry facts = await PostAsync<Expiry>("session/expired", writer =>
        {
            writer.WriteString("token", token.Reveal());
            Write(writer, "previous", previous);
        }, cancellationToken);
        if (facts.Authentication != BackendAuthentication.Rejected || facts.ExpiresAt != previous.ExpiresAt ||
            facts.ExpiresAt > DateTimeOffset.UtcNow)
            throw new NativeCaseFailureException("effect-mismatch");
    }

    public ValueTask<RotationBackendFacts> MeasureAsync(RotationBackendCoordinate coordinate, CancellationToken token) =>
        PostAsync<RotationBackendFacts>("rotation/measure", writer => Write(writer, "coordinate", coordinate), token);

    public async ValueTask<RotationIdentityCatalogFacts> InspectIdentityCatalogAsync(RotationBackendCoordinate coordinate,
        IReadOnlyList<string> usernames, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (coordinate is null) throw new NativeCaseFailureException("observer-unavailable");
        if (coordinate.Profile == InfisicalRotationProfile.MysqlCredentials && mysqlCatalog is not null)
            return await mysqlCatalog.InspectIdentityCatalogAsync(coordinate, usernames, token).ConfigureAwait(false);
        if (coordinate.Profile == InfisicalRotationProfile.MssqlCredentials && mssqlCatalog is not null)
            return await mssqlCatalog.InspectIdentityCatalogAsync(coordinate, usernames, token).ConfigureAwait(false);
        if (mysqlCatalog is not null || mssqlCatalog is not null)
            throw new NativeCaseFailureException("observer-unavailable");
        RotationIdentityCatalogFacts facts = await PostAsync<RotationIdentityCatalogFacts>("rotation/identity-catalog", writer =>
        {
            Write(writer, "coordinate", coordinate);
            Write(writer, "usernames", usernames);
        }, token);
        if (!RotationSqlIdentityEvidence.Bound(facts, coordinate, usernames))
            throw new NativeCaseFailureException("observer-unavailable");
        return facts;
    }

    public async ValueTask<BackendAuthentication> AuthenticateAsync(RotationBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (coordinate.Profile == InfisicalRotationProfile.PostgresCredentials && postgresConsumerAuthentication is not null)
            return await postgresConsumerAuthentication.AuthenticateAsync(coordinate, username, password, token).ConfigureAwait(false);
        if (coordinate.Profile == InfisicalRotationProfile.MysqlCredentials && mysqlConsumerAuthentication is not null)
            return await mysqlConsumerAuthentication.AuthenticateAsync(coordinate, username, password, token).ConfigureAwait(false);
        if (postgresConsumerAuthentication is not null || mysqlConsumerAuthentication is not null)
            return BackendAuthentication.Unavailable;
        Authentication facts = await PostAsync<Authentication>("rotation/authenticate", writer =>
        {
            Write(writer, "coordinate", coordinate);
            writer.WriteString("username", username.Reveal());
            writer.WriteString("password", password.Reveal());
        }, token);
        if (facts.Coordinate != coordinate) throw new NativeCaseFailureException("effect-mismatch");
        return facts.Result;
    }

    public ValueTask<RotationCredentialFacts> MeasureCredentialsAsync(RotationBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token) =>
        PostAsync<RotationCredentialFacts>("rotation/measure-credentials", writer =>
        {
            Write(writer, "coordinate", coordinate);
            writer.WriteString("username", username.Reveal());
            writer.WriteString("password", password.Reveal());
        }, token);

    public async ValueTask<IInfisicalRotationBackendSubscription> SubscribeAsync(RotationBackendCoordinate coordinate,
        CancellationToken token)
    {
        Registration registration = await PostAsync<Registration>("rotation/arm", writer =>
            Write(writer, "coordinate", coordinate), token);
        if (string.IsNullOrWhiteSpace(registration.Id) || registration.Id.Length > 128 ||
            registration.Coordinate != coordinate || registration.RemainingRegistrations != 1)
            throw new NativeCaseFailureException("observer-unavailable");
        return new Subscription(this, registration.Id, coordinate, token);
    }

    internal async ValueTask<T> PostAsync<T>(string path, Action<Utf8JsonWriter> fields, CancellationToken token)
        where T : notnull
    {
        string nonce = Guid.NewGuid().ToString("N");
        DateTimeOffset started = DateTimeOffset.UtcNow;
        // The guard precedes serialization and setup. The writer uses only owned
        // storage, including pending bytes; ByteArrayContent borrows it without a copy.
        using var body = new OwnedJsonBuffer(allocate);
        using (var writer = new Utf8JsonWriter(body))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("nonce", nonce);
            fields(writer);
            writer.WriteEndObject();
            writer.Flush();
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(settings.TimeoutSeconds));
        using var client = transport is null ? new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        }) : new HttpClient(transport, disposeHandler: false);
        client.Timeout = Timeout.InfiniteTimeSpan;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(settings.Endpoint, path));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.Token);
            request.Content = new ByteArrayContent(body.Buffer, 0, body.WrittenCount);
            request.Content.Headers.ContentType = new("application/json");
            using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                deadline.Token);
            if (!response.IsSuccessStatusCode) throw new NativeCaseFailureException("observer-unavailable");
            await using Stream stream = await response.Content.ReadAsStreamAsync(deadline.Token);
            using var received = new MemoryStream();
            byte[] chunk = new byte[8192];
            try
            {
                int count;
                while ((count = await stream.ReadAsync(chunk, deadline.Token)) != 0)
                {
                    if (received.Length + count > 1024 * 1024)
                        throw new NativeCaseFailureException("observer-unavailable");
                    received.Write(chunk, 0, count);
                }
                using JsonDocument document = JsonDocument.Parse(received.GetBuffer().AsMemory(0,
                    checked((int)received.Length)), new JsonDocumentOptions { MaxDepth = 32 });
                try { NativeRunProtocol.RejectDuplicates(document.RootElement); }
                catch (InvalidOperationException) { throw new NativeCaseFailureException("observer-unavailable"); }
                Envelope<T>? envelope = document.RootElement.Deserialize<Envelope<T>>(InfisicalLifecycleFamilies.Options);
                if (envelope is null || envelope.Facts is null || envelope.SchemaVersion != 1 || envelope.Nonce != nonce ||
                    envelope.ObserverIdentity != settings.Identity || envelope.ObservedAt < started.AddSeconds(-30) ||
                    envelope.ObservedAt > DateTimeOffset.UtcNow.AddSeconds(30))
                    throw new NativeCaseFailureException("observer-unavailable");
                return envelope.Facts;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(chunk);
                CryptographicOperations.ZeroMemory(received.GetBuffer());
            }
        }
        catch (JsonException) { throw new NativeCaseFailureException("observer-unavailable"); }
        catch (HttpRequestException) { throw new NativeCaseFailureException("observer-unavailable"); }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new NativeCaseFailureException("deadline-exceeded"); }
    }

    internal sealed class OwnedJsonBuffer(Func<int, byte[]> allocate) : IBufferWriter<byte>, IDisposable
    {
        internal byte[] Buffer { get; private set; } = [];
        internal int WrittenCount { get; private set; }

        public void Advance(int count)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            if (count > Buffer.Length - WrittenCount) throw new ArgumentOutOfRangeException(nameof(count));
            WrittenCount += count;
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(sizeHint);
            sizeHint = Math.Max(sizeHint, 1);
            if (sizeHint > Buffer.Length - WrittenCount)
            {
                byte[] next = allocate(Math.Max(checked(WrittenCount + sizeHint), checked(Buffer.Length * 2)));
                Buffer.AsSpan(0, WrittenCount).CopyTo(next);
                CryptographicOperations.ZeroMemory(Buffer);
                Buffer = next;
            }
            return Buffer.AsMemory(WrittenCount);
        }

        public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;

        public void Dispose()
        {
            // Clear capacity, not just committed bytes: a throwing writer can
            // leave sensitive bytes in memory without ever calling Advance.
            CryptographicOperations.ZeroMemory(Buffer);
            Buffer = [];
            WrittenCount = 0;
        }
    }

    private static void Write<T>(Utf8JsonWriter writer, string name, T value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }

    private sealed record Envelope<T>(int SchemaVersion, string Nonce, string ObserverIdentity,
        DateTimeOffset ObservedAt, T Facts);
    private sealed record Expiry(BackendAuthentication Authentication, DateTimeOffset ExpiresAt);
    private sealed record Authentication(RotationBackendCoordinate Coordinate, BackendAuthentication Result);
    private sealed record Registration(string Id, RotationBackendCoordinate Coordinate, int RemainingRegistrations);
    private sealed record Unregistration(string Id, int RemainingRegistrations);

    private sealed class Subscription : IInfisicalRotationBackendSubscription
    {
        private readonly InfisicalLifecycleObservers owner;
        private readonly string id;
        private readonly CancellationTokenSource cancellation;
        public Task<RotationBackendFacts> Observed { get; }

        internal Subscription(InfisicalLifecycleObservers owner, string id, RotationBackendCoordinate coordinate,
            CancellationToken token)
        {
            this.owner = owner;
            this.id = id;
            cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            Observed = owner.PostAsync<RotationBackendFacts>("rotation/observe", writer =>
            {
                writer.WriteString("subscriptionId", id);
                Write(writer, "coordinate", coordinate);
            }, cancellation.Token).AsTask();
        }

        public async ValueTask DisposeAsync()
        {
            await cancellation.CancelAsync();
            try { await Observed; }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            finally
            {
                try
                {
                    Unregistration facts = await owner.PostAsync<Unregistration>("rotation/disarm", writer =>
                        writer.WriteString("subscriptionId", id), CancellationToken.None);
                    if (facts.Id != id || facts.RemainingRegistrations != 0)
                        throw new NativeCaseFailureException("cleanup-incomplete");
                }
                finally { cancellation.Dispose(); }
            }
        }
    }
}
