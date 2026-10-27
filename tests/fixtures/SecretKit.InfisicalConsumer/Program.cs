using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;
#if CONFIGURATION
using Microsoft.Extensions.Configuration;
using SecretKit.Extensions.Configuration;
#endif
#if HOSTING
using SecretKit.Extensions.Hosting;
#endif

if (args.Length > 0 && args[0] == "native")
{
    Environment.ExitCode = await NativeWorkflow.RunAsync(args[1..]);
    return;
}

if (args is not ["offline"])
{
    Console.Error.WriteLine("Expected offline or native workflow arguments.");
    Environment.ExitCode = 2;
    return;
}

try
{
    Console.WriteLine(await InstalledWorkflow.RunAsync());
}
catch
{
    Console.Error.WriteLine("Installed workflow failed; protected diagnostics withheld.");
    Environment.ExitCode = 1;
}

internal static class InstalledWorkflow
{
    private const string Value = "installed-material-canary";
    private const string Token = "installed-token-canary";
    private const string Project = "installed-project-canary";
    private const string Key = "installed-key-canary";
    private const string Resource = "installed-resource-canary";

    internal static async Task<string> RunAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var wire = new Loopback(deadline.Token);
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, ActivityHeadersPropagator = null, UseProxy = false
        };
        var network = new InfisicalNetworkOptions
        {
            AllowLoopbackDevelopmentHttp = true,
            Transport = InfisicalTransportOptions.HostControlled(handler)
        };
        var clock = new Clock();
        var scenarios = new List<object>();
        using var authentication = new InfisicalUniversalAuthentication(wire.Origin, network, clock);
        using var credential = SecretMaterial.FromText("installed-bootstrap-canary");
        InfisicalUniversalLoginReceipt loginReceipt = authentication.CreateReceipt();
        using InfisicalUniversalLogin login = (await wire.Exchange(
            () => authentication.LoginAsync("installed-client-canary", credential, loginReceipt,
                cancellationToken: deadline.Token).AsTask(),
            "POST", "/api/v1/auth/universal-auth/login", 200,
            TokenBody(Token), null, body =>
                body.GetProperty("clientSecret").GetString() == "installed-bootstrap-canary")).Value;
        Require(loginReceipt.Evidence == DispatchEvidence.Applied);
        InfisicalTokenLifetimeEvidence evidence = login.BindLifetimeEvidence(new()
        {
            OriginalIssuedAt = clock.GetUtcNow(), ExpiresAt = login.Token.ExpiresAt!.Value,
            Lifetime = InfisicalTokenLifetime.Finite, ReportedMaximumTtl = TimeSpan.FromSeconds(120)
        });
        await using var session = new InfisicalPeriodicTokenSession(login, evidence,
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), network, clock);
        login.Dispose();
        using (InfisicalAccessToken selected = (await session.GetTokenAsync(deadline.Token)).Value)
            Require(selected.Material.Reveal() == Token);
        Require(session.LastRenewal is null && session.State == InfisicalTokenSessionState.Ready);
        await using var client = new InfisicalClient(wire.Origin, session, network, clock);
        SecretReference reference = Reference(client);
        long started = Stopwatch.GetTimestamp();

        // The application constructs its dependent object only after both required reads.
        int constructed = 0;
        foreach (int status in new[] { 403, 404 })
        {
            RequiredConsumer? required = await ConstructRequired(status);
            Require(required is null);
        }
        Require(constructed == 0);
        RequiredConsumer complete = await ConstructRequired(200) ?? throw new InvalidOperationException();
        Require(complete.First == Value && complete.Second == "secondary-material-canary");
        using InfisicalSecretRead first = (await Read(200, SecretBody())).Value;
        Require(first.Material.Reveal() == Value && constructed == 1);
        SecretOutcome<InfisicalSecretRead> optional = await Read(404, "{}");
        Require(optional.Status == SecretStatus.Absent && constructed == 1 && complete.First == Value);
        scenarios.Add(new { id = "S09", subset = "two-required-denied-or-absent-no-construction", status = "passed" });
        scenarios.Add(new { id = "S10", subset = "separate-optional-absence-preserves-required-consumer", status = "passed" });

        await using var replacement = new InfisicalClient(wire.Origin, session, network, clock);
        using InfisicalSecretRead same = (await wire.Exchange(
            () => replacement.ReadNativeAsync(Reference(replacement), deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 200, SecretBody(), Token)).Value;
        Require(first.Revision == same.Revision);
        Require((await replacement.ReadNativeAsync(reference, deadline.Token)).Status == SecretStatus.Invalid);
        using InfisicalSecretRead drift = (await Read(200, SecretBody(version: 2))).Value;
        using InfisicalSecretRead recreated = (await Read(200, SecretBody(resource: "recreated-canary"))).Value;
        Require(first.Revision != drift.Revision && first.Revision != recreated.Revision);
        first.Dispose();
        Require(same.Material.Reveal() == Value);
        Require((await Read(200, SecretBody(hidden: true))).Status == SecretStatus.Denied);
        Require((await Read(200, SecretBody(version: 0))).Status == SecretStatus.Unknown);
        Require((await Read(200, SecretBody(project: "foreign-canary"))).Status == SecretStatus.Invalid);
        scenarios.Add(new { id = "S03", subset = "exact-raw-value", status = "passed" });
        scenarios.Add(new { id = "S04", subset = "cross-client-version-and-recreation-revision", status = "passed" });
        scenarios.Add(new { id = "S05", subset = "foreign-authority-hidden-version-and-scope-rejection", status = "passed" });

        var scope = new InfisicalInventoryScope(client.Authority, Project, "test", "/", maximumItems: 1);
        string inventoryBody = JsonSerializer.Serialize(new
        {
            secrets = new[]
            {
                new { secretKey = Key, workspace = Project, environment = "test", secretPath = "/",
                    type = "shared", version = 1, secretValue = "inventory-material-must-not-escape" },
                new { secretKey = "second", workspace = Project, environment = "test", secretPath = "/",
                    type = "shared", version = 2, secretValue = "inventory-material-must-not-escape" }
            }
        });
        SecretInventory inventory = (await wire.Exchange(
            () => client.InspectAsync(scope, deadline.Token).AsTask(),
            "GET", "/api/v4/secrets", 200, inventoryBody, Token)).Value;
        Require(inventory.Items.Count == 1 && !inventory.IsComplete &&
            !inventory.IsPointInTime && inventory.Items[0].Version == "1" &&
            inventory.Items[0].Validity == SecretValidity.Unknown &&
            inventory.Items[0].Reference.BelongsTo(client.Authority));
        Require(!JsonSerializer.Serialize(inventory).Contains("inventory-material", StringComparison.Ordinal));
        string foreignInventory = inventoryBody.Replace(Project, "foreign-canary", StringComparison.Ordinal);
        Require((await wire.Exchange(() => client.InspectAsync(scope, deadline.Token).AsTask(),
            "GET", "/api/v4/secrets", 200, foreignInventory, Token)).Status == SecretStatus.Invalid);
        scenarios.Add(new { id = "S06", subset = "metadata-query-scope-truncation-and-no-material", status = "passed" });

        using SecretMaterial update = SecretMaterial.FromText("installed-updated-canary");
        var appliedReceipt = new MutationReceipt(reference);
        SecretOutcome<InfisicalStaticChange> applied = await Change(appliedReceipt, 200, SecretBody(version: 2));
        Require(applied.IsSuccess && applied.Value.Disposition == InfisicalChangeDisposition.Applied &&
            appliedReceipt.Evidence == DispatchEvidence.Applied);
        var pendingReceipt = new MutationReceipt(reference);
        SecretOutcome<InfisicalStaticChange> pending = await Change(pendingReceipt, 200,
            """{"approval":{"id":"12345678-1234-1234-1234-123456789012","hasMerged":false}}""");
        Require(pending.IsSuccess && pending.Value.Disposition == InfisicalChangeDisposition.SubmittedForApproval &&
            pendingReceipt.Evidence == DispatchEvidence.Pending);
        var rejectedReceipt = new MutationReceipt(reference);
        Require((await Change(rejectedReceipt, 403, "{}")).Status == SecretStatus.Denied &&
            rejectedReceipt.Evidence == DispatchEvidence.Rejected);
        var unknownReceipt = new MutationReceipt(reference);
        Require((await Change(unknownReceipt, 200, "{}")).Status == SecretStatus.Unknown &&
            unknownReceipt.Evidence == DispatchEvidence.PossiblyDispatched);
        Require((await client.UpdateValueAsync(reference, update, unknownReceipt, deadline.Token)).Status ==
            SecretStatus.Invalid);
        Require(update.Reveal() == "installed-updated-canary");
        scenarios.Add(new { id = "S12", subset = "applied-pending-rejected-unknown-no-replay", status = "passed" });

#if CONFIGURATION
        using var requiredLoader = new SecretSnapshotLoader([new SecretSelection("required", client, reference)], clock);
        using var optionalLoader = new SecretSnapshotLoader([new SecretSelection("optional", client, reference)], clock);
        Require((await wire.Exchange(() => requiredLoader.RefreshAsync(deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 200, SecretBody(), Token)).IsSuccess);
        using SecretSnapshotHandle old = requiredLoader.Acquire();
        using SecretRead independent = old.Read("required");
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(old,
            [new SecretConfigurationMapping("required", "Application:Value")]);
        IConfigurationRoot configuration = new ConfigurationBuilder().Add(export).Build();
        using var configurationOwner = (IDisposable)configuration;
        Require(configuration["Application:Value"] == Value && !old.RemoteSnapshotGuaranteed);
        Require((await wire.Exchange(() => optionalLoader.RefreshAsync(deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 404, "{}", Token)).Status == SecretStatus.Absent);
        Require((await wire.Exchange(() => requiredLoader.RefreshAsync(deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 200, SecretBody(version: 2, value: "next-generation-canary"),
            Token)).Value == 2);
        using SecretSnapshotHandle next = requiredLoader.Acquire();
        Require(old.Generation == 1 && next.Generation == 2);
        export.ReplaceAcknowledgingManagedStrings(next);
        using (SecretRead pinned = old.Read("required")) Require(pinned.Material.Reveal() == Value);
        Require(configuration["Application:Value"] == "next-generation-canary");
        Require((await wire.Exchange(() => requiredLoader.RefreshAsync(deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 403, "{}", Token)).Status == SecretStatus.Denied);
        using (SecretSnapshotHandle retained = requiredLoader.Acquire()) Require(retained.Generation == 2);
        requiredLoader.Dispose();
        old.Dispose();
        Require(independent.Material.Reveal() == Value);
        Require(!export.GetRedactedDebugView().Contains("Application", StringComparison.Ordinal));
        scenarios.Add(new { id = "S11", subset = "explicit-export-pinned-generation-and-failed-refresh", status = "passed" });
#endif

        clock.Advance(TimeSpan.FromSeconds(20));
        Require(await wire.Exchange(() => session.RenewAsync(deadline.Token).AsTask(),
            "POST", "/api/v1/auth/token/renew", 200, TokenBody("installed-renewed-canary"), null,
            body => body.GetProperty("accessToken").GetString() == Token) == SecretStatus.Success);
        Require(session.LastRenewal?.Evidence == InfisicalRenewalEvidence.Applied);
        using (InfisicalAccessToken renewed = (await session.GetTokenAsync(deadline.Token)).Value)
            Require(renewed.Material.Reveal() == "installed-renewed-canary" &&
                renewed.ExpiresAt == clock.GetUtcNow().AddSeconds(60));
        clock.Advance(TimeSpan.FromSeconds(61));
        Require((await session.GetTokenAsync(deadline.Token)).Status == SecretStatus.RecoveryRequired);
        Require(session.State == InfisicalTokenSessionState.Expired);
        Require(await session.RenewAsync(deadline.Token) == SecretStatus.RecoveryRequired);
        scenarios.Add(new { id = "S07", subset = "login-bound-finite-lifetime-and-explicit-renewal", status = "passed" });
        scenarios.Add(new { id = "S08", subset = "expiry-requires-recovery-without-login-or-renewal", status = "passed" });
#if HOSTING
        await using var maintenance = new InfisicalAuthenticationMaintenance(session, TimeSpan.FromSeconds(2));
        Require(maintenance.State == AuthenticationMaintenanceState.NotStarted);
        await maintenance.StartAsync(deadline.Token);
        Require(maintenance.State == AuthenticationMaintenanceState.Expired);
        await maintenance.StopAsync(deadline.Token);
        Require(maintenance.State == AuthenticationMaintenanceState.Stopped &&
            session.State == InfisicalTokenSessionState.Stopped);
#endif
        await replacement.DisposeAsync();
        await client.DisposeAsync();
        // A host transport still works after both SDK clients have shut down.
        using var host = new HttpClient(handler, disposeHandler: false);
        using HttpResponseMessage response = await wire.Exchange(() => host.GetAsync(wire.Origin, deadline.Token),
            "GET", "/", 200, "{}", null);
        Require(response.IsSuccessStatusCode);
        scenarios.Add(new { id = "S13", subset = "host-handler-remains-usable-after-client-shutdown", status = "passed" });
        scenarios.Add(new { id = "S16", subset = "report-and-native-read-serialization-redaction", status = "passed" });
        string report = JsonSerializer.Serialize(new
        {
            schemaVersion = 1, kind = "local-installed-offline", nativeQualified = false,
            mode = Mode, scenarios, unqualifiedScenarios = new[] { "S15" }, requests = wire.Requests,
            elapsedMilliseconds = Stopwatch.GetElapsedTime(started).TotalMilliseconds
        });
        foreach (string canary in new[] { Value, Token, Project, Key, Resource, "bootstrap-canary",
            "renewed-canary", "updated-canary", "next-generation-canary", "secondary-material-canary",
            "inventory-material", "12345678" })
            Require(!report.Contains(canary, StringComparison.Ordinal) &&
                !JsonSerializer.Serialize(same).Contains(canary, StringComparison.Ordinal));
        return report;

        async Task<RequiredConsumer?> ConstructRequired(int secondStatus)
        {
            using InfisicalSecretRead requiredFirst = (await Read(200, SecretBody())).Value;
            SecretReference secondReference = new(client.Authority,
                new InfisicalSecretAddress(Project, "test", "/", "secondary"));
            SecretOutcome<InfisicalSecretRead> second = await wire.Exchange(
                () => client.ReadNativeAsync(secondReference, deadline.Token).AsTask(),
                "GET", "/api/v4/secrets/secondary", secondStatus,
                secondStatus == 200 ? SecretBody(key: "secondary", value: "secondary-material-canary") : "{}", Token);
            if (!second.IsSuccess)
            {
                Require(second.Status == (secondStatus == 403 ? SecretStatus.Denied : SecretStatus.Absent));
                return null;
            }
            using InfisicalSecretRead requiredSecond = second.Value;
            var consumer = new RequiredConsumer(requiredFirst.Material.Reveal(), requiredSecond.Material.Reveal());
            constructed++;
            return consumer;
        }

        Task<SecretOutcome<InfisicalSecretRead>> Read(int status, string body) =>
            wire.Exchange(() => client.ReadNativeAsync(reference, deadline.Token).AsTask(),
                "GET", "/api/v4/secrets/" + Key, status, body, Token);
        Task<SecretOutcome<InfisicalStaticChange>> Change(MutationReceipt receipt, int status, string body) =>
            wire.Exchange(() => client.UpdateValueAsync(reference, update, receipt, deadline.Token).AsTask(),
                "PATCH", "/api/v4/secrets/" + Key, status, body, Token,
                payload => payload.GetProperty("secretValue").GetString() == "installed-updated-canary" &&
                    payload.GetProperty("projectId").GetString() == Project);
    }

    private static string Mode =>
#if CONFIGURATION && HOSTING
        "full";
#elif CONFIGURATION
        "configuration";
#elif HOSTING
        "hosting";
#else
        "minimal";
#endif

    private static SecretReference Reference(InfisicalClient client) =>
        new(client.Authority, new InfisicalSecretAddress(Project, "test", "/", Key));
    private static string SecretBody(int version = 1, string resource = Resource, bool hidden = false,
        string project = Project, string value = Value, string key = Key) => JsonSerializer.Serialize(new
        {
            secret = new { id = resource, workspace = project, environment = "test", secretPath = "/",
                type = "shared", secretKey = key, version, secretValue = value, secretValueHidden = hidden }
        });
    private static string TokenBody(string token) => JsonSerializer.Serialize(new
    {
        accessToken = token, tokenType = "Bearer", expiresIn = 60, accessTokenMaxTTL = 120
    });
    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Installed workflow assertion failed.");
    }

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 23, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan elapsed) => _now += elapsed;
    }

    private sealed record RequiredConsumer(string First, string Second);

    private sealed class Loopback : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationToken _token;
        internal Loopback(CancellationToken token)
        {
            _token = token;
            _listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/");
        }
        internal Uri Origin { get; }
        internal int Requests { get; private set; }
        internal async Task<T> Exchange<T>(Func<Task<T>> action, string method, string path, int status,
            string body, string? bearer, Func<JsonElement, bool>? payload = null)
        {
            // Subscribe before dispatch. Both sides use the same bounded cancellation scope.
            Task server = Respond(method, path, status, body, bearer, payload);
            Task<T> request = action();
            await Task.WhenAll(server, request).WaitAsync(_token);
            return await request;
        }
        private async Task Respond(string method, string path, int status, string body, string? bearer,
            Func<JsonElement, bool>? payload)
        {
            using TcpClient connection = await _listener.AcceptTcpClientAsync(_token);
            using NetworkStream stream = connection.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            string[] request = (await reader.ReadLineAsync(_token) ?? "").Split(' ');
            Require(request.Length == 3 && request[0] == method &&
                new Uri(Origin, request[1]).AbsolutePath == path);
            if (method == "GET" && path.StartsWith("/api/v4/secrets", StringComparison.Ordinal))
            {
                Dictionary<string, string> query = new Uri(Origin, request[1]).Query.TrimStart('?').Split('&')
                    .Select(pair => pair.Split('=', 2)).ToDictionary(pair => Uri.UnescapeDataString(pair[0]),
                        pair => Uri.UnescapeDataString(pair[1]), StringComparer.Ordinal);
                Require(query["projectId"] == Project && query["environment"] == "test" &&
                    query["secretPath"] == "/" && query["includeImports"] == "false" &&
                    query["expandSecretReferences"] == "false");
                if (path == "/api/v4/secrets")
                    Require(query["viewSecretValue"] == "false" && query["recursive"] == "false" &&
                        query["includePersonalOverrides"] == "false");
                else Require(query["viewSecretValue"] == "true" && query["type"] == "shared");
            }
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (await reader.ReadLineAsync(_token) is { Length: > 0 } header)
            {
                int separator = header.IndexOf(':');
                Require(separator > 0);
                headers.Add(header[..separator], header[(separator + 1)..].Trim());
            }
            Require(bearer is null ? !headers.ContainsKey("Authorization") :
                headers.GetValueOrDefault("Authorization") == "Bearer " + bearer);
            if (payload is not null)
            {
                int length = int.Parse(headers["Content-Length"], System.Globalization.CultureInfo.InvariantCulture);
                Require(length is > 0 and < 65536);
                char[] buffer = new char[length];
                Require(await reader.ReadBlockAsync(buffer.AsMemory(), _token) == length);
                using JsonDocument document = JsonDocument.Parse(new string(buffer));
                Require(payload(document.RootElement));
                Array.Clear(buffer);
            }
            Requests++;
            byte[] bytes = Encoding.UTF8.GetBytes(body);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"), _token);
            await stream.WriteAsync(bytes, _token);
        }
        public ValueTask DisposeAsync()
        {
            _listener.Stop();
            return ValueTask.CompletedTask;
        }
    }
}
