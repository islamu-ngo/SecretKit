using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureAuditDiagnosticSettingsTests
{
    [Test]
    public async Task NativeRoutingIsIndependentlyReadAndBorrowedWorkspaceSurvivesRelease()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(AuditDiagnosticSettings.State.Ready);
        await Assert.That(result.RoutingReady).IsTrue();
        await Assert.That(fixture.State.PersistedBeforeSend).IsTrue();
        using (var settings = JsonDocument.Parse(fixture.State.Settings!))
        {
            var properties = settings.RootElement.GetProperty("properties");
            await Assert.That(properties.GetProperty("workspaceId").GetString()).IsEqualTo(Workspace);
            await Assert.That(properties.GetProperty("logs").GetArrayLength()).IsEqualTo(1);
            await Assert.That(properties.GetProperty("logs")[0].GetProperty("category").GetString()).IsEqualTo("AuditEvent");
            await Assert.That(properties.GetProperty("logAnalyticsDestinationType").ValueKind).IsEqualTo(JsonValueKind.Null);
        }
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsTrue();
        var release = await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector);
        await Assert.That(release.State).IsEqualTo(AuditDiagnosticSettings.State.Released);
        await Assert.That(fixture.State.Settings).IsNull();
        await Assert.That(fixture.State.WorkspaceCustomer).IsEqualTo(QueryWorkspace);
        await Assert.That(fixture.State.VaultNonce).IsEqualTo(fixture.Selector.Nonce.ToString("N"));
        await Assert.That(fixture.Read().Resources.Single(r => r.Borrowed).Absent).IsFalse();
        await Assert.That(fixture.State.Requests.Where(r => r.Role == "read").All(r => r.Method == "GET")).IsTrue();
        await Assert.That(fixture.State.Requests.Where(r => r.Method != "GET").All(r => r.Path == plan.SettingsId)).IsTrue();
        await Assert.That(fixture.State.Requests.Where(r => r.Path == Workspace).All(r => r.Method == "GET")).IsTrue();
        await Assert.That(fixture.Backends.All(b => !b.Disposed)).IsTrue();
    }

    [Test]
    [Arguments("workspace")]
    [Arguments("nonce")]
    [Arguments("vault-id")]
    [Arguments("tenant")]
    [Arguments("location")]
    [Arguments("denied")]
    public async Task NativeOwnershipAndWorkspaceIdentityGateExport(string fault)
    {
        using var fixture = new Fixture();
        switch (fault)
        {
            case "workspace": fixture.State.WorkspaceCustomer = Guid.NewGuid(); break;
            case "nonce": fixture.State.VaultNonce = Guid.NewGuid().ToString("N"); break;
            case "vault-id": fixture.State.ReturnedVault = Group + "/providers/Microsoft.KeyVault/vaults/foreign"; break;
            case "tenant": fixture.State.ReturnedTenant = Guid.NewGuid(); break;
            case "location": fixture.State.ReturnedLocation = "westus"; break;
            case "denied": fixture.State.ReadDenied = true; break;
        }
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(fault == "denied" ?
            AuditDiagnosticSettings.State.Denied : AuditDiagnosticSettings.State.Uncertain);
        await Assert.That(fixture.State.Settings).IsNull();
        await Assert.That(fixture.State.Requests.All(r => r.Method == "GET")).IsTrue();
        await Assert.That(fixture.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
    }

    [Test]
    [Arguments("no-op")]
    [Arguments("wrong-workspace")]
    [Arguments("dedicated")]
    [Arguments("extra-log")]
    [Arguments("storage")]
    [Arguments("eventhub")]
    [Arguments("metrics")]
    [Arguments("partner")]
    public async Task SelectedAcknowledgementCannotEstablishRouting(string fault)
    {
        using var fixture = new Fixture();
        fixture.State.CreateFault = fault;
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsNotEqualTo(AuditDiagnosticSettings.State.Ready);
        await Assert.That(result.RoutingReady).IsFalse();
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsTrue();
        await Assert.That(fixture.State.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(async () => await fixture.Source.ProvisionAsync(plan)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("pending")]
    public async Task UnsettledCreateSurvivesRestartAndAbsenceWithoutReplay(string fault)
    {
        using var fixture = new Fixture();
        fixture.State.CreateFault = fault;
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(fault == "pending" ?
            AuditDiagnosticSettings.State.Pending : AuditDiagnosticSettings.State.Uncertain);
        var owned = fixture.Read().Resources.Single(r => !r.Borrowed);
        await Assert.That(owned.InvocationTerminated).IsTrue();
        await Assert.That(owned.ActiveDispatch == Guid.Empty).IsFalse();
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsFalse();
        var reopened = fixture.Reopen();
        await Assert.That((await reopened.ObserveAsync(Owner, fixture.Selector)).State)
            .IsEqualTo(AuditDiagnosticSettings.State.Pending);
        fixture.State.Settings = null; // Native state changed independently, not settlement evidence.
        var release = await reopened.ReleaseAsync(Owner, fixture.Selector);
        await Assert.That(release.State).IsEqualTo(AuditDiagnosticSettings.State.Pending);
        await Assert.That(fixture.State.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(fixture.State.Requests.Any(r => r.Method == "DELETE")).IsFalse();
        await Assert.That(() => reopened.PlanFixture(Owner, fixture.Selector, Vault)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RetainedNativeCompletionSurvivesJournalContentionWithoutReplay(bool reopen)
    {
        using var fixture = new Fixture();
        fixture.State.Applied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.State.Terminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var plan = fixture.Plan();
        Task<AuditDiagnosticSettings.Result> provision = fixture.Source.ProvisionAsync(plan).AsTask();
        try
        {
            await fixture.State.Applied.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using (fixture.LockJournal())
            {
                fixture.State.Terminate.TrySetResult();
                await Assert.That(async () => await provision).Throws<InvalidOperationException>();
            }
            await Assert.That(plan.Receipts.Single().Terminated).IsTrue();
            await Assert.That(plan.Receipts.Single().RemoteSettled).IsTrue();
            await Assert.That(fixture.Read().Resources.Single(r => !r.Borrowed).ActiveDispatch == Guid.Empty).IsFalse();
            var release = await (reopen ? fixture.Reopen() : fixture.Source).ReleaseAsync(Owner, fixture.Selector);
            await Assert.That(release.State).IsEqualTo(reopen
                ? AuditDiagnosticSettings.State.Pending : AuditDiagnosticSettings.State.Released);
            await Assert.That(fixture.State.Settings is null).IsEqualTo(!reopen);
            await Assert.That(fixture.State.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
            await Assert.That(fixture.State.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(reopen ? 0 : 1);
        }
        finally
        {
            fixture.State.Terminate.TrySetResult();
            try { await provision; }
            catch (InvalidOperationException) { }
        }
    }

    [Test]
    public async Task CloseDuringAppliedInvocationDoesNotDeleteBeforeActualDrain()
    {
        using var fixture = new Fixture();
        fixture.State.Applied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.State.Terminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var plan = fixture.Plan();
        Task provision = fixture.Source.ProvisionAsync(plan, cancellation.Token).AsTask();
        try
        {
            await fixture.State.Applied.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var release = await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector);
            await Assert.That(release.State).IsEqualTo(AuditDiagnosticSettings.State.Pending);
            await Assert.That(fixture.Read().Resources.Single(r => !r.Borrowed).InvocationTerminated).IsFalse();
            cancellation.Cancel();
            fixture.State.Terminate.TrySetResult();
            await Assert.That(async () => await provision).Throws<OperationCanceledException>();
            await Assert.That(fixture.Read().Resources.Single(r => !r.Borrowed).InvocationTerminated).IsTrue();
            await Assert.That((await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector)).State)
                .IsEqualTo(AuditDiagnosticSettings.State.Pending);
            await Assert.That(fixture.State.Requests.Any(r => r.Method == "DELETE")).IsFalse();
        }
        finally
        {
            cancellation.Cancel();
            fixture.State.Terminate.TrySetResult();
            try { await provision; }
            catch (OperationCanceledException) { }
        }
    }

    [Test]
    [Arguments("lost")]
    [Arguments("pending")]
    [Arguments("no-op")]
    [Arguments("denied")]
    public async Task DeleteFailureNeverReplaysOrManufacturesAbsence(string fault)
    {
        using var fixture = new Fixture();
        await fixture.Source.ProvisionAsync(fixture.Plan());
        fixture.State.DeleteFault = fault;
        var first = await fixture.Source.ReleaseAsync(Owner, fixture.Selector);
        var second = await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector);
        await Assert.That(first.State).IsNotEqualTo(AuditDiagnosticSettings.State.Released);
        await Assert.That(second.State).IsNotEqualTo(AuditDiagnosticSettings.State.Released);
        await Assert.That(fixture.Read().Resources.Single(r => !r.Borrowed).Absent).IsFalse();
        await Assert.That(fixture.State.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(fixture.State.WorkspaceCustomer).IsEqualTo(QueryWorkspace);
    }

    [Test]
    public async Task PositiveReadbackInvalidatesEarlierAbsenceWithoutDeleteReplay()
    {
        using var fixture = new Fixture();
        await fixture.Source.ProvisionAsync(fixture.Plan());
        string saved = fixture.State.Settings!;
        await Assert.That((await fixture.Source.ReleaseAsync(Owner, fixture.Selector)).State)
            .IsEqualTo(AuditDiagnosticSettings.State.Released);
        fixture.State.Settings = saved;
        var release = await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector);
        await Assert.That(release.State).IsEqualTo(AuditDiagnosticSettings.State.Closing);
        await Assert.That(release.Journal!.Released).IsFalse();
        await Assert.That(fixture.Read().Released).IsFalse();
        await Assert.That(fixture.State.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
    }

    [Test]
    public async Task DeniedReadbackNeverBecomesAbsence()
    {
        using var fixture = new Fixture();
        await fixture.Source.ProvisionAsync(fixture.Plan());
        fixture.State.ReadDenied = true;
        var release = await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector);
        await Assert.That(release.State).IsEqualTo(AuditDiagnosticSettings.State.Denied);
        await Assert.That(fixture.Read().Released).IsFalse();
        await Assert.That(fixture.State.Settings).IsNotNull();
        await Assert.That(fixture.State.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    public async Task ForeignNonceAfterSetupPreventsDiagnosticDeletion()
    {
        using var fixture = new Fixture();
        await fixture.Source.ProvisionAsync(fixture.Plan());
        fixture.State.VaultNonce = Guid.NewGuid().ToString("N");
        var release = await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector);
        await Assert.That(release.State).IsEqualTo(AuditDiagnosticSettings.State.Uncertain);
        await Assert.That(fixture.State.Settings).IsNotNull();
        await Assert.That(fixture.State.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    public async Task PreexistingSettingIsNeitherOverwrittenNorDeleted()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        fixture.State.Settings = JsonSerializer.Serialize(new { id = plan.SettingsId });
        await Assert.That((await fixture.Source.ProvisionAsync(plan)).State)
            .IsEqualTo(AuditDiagnosticSettings.State.Uncertain);
        await Assert.That((await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector)).State)
            .IsEqualTo(AuditDiagnosticSettings.State.Uncertain);
        await Assert.That(fixture.State.Settings).IsNotNull();
        await Assert.That(fixture.State.Requests.All(r => r.Method == "GET")).IsTrue();
    }

    [Test]
    public async Task InvalidVaultCoordinateCannotReachNativeAuthority()
    {
        using var fixture = new Fixture();
        await Assert.That(() => fixture.Source.PlanFixture(Owner, fixture.Selector,
            Group + "/providers/Microsoft.KeyVault/vaults/sk-fixture/secrets/canary"))
            .Throws<InvalidOperationException>();
        await Assert.That(fixture.State.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task CancellationBeforeInvocationDoesNotConsumeOrDispatchPlan()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await fixture.Source.ProvisionAsync(plan, cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(fixture.State.Requests.Count).IsEqualTo(0);
        await Assert.That(fixture.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
        await Assert.That((await fixture.Source.ProvisionAsync(plan)).State)
            .IsEqualTo(AuditDiagnosticSettings.State.Ready);
    }

    [Test]
    public async Task OmittedDestinationTypeKeepsNativeDefaultAzureDiagnostics()
    {
        using var fixture = new Fixture();
        await fixture.Source.ProvisionAsync(fixture.Plan());
        fixture.State.Settings = fixture.State.Settings!.Replace(",\"logAnalyticsDestinationType\":null", "", StringComparison.Ordinal);
        await Assert.That((await fixture.Reopen().ObserveAsync(Owner, fixture.Selector)).RoutingReady).IsTrue();
    }

    [Test]
    public async Task AsyncHeadersOnSuccessfulAcknowledgementDoNotSettleDispatch()
    {
        using var fixture = new Fixture();
        fixture.State.CreateFault = "async-header";
        var plan = fixture.Plan();
        await Assert.That((await fixture.Source.ProvisionAsync(plan)).State)
            .IsEqualTo(AuditDiagnosticSettings.State.Uncertain);
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsFalse();
        await Assert.That((await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector)).State)
            .IsEqualTo(AuditDiagnosticSettings.State.Pending);
        await Assert.That(fixture.State.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    public async Task DeniedCreateIsJournaledAndDoesNotDeleteUnattemptedResources()
    {
        using var fixture = new Fixture();
        fixture.State.CreateFault = "denied";
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan);
        await Assert.That(result.State).IsEqualTo(AuditDiagnosticSettings.State.Denied);
        await Assert.That(plan.Receipts.Single().Attempted).IsTrue();
        await Assert.That(plan.Receipts.Single().RemoteSettled).IsTrue();
        await Assert.That((await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector)).State)
            .IsEqualTo(AuditDiagnosticSettings.State.Released);
        await Assert.That(fixture.State.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    public async Task CloseBeforePrepareIsDurableAndFullSelectorCannotBeRebound()
    {
        using var fixture = new Fixture();
        var result = await fixture.Reopen().ReleaseAsync(Owner, fixture.Selector);
        await Assert.That(result.State).IsEqualTo(AuditDiagnosticSettings.State.Released);
        await Assert.That(() => fixture.Plan()).Throws<InvalidOperationException>();
        await Assert.That(async () => await fixture.Source.ReleaseAsync("other-owner", fixture.Selector))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await fixture.Source.ReleaseAsync(Owner, fixture.Selector with { Variant = "foreign" }))
            .Throws<InvalidOperationException>();
        await Assert.That(fixture.State.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("oversized")]
    [Arguments("redirect")]
    [Arguments("duplicate")]
    public async Task UntrustedReadBodiesAndRedirectsFailClosed(string fault)
    {
        using var fixture = new Fixture();
        fixture.State.ReadFault = fault;
        var result = await fixture.Source.ProvisionAsync(fixture.Plan());
        await Assert.That(result.State).IsEqualTo(AuditDiagnosticSettings.State.Uncertain);
        await Assert.That(fixture.State.Settings).IsNull();
        await Assert.That(fixture.Read().Resources.All(r => !r.CreateAttempted)).IsTrue();
    }

    [Test]
    public async Task CoordinatesAndSecretsAreNotFormattedOrSerialized()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        var result = await fixture.Source.ProvisionAsync(plan);
        string output = $"{fixture.Source} {plan} {result} {fixture.Scope} " +
            JsonSerializer.Serialize(fixture.Scope) + JsonSerializer.Serialize(plan) + JsonSerializer.Serialize(result);
        await Assert.That(output.Contains(Workspace, StringComparison.Ordinal)).IsFalse();
        await Assert.That(output.Contains(Vault, StringComparison.Ordinal)).IsFalse();
        await Assert.That(output.Contains(fixture.Selector.Nonce.ToString("N"), StringComparison.Ordinal)).IsFalse();
    }

    private const string Owner = "audit-owner";
    private static readonly Guid Subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Tenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid QueryWorkspace = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static string Group => $"/subscriptions/{Subscription:D}/resourceGroups/fixture-group";
    private static string Vault => Group + "/providers/Microsoft.KeyVault/vaults/sk-fixture";
    private static string Workspace => Group + "/providers/Microsoft.OperationalInsights/workspaces/fixture-workspace";

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "audit-settings-" + Guid.NewGuid().ToString("N"));
        internal readonly FixtureSelector Selector = new(Guid.NewGuid(), "audit", "query", "resource", "effect");
        internal readonly WireState State = new();
        internal readonly Backend[] Backends;
        private readonly HttpClient[] clients;
        private readonly HttpClientTransport[] transports;
        private readonly Credential[] credentials = [new("setup"), new("read")];
        internal readonly AuditDiagnosticSettings.HostScope Scope =
            new(Subscription, "fixture-group", "eastus", Tenant, Workspace, QueryWorkspace, true);
        internal readonly AuditDiagnosticSettings Source;
        internal Fixture()
        {
            Directory.CreateDirectory(directory);
            State.VaultNonce = Selector.Nonce.ToString("N");
            State.BeforeSend = id =>
            {
                var row = Read().Resources.Single(r => r.Id == id);
                State.PersistedBeforeSend &= row.ActiveDispatch != Guid.Empty &&
                    (row.CreateAttempted || row.DeleteAttempted);
            };
            Backends = [new("setup", State), new("read", State)];
            clients = Backends.Select(b => new HttpClient(b)).ToArray();
            transports = clients.Select(c => new HttpClientTransport(c)).ToArray();
            Source = Reopen();
        }
        internal AuditDiagnosticSettings Reopen() => new(new(directory), Scope,
            new("setup", credentials[0], transports[0]), new("read", credentials[1], transports[1]),
            new(64 * 1024, TimeSpan.FromSeconds(20)));
        internal AuditDiagnosticSettings.Plan Plan() => Source.PlanFixture(Owner, Selector, Vault);
        internal RoleFixtureJournal.Snapshot Read() => new RoleFixtureJournal(directory).Read(Owner, Selector);
        internal FileStream LockJournal() => new(Directory.GetFiles(directory).Single(),
            FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        public void Dispose()
        {
            foreach (var client in clients) client.Dispose();
            Directory.Delete(directory, true);
        }
    }

    // Independent native state persists across source reopen. Acknowledgements
    // may lie or be lost without rewriting the independent read model.
    private sealed class WireState
    {
        internal string? Settings;
        internal string? VaultNonce;
        internal string ReturnedVault = Vault;
        internal Guid ReturnedTenant = Tenant;
        internal string ReturnedLocation = "eastus";
        internal Guid WorkspaceCustomer = QueryWorkspace;
        internal string? CreateFault, DeleteFault, ReadFault;
        internal bool ReadDenied;
        internal bool PersistedBeforeSend = true;
        internal Action<string> BeforeSend = null!;
        internal TaskCompletionSource? Applied, Terminate;
        internal readonly List<(string Role, string Method, string Path)> Requests = [];

        internal async Task<HttpResponseMessage> Respond(string role, HttpRequestMessage request, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            string method = request.Method.Method;
            Requests.Add((role, method, path));
            if (request.Headers.Authorization?.Parameter != role ||
                role == "read" && method != "GET" || role == "setup" && method == "GET")
                throw new InvalidOperationException("controlled-authority");
            string revision = path == Workspace ? "2022-10-01" : path == Vault ? "2026-02-01" : "2021-05-01-preview";
            if (request.RequestUri.Query != "?api-version=" + revision)
                throw new InvalidOperationException("controlled-revision");
            if (method == "GET" && ReadDenied) return Json(403, """{"error":{"message":"protected-denial"}}""");
            if (method == "GET" && ReadFault == "oversized") return Json(200, "{\"data\":\"" + new string('x', 70000) + "\"}");
            if (method == "GET" && ReadFault == "duplicate") return Json(200, """{"id":"one","id":"two"}""");
            if (method == "GET" && ReadFault == "redirect")
            {
                var redirect = Json(302, "{}");
                redirect.Headers.Location = new("https://foreign.invalid/protected");
                return redirect;
            }
            if (path == Workspace)
                return Json(200, JsonSerializer.Serialize(new
                {
                    id = Workspace,
                    type = "Microsoft.OperationalInsights/workspaces",
                    properties = new { customerId = WorkspaceCustomer, provisioningState = "Succeeded" }
                }));
            if (path == Vault)
                return Json(200, JsonSerializer.Serialize(new
                {
                    id = ReturnedVault,
                    type = "Microsoft.KeyVault/vaults",
                    location = ReturnedLocation,
                    tags = new Dictionary<string, string?> { ["secretkit-fixture"] = VaultNonce },
                    properties = new { tenantId = ReturnedTenant, provisioningState = "Succeeded" }
                }));
            if (!path.StartsWith(Vault + "/providers/Microsoft.Insights/diagnosticSettings/sk-audit-", StringComparison.Ordinal))
                throw new InvalidOperationException("controlled-coordinate");
            if (method == "GET") return Settings is null ? Json(404, "{}") : Json(200, Settings);
            BeforeSend(path);
            if (method == "PUT")
            {
                if (CreateFault == "denied") return Json(403, "{}");
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                string acknowledgement = "{\"id\":" + JsonSerializer.Serialize(path) +
                    ",\"properties\":" + body.RootElement.GetProperty("properties").GetRawText() + "}";
                Settings = CreateFault == "no-op" ? null : acknowledgement;
                if (CreateFault == "wrong-workspace")
                    Settings = Settings!.Replace(Workspace, Workspace + "-other", StringComparison.Ordinal);
                if (CreateFault == "dedicated")
                    Settings = Settings!.Replace("\"logAnalyticsDestinationType\":null", "\"logAnalyticsDestinationType\":\"Dedicated\"", StringComparison.Ordinal);
                if (CreateFault == "extra-log")
                    Settings = Settings!.Replace("\"category\":\"AuditEvent\"", "\"category\":\"AllLogs\"", StringComparison.Ordinal);
                if (CreateFault is "storage" or "eventhub" or "partner")
                {
                    string name = CreateFault switch
                    {
                        "storage" => "storageAccountId",
                        "eventhub" => "eventHubAuthorizationRuleId",
                        _ => "marketplacePartnerId"
                    };
                    Settings = Settings!.Replace("\"metrics\":[]", "\"metrics\":[],\"" + name + "\":\"foreign-export\"", StringComparison.Ordinal);
                }
                if (CreateFault == "metrics")
                    Settings = Settings!.Replace("\"metrics\":[]", "\"metrics\":[{\"category\":\"AllMetrics\",\"enabled\":true}]", StringComparison.Ordinal);
                Applied?.TrySetResult();
                if (Terminate is not null) await Terminate.Task.ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                if (CreateFault == "lost") throw new IOException("protected-native-response-loss");
                var response = Json(CreateFault == "pending" ? 202 : 200, acknowledgement);
                if (CreateFault == "async-header")
                    response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", "https://management.azure.com/pending");
                return response;
            }
            if (method == "DELETE")
            {
                if (DeleteFault == "denied") return Json(403, "{}");
                if (DeleteFault != "no-op") Settings = null;
                if (DeleteFault == "lost") throw new IOException("protected-delete-response-loss");
                return Json(DeleteFault == "pending" ? 202 : 204, "");
            }
            throw new InvalidOperationException("controlled-method");
        }
    }
    private sealed class Backend(string role, WireState state) : HttpMessageHandler
    {
        internal bool Disposed;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            state.Respond(role, request, cancellationToken);
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
    private sealed class Credential(string role) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (requestContext.Scopes.Length != 1 || requestContext.Scopes[0] != "https://management.azure.com/.default")
                throw new InvalidOperationException("controlled-audience");
            return new(role, DateTimeOffset.MaxValue);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
    private static HttpResponseMessage Json(int status, string body) => new((HttpStatusCode)status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };
}
