using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSqlRotationPatchSourceTests
{
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://sql-patch-source.invalid/private/"), "service-token", "sql-patch-source", 30);

    [Test]
    public async Task OptionalSettingsLeaveExistingFactoryInputsValidAndBindExplicitTrial()
    {
        await using var store = new InfisicalSqlRotationPatchFixture();
        using var environment = store.Environment();
        var definition = InfisicalSqlRotationPatchFixture.Definition("Postgres", "patch.empty");
        await using var fixture = new InfisicalSqlRotationPatchFixture.Lease(store,
            "00000000-0000-0000-0000-000000000002", ProjectFamilyContext.FreshName(), definition);
        using var service = new SourceService(fixture.SqlRotationPatch!.Binding);
        var channel = new InfisicalLifecycleObservers(Settings, service);
        await Assert.That(SqlRotationPatchSource.FromInput(JsonSerializer.SerializeToElement(new { }),
            channel, environment, definition, InfisicalSqlRotationPatchFixture.Organization,
            fixture.Project, fixture)).IsNull();
        var trial = SqlRotationPatchSource.FromInput(JsonSerializer.SerializeToElement(new
        {
            sqlRotationPatch = new
            { version = "v0.166.3", deployment = "local", sourceId = "storage-reader", clockId = "clock", epoch = 7 }
        }), channel, environment, definition, InfisicalSqlRotationPatchFixture.Organization,
            fixture.Project, fixture)!;
        await Assert.That(trial.Binding.Case).IsEqualTo(definition);
        await Assert.That(trial.Binding.ProjectId).IsEqualTo(fixture.Project);
        await Assert.That(trial.Binding.Coordinate).IsEqualTo(fixture.BackendCoordinate);
        await Assert.That(trial.Binding.Version).IsEqualTo("v0.166.3");
        await Assert.That(trial.Binding.Nonce).IsNotEqualTo(fixture.SqlRotationPatch.Binding.Nonce);
        await Assert.That(trial.Binding.Epoch).IsEqualTo(7);
        await Assert.That(JsonSerializer.Serialize(trial.Binding)).IsEqualTo("{}");
    }

    [Test]
    public async Task SourceAdapterReadsProtectedCommittedColumnsAndOriginalTerminalJournal()
    {
        await using var store = new InfisicalSqlRotationPatchFixture();
        using var environment = store.Environment();
        var definition = InfisicalSqlRotationPatchFixture.Definition("Postgres", "patch.empty");
        await using var fixture = new InfisicalSqlRotationPatchFixture.Lease(store,
            "00000000-0000-0000-0000-000000000002", ProjectFamilyContext.FreshName(), definition);
        var binding = fixture.SqlRotationPatch!.Binding;
        using var service = new SourceService(binding);
        var source = new SqlRotationPatchSource(new(Settings, service), environment);
        await source.OpenAsync(binding, CancellationToken.None);
        using var read = await source.ReadAsync(binding, service.Rotation, CancellationToken.None);
        await Assert.That(read.Configuration.Username1).IsEqualTo("stored-user-a");
        await Assert.That(read.Statement!.Reveal()).IsEqualTo("stored-protected-statement");
        using var controls = await source.ControlsAsync(binding, service.Rotation, CancellationToken.None);
        await Assert.That(controls.Rows.Length).IsEqualTo(12);
        using var completed = await source.CompleteAsync(binding, service.Rotation,
            DispatchEvidence.PossiblyDispatched, CancellationToken.None);
        await Assert.That(completed.TerminalAttempts).IsEqualTo(1);
        await Assert.That(completed.Pending).IsEqualTo(0);
        await Assert.That(service.LastCallerReceipt).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await source.RecoverAsync(binding, CancellationToken.None);
        var remaining = await source.CloseAsync(binding, CancellationToken.None);
        await Assert.That(remaining.OwnedResources).IsEqualTo(0);
        await Assert.That(service.Registrations).IsEqualTo(0);
        await Assert.That(service.RecoveryRoots.All(r => r == binding.ProjectId)).IsTrue();
        await Assert.That(service.Disposed).IsFalse();
        await Assert.That(JsonSerializer.Serialize(read)).IsEqualTo("{}");
    }

    [Test]
    public async Task LostSourceReleaseAcknowledgementIsResolvedByExactRootReadWithoutReplay()
    {
        await using var store = new InfisicalSqlRotationPatchFixture();
        using var environment = store.Environment();
        var definition = InfisicalSqlRotationPatchFixture.Definition("Postgres", "patch.empty");
        await using var fixture = new InfisicalSqlRotationPatchFixture.Lease(store,
            "00000000-0000-0000-0000-000000000002", ProjectFamilyContext.FreshName(), definition);
        var binding = fixture.SqlRotationPatch!.Binding;
        using var service = new SourceService(binding);
        var source = new SqlRotationPatchSource(new(Settings, service), environment);
        await source.OpenAsync(binding, CancellationToken.None);
        service.Fault = "release-loss";
        var remaining = await source.CloseAsync(binding, CancellationToken.None);
        await Assert.That(remaining.SourceRegistrations).IsEqualTo(0);
        await Assert.That(service.ReleaseCalls).IsEqualTo(1);
        await Assert.That(service.RecoveryRoots.SequenceEqual(new[] { binding.ProjectId, binding.ProjectId })).IsTrue();
    }

    [Test]
    [Arguments("trialNonce")]
    [Arguments("provider")]
    [Arguments("operation")]
    [Arguments("variant")]
    [Arguments("scope")]
    [Arguments("case")]
    [Arguments("member")]
    [Arguments("organizationId")]
    [Arguments("projectId")]
    [Arguments("ownedName")]
    [Arguments("sourcePath")]
    [Arguments("connectionId")]
    [Arguments("host")]
    [Arguments("database")]
    [Arguments("version")]
    [Arguments("deployment")]
    [Arguments("sourceId")]
    [Arguments("clockId")]
    [Arguments("epoch")]
    [Arguments("profile")]
    [Arguments("port")]
    [Arguments("rotationId")]
    public async Task EverySourceBindingFieldIsCheckedInsteadOfTrustingReturnedTargets(string field)
    {
        await using var store = new InfisicalSqlRotationPatchFixture();
        using var environment = store.Environment();
        var definition = InfisicalSqlRotationPatchFixture.Definition("Postgres", "patch.empty");
        await using var fixture = new InfisicalSqlRotationPatchFixture.Lease(store,
            "00000000-0000-0000-0000-000000000002", ProjectFamilyContext.FreshName(), definition);
        var binding = fixture.SqlRotationPatch!.Binding;
        using var service = new SourceService(binding, field);
        var source = new SqlRotationPatchSource(new(Settings, service), environment);
        await Assert.That(async () =>
        {
            using var measured = await source.ReadAsync(binding, service.Rotation, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        // The recovery target stays the caller-owned root even after a substituted reply.
        service.Fault = null;
        await source.RecoverAsync(binding, CancellationToken.None);
        await source.CloseAsync(binding, CancellationToken.None);
        await Assert.That(service.RecoveryRoots.All(r => r == binding.ProjectId)).IsTrue();
    }

    // Adapter calibration only. Fixed journals intentionally differ from request
    // coordinates and are never constructed from the incoming request body.
    private sealed class SourceService(SqlRotationPatchBinding binding, string? fault = null) : HttpMessageHandler
    {
        internal string? Fault { get; set; } = fault;
        internal string Rotation { get; } = "00000000-0000-0000-0000-000000000009";
        internal int Registrations { get; private set; }
        internal bool Disposed { get; private set; }
        internal DispatchEvidence? LastCallerReceipt { get; private set; }
        internal int ReleaseCalls { get; private set; }
        internal List<string> RecoveryRoots { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            var sent = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!.AsObject();
            string action = request.RequestUri!.Segments[^1];
            JsonObject reply = Identity();
            if (action == "arm") Registrations = 1;
            if (action == "complete") LastCallerReceipt = (DispatchEvidence)sent["receipt"]!.GetValue<int>();
            if (action is "recover" or "release" or "remaining")
                RecoveryRoots.Add(sent["projectId"]!.GetValue<string>());
            if (action == "release")
            {
                Registrations = 0;
                ReleaseCalls++;
                if (Fault == "release-loss") throw new HttpRequestException("lost-source-release-reply");
            }
            reply["sourceRegistrations"] = Registrations;
            reply["pending"] = 0; reply["locks"] = 0;
            reply["borrowedStatePreserved"] = true; reply["ownedResources"] = 0;
            reply["attempts"] = 0; reply["terminalAttempts"] = 0;
            if (action is "read" or "complete") reply = State(action == "complete");
            if (action == "controls") reply["rows"] = new JsonArray(SqlRotationPatchTrial.RejectionControls
                .Select(name => (JsonNode)new JsonObject { ["name"] = name, ["status"] = 400, ["state"] = State(false) }).ToArray());
            if (Fault is "epoch" or "profile" or "port") reply[Fault] = 999;
            else if (Fault is not null && Fault != "release-loss") reply[Fault] = "foreign";
            var envelope = new JsonObject
            {
                ["schemaVersion"] = 1,
                ["nonce"] = sent["nonce"]!.DeepClone(),
                ["observerIdentity"] = Settings.Identity,
                ["observedAt"] = DateTimeOffset.UtcNow,
                ["facts"] = reply
            };
            return new(HttpStatusCode.OK)
            { Content = new StringContent(envelope.ToJsonString(), Encoding.UTF8, "application/json") };
        }
        private JsonObject Identity() => new()
        {
            ["trialNonce"] = binding.Nonce,
            ["provider"] = binding.Case.Key.Provider,
            ["operation"] = binding.Case.Key.Operation,
            ["variant"] = binding.Case.Key.Variant,
            ["scope"] = binding.Case.Key.Scope,
            ["case"] = binding.Case.Key.Case,
            ["member"] = binding.Case.Member,
            ["organizationId"] = binding.OrganizationId,
            ["projectId"] = binding.ProjectId,
            ["ownedName"] = binding.OwnedName,
            ["sourcePath"] = binding.SourcePath,
            ["profile"] = (int)binding.Coordinate.Profile,
            ["host"] = binding.Coordinate.Host,
            ["port"] = binding.Coordinate.Port,
            ["database"] = binding.Coordinate.Database,
            ["connectionId"] = binding.Coordinate.ConnectionId,
            ["version"] = binding.Version,
            ["deployment"] = binding.Deployment,
            ["sourceId"] = binding.SourceId,
            ["clockId"] = binding.ClockId,
            ["epoch"] = binding.Epoch
        };
        private JsonObject State(bool completed)
        {
            JsonObject state = Identity();
            state["rotationId"] = Rotation;
            state["configuration"] = new JsonObject
            {
                ["name"] = "stored-name",
                ["connectionId"] = binding.Coordinate.ConnectionId,
                ["environment"] = "stored-environment",
                ["path"] = binding.SourcePath,
                ["username1"] = "stored-user-a",
                ["username2"] = "stored-user-b",
                ["usernameKey"] = "STORED_USER",
                ["passwordKey"] = "STORED_PASSWORD",
                ["interval"] = 2,
                ["hours"] = 2,
                ["minutes"] = 3,
                ["enabled"] = false,
                ["hasDescription"] = true,
                ["description"] = null,
                ["passwordRequirements"] = null
            };
            state["rotationStatement"] = "stored-protected-statement";
            state["attempts"] = completed ? 1 : 0; state["terminalAttempts"] = completed ? 1 : 0;
            state["pending"] = 0; state["locks"] = 0; state["scheduled"] = completed ? 1 : 0;
            state["sourceRegistrations"] = Registrations; state["ownedRotations"] = 1;
            state["borrowedStatePreserved"] = true; state["observedAt"] = InfisicalSqlRotationPatchFixture.Date;
            return state;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
