using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class LocalNativeProofTests
{
    [Test]
    public async Task UncertainForeignMembershipProtectsBothOwnedParentsDuringCleanup()
    {
        var clock = new ProofTime();
        var backend = new CausalBackend(clock) { LoseForeignMembershipAcknowledgement = true };
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        await using var proof = new LocalNativeProof(sandbox, Selection(server.Origin),
            LocalProfileAdmissionTests.Binding, timeProvider: clock);
        await Assert.That(async () => await proof.ProduceAsync(CancellationToken.None))
            .Throws<InvalidOperationException>();
        LocalProducerCleanup cleanup = await proof.CleanupAsync(CancellationToken.None);
        await Assert.That(cleanup.Status).IsEqualTo("incomplete");
        await Assert.That(backend.OnlyUncertainForeignMembershipAndBothParentsRemain).IsTrue();
    }

    [Test]
    public async Task RejectedRecoveryRenewalSettlesItsProducerLedgerBeforeCleanup()
    {
        var clock = new ProofTime();
        var backend = new CausalBackend(clock) { RenewalFault = "q06-denied" };
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        await using var proof = new LocalNativeProof(sandbox, Selection(server.Origin),
            LocalProfileAdmissionTests.Binding, timeProvider: clock);
        var input = proof.AdmitProduced(await proof.ProduceAsync(CancellationToken.None));
        var report = NativeWorkflow.EmptyReport(input);
        proof.BeginChild();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await NativeWorkflow.ExecuteAsync(input, report, deadline.Token, () => Task.CompletedTask,
            proof.ExchangeAsync, proof.AcknowledgeRenewalAsync, clock, clock.Probe);
        proof.ObserveChildReport(report);
        await Assert.That(report.SupplementalCases.Single(c => c.Id == "Q06").Status).IsEqualTo("failed");
        await LocalProfileConformance.ReconcileCleanupAsync(report,
            () => proof.RemoveSecretAsync(input.Settings.ProjectId, input.Settings.Environment,
                input.Settings.Folder, input.Settings.WriteKey, deadline.Token), () => Task.CompletedTask);
        await Assert.That(await proof.CleanupAsync(deadline.Token))
            .IsEqualTo(new LocalProducerCleanup("complete", 0, 0));
        await Assert.That(backend.OwnedResourcesRemain).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ProducedChainChallengesTheSameRuntimeActorInPopulatedForeignScope(bool permitForeignRuntime)
    {
        var clock = new ProofTime();
        var backend = new CausalBackend(clock) { PermitForeignRuntime = permitForeignRuntime };
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        var selection = Selection(server.Origin);
        await using var proof = new LocalNativeProof(sandbox, selection, LocalProfileAdmissionTests.Binding, timeProvider: clock);
        byte[] bytes = await proof.ProduceAsync(CancellationToken.None);
        var input = proof.AdmitProduced(bytes);
        var report = NativeWorkflow.EmptyReport(input);
        proof.BeginChild();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await NativeWorkflow.ExecuteAsync(input, report, deadline.Token, () => Task.CompletedTask,
            proof.ExchangeAsync, proof.AcknowledgeRenewalAsync, clock, clock.Probe);
        report = JsonSerializer.Deserialize<LocalNativeReport>(JsonSerializer.Serialize(report,
            NativeWorkflow.JsonOptions), NativeWorkflow.JsonOptions)!;
        proof.ObserveChildReport(report);
        LocalProfileConformance.ValidateReport(report, input.Binding, proof);
        await Assert.That(report.Cases.Single(c => c.Id == "actor-binding").Status)
            .IsEqualTo(permitForeignRuntime ? "failed" : "passed");
        await Assert.That(report.Cases.Single(c => c.Id == "policy-binding").Status)
            .IsEqualTo(permitForeignRuntime ? "failed" : "passed");
        await Assert.That(backend.ForeignObserverReads).IsEqualTo(2);
        await Assert.That(backend.ForeignRuntimeReads).IsEqualTo(2);
        await Assert.That(report.SupplementalCases.Select(c => c.Id))
            .IsEquivalentTo(["Q01", "Q02", "Q03", "Q04", "Q05", "Q06"]);
        await Assert.That(report.SupplementalCases.All(c => c.Status == "passed")).IsTrue();
        await Assert.That(backend.OneUseReads).IsEqualTo(2);
        await Assert.That(backend.OneUseRenewals).IsEqualTo(0);
        await Assert.That(backend.ConsumedBootstrapAttempts).IsEqualTo(1);
        await Assert.That(backend.RecoveryBootstraps).IsEqualTo(2);
        await LocalProfileConformance.ReconcileCleanupAsync(report,
            () => proof.RemoveSecretAsync(input.Settings.ProjectId, input.Settings.Environment,
                input.Settings.Folder, input.Settings.WriteKey, deadline.Token), () => Task.CompletedTask);
        report.ProducerCleanup = await proof.CleanupAsync(deadline.Token);
        await Assert.That(report.ProducerCleanup).IsEqualTo(new LocalProducerCleanup("complete", 0, 0));
        await Assert.That(backend.OwnedResourcesRemain).IsFalse();
        string output = JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions);
        foreach (string canary in new[] { input.Settings.Runtime.Token, input.Settings.ProjectId,
            input.Settings.Issuance!.ExpectedReadValue, input.Settings.Issuance.ForeignValue })
            await Assert.That(output.Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("token")]
    [Arguments("run")]
    [Arguments("namespace")]
    [Arguments("candidate")]
    [Arguments("trial-order")]
    public async Task ProducedEnvelopeCannotBeSubstitutedOrImportedAsSetupSelection(string fault)
    {
        var clock = new ProofTime();
        var backend = new CausalBackend(clock);
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        await using var proof = new LocalNativeProof(sandbox, Selection(server.Origin),
            LocalProfileAdmissionTests.Binding, timeProvider: clock);
        byte[] bytes = await proof.ProduceAsync(CancellationToken.None);
        await Assert.That(() => LocalProfileConformance.Admit(bytes, LocalProfileAdmissionTests.Binding))
            .Throws<InvalidOperationException>();
        JsonNode substituted = JsonNode.Parse(bytes)!;
        switch (fault)
        {
            case "token": substituted["settings"]!["runtime"]!["token"] = "substituted-issued-token"; break;
            case "run": substituted["settings"]!["issuance"]!["runId"] = Guid.NewGuid().ToString("N"); break;
            case "namespace": substituted["settings"]!["projectId"] = Guid.NewGuid().ToString(); break;
            case "candidate": substituted["binding"]!["sourceSha256"] = new string('f', 64); break;
            case "trial-order": substituted["settings"]!["issuance"]!["trialIds"]![0] = "Q02"; break;
        }
        await Assert.That(() => proof.AdmitProduced(JsonSerializer.SerializeToUtf8Bytes(substituted, NativeWorkflow.JsonOptions)))
            .Throws<InvalidOperationException>();
        var report = NativeWorkflow.EmptyReport(proof.AdmitProduced(bytes)) with { ProofRun = Guid.NewGuid().ToString("N") };
        await Assert.That(() => LocalProfileConformance.ValidateReport(report, report.Binding, proof))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("duplicate")]
    [Arguments("substituted")]
    [Arguments("omitted-property")]
    public async Task ReportParserAndAdmissionRequireTheCompleteTrialDenominator(string fault)
    {
        var input = LocalProfileConformance.Admit(JsonSerializer.SerializeToUtf8Bytes(LocalProfileAdmissionTests.Request(),
            NativeWorkflow.JsonOptions), LocalProfileAdmissionTests.Binding);
        var report = NativeWorkflow.EmptyReport(input);
        if (fault == "omitted-property")
        {
            var wire = JsonSerializer.SerializeToNode(report, NativeWorkflow.JsonOptions)!.AsObject();
            wire.Remove("supplementalCases");
            await Assert.That(() => JsonSerializer.Deserialize<LocalNativeReport>(wire.ToJsonString(),
                NativeWorkflow.JsonOptions)).Throws<JsonException>();
            return;
        }
        report = report with
        {
            SupplementalCases = fault switch
            {
                "missing" => report.SupplementalCases[1..],
                "duplicate" => [report.SupplementalCases[0], .. report.SupplementalCases[..^1]],
                _ => [new("Q99", "passed", "observed"), .. report.SupplementalCases[1..]]
            }
        };
        await Assert.That(() => LocalProfileConformance.ValidateReport(report, input.Binding))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("partial-setup")]
    [Arguments("failed-launch")]
    [Arguments("child-failure")]
    [Arguments("observer-failure")]
    [Arguments("cancelled")]
    public async Task WholeProducerFinalizationCleansOnlyAcknowledgedResources(string failure)
    {
        using var ledger = new LocalProducerLedger("protected-owner", "protected-run");
        var live = new HashSet<string>(StringComparer.Ordinal);
        var history = new List<string>();
        try
        {
            ledger.Add("identity:acknowledged", 20, null);
            live.Add("identity:acknowledged");
            if (failure == "partial-setup") throw new IOException();
            ledger.Add("configuration:acknowledged", 40, "identity:acknowledged");
            live.Add("configuration:acknowledged");
            if (failure == "failed-launch") throw new IOException();
            ledger.Add("bootstrap:acknowledged", 50, "configuration:acknowledged");
            live.Add("bootstrap:acknowledged");
            int unknown = ledger.Begin("uncertain-issuance");
            ledger.Effect(unknown, DispatchEvidence.PossiblyDispatched);
            if (failure == "cancelled") throw new OperationCanceledException();
            throw new IOException();
        }
        catch (Exception error) when (error is IOException or OperationCanceledException) { }
        finally
        {
            var cleanup = await ledger.CleanupAsync((handle, _) =>
            {
                history.Add(handle);
                return Task.FromResult(live.Remove(handle));
            }, CancellationToken.None);
            await Assert.That(cleanup.OutstandingKnown).IsEqualTo(0);
            await Assert.That(cleanup.Uncertain).IsEqualTo(failure is "partial-setup" or "failed-launch" ? 0 : 1);
        }
        await Assert.That(live.Count).IsEqualTo(0);
        await Assert.That(history.Last()).IsEqualTo("identity:acknowledged");
        await Assert.That(history.Any(h => h.Contains("uncertain", StringComparison.Ordinal))).IsFalse();
        // Calling teardown again cannot replay acknowledged or uncertain removals.
        await ledger.CleanupAsync((_, _) => throw new InvalidOperationException(), CancellationToken.None);
    }

    [Test]
    public async Task UncertainChildCleanupPreservesParentsAndStillCleansIndependentResources()
    {
        using var ledger = new LocalProducerLedger("protected-owner", "protected-run");
        ledger.Add("identity:a", 20, null);
        ledger.Add("bootstrap:a", 50, "identity:a");
        ledger.Add("identity:b", 20, null);
        var removed = new List<string>();
        var result = await ledger.CleanupAsync((handle, _) =>
        {
            removed.Add(handle);
            return Task.FromResult(handle != "bootstrap:a");
        }, CancellationToken.None);
        await Assert.That(result).IsEqualTo(new LocalProducerCleanup("incomplete", 2, 0));
        await Assert.That(removed.Contains("identity:a", StringComparer.Ordinal)).IsFalse();
        await Assert.That(removed.Contains("identity:b", StringComparer.Ordinal)).IsTrue();
    }

    [Test]
    public async Task PartialTypedSetupFailureStillRemovesTheAcknowledgedProject()
    {
        var backend = new CausalBackend(new ProofTime()) { FailFixtureCreate = true };
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        await using var proof = new LocalNativeProof(sandbox, Selection(server.Origin), LocalProfileAdmissionTests.Binding);
        await Assert.That(async () => await proof.ProduceAsync(CancellationToken.None)).Throws<InvalidOperationException>();
        var cleanup = await proof.CleanupAsync(CancellationToken.None);
        await Assert.That(cleanup).IsEqualTo(new LocalProducerCleanup("complete", 0, 0));
        await Assert.That(backend.OwnedResourcesRemain).IsFalse();
    }

    [Test]
    [Arguments("denied")]
    [Arguments("unknown")]
    [Arguments("cancelled")]
    [Arguments("unavailable")]
    public async Task TrialCannotPromoteRejectedUnknownCancelledOrUnestablishedEvidence(string fault)
    {
        var clock = new ProofTime();
        var backend = new CausalBackend(clock);
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        await using var proof = new LocalNativeProof(sandbox, Selection(server.Origin), LocalProfileAdmissionTests.Binding,
            timeProvider: clock);
        var input = proof.AdmitProduced(await proof.ProduceAsync(CancellationToken.None));
        var started = await proof.ExchangeAsync("Q01", "start", CancellationToken.None);
        backend.RenewalFault = fault;
        using var handler = Handler();
        using var cancellation = new CancellationTokenSource();
        LocalNativeTrial trial = fault == "unavailable" ? started.Issued! with { PeriodSeconds = 60 } : started.Issued!;
        if (fault == "cancelled") cancellation.Cancel();
        var observed = await NativeLifetimeTrials.RunAsync(trial, input.Settings, handler, clock,
            (operation, ct) => proof.ExchangeAsync("Q01", operation, ct),
            (value, effect, ct) => proof.AcknowledgeRenewalAsync("Q01", value, effect, ct),
            cancellation.Token, clock.Probe);
        await Assert.That(observed.Status).IsEqualTo(fault == "denied" ? "failed" : "unavailable");
        var cleanup = await proof.CleanupAsync(CancellationToken.None);
        await Assert.That(cleanup.Uncertain).IsEqualTo(fault == "unknown" ? 1 : 0);
    }

    [Test]
    [Arguments("handoff-time")]
    [Arguments("run")]
    [Arguments("candidate")]
    [Arguments("project")]
    public async Task TrialScopeAndOriginalExpiryRejectStaleHandoffBeforeAnySelectedOperation(string fault)
    {
        var clock = new ProofTime();
        var backend = new CausalBackend(clock);
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        await using var proof = new LocalNativeProof(sandbox, Selection(server.Origin),
            LocalProfileAdmissionTests.Binding, timeProvider: clock);
        var input = proof.AdmitProduced(await proof.ProduceAsync(CancellationToken.None));
        LocalNativeTrial trial = (await proof.ExchangeAsync("Q01", "start", CancellationToken.None)).Issued!;
        trial = fault switch
        {
            "run" => trial with { Scope = trial.Scope with { RunId = Guid.NewGuid().ToString("N") } },
            "candidate" => trial with { Scope = trial.Scope with { RecordSha256 = new string('f', 64) } },
            "project" => trial with { Scope = trial.Scope with { ProjectId = Guid.NewGuid().ToString() } },
            _ => trial
        };
        if (fault == "handoff-time") await clock.Probe(trial.CompletedAt.AddSeconds(9), CancellationToken.None);
        using var handler = Handler();
        var result = await NativeLifetimeTrials.RunAsync(trial, input.Settings, handler, clock,
            (_, _) => throw new InvalidOperationException("Unexpected exchange."),
            (_, _, _) => throw new InvalidOperationException("Unexpected renewal."),
            CancellationToken.None, clock.Probe);
        await Assert.That(result.Status).IsEqualTo("unavailable");
        await Assert.That(backend.OneUseReads).IsEqualTo(0);
    }

    [Test]
    public async Task AReportCannotPromoteBindingLabelsWithoutTheirNativeChallenges()
    {
        var clock = new ProofTime();
        var backend = new CausalBackend(clock) { PermitForeignRuntime = true };
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        await using var proof = new LocalNativeProof(sandbox, Selection(server.Origin),
            LocalProfileAdmissionTests.Binding, timeProvider: clock);
        var input = proof.AdmitProduced(await proof.ProduceAsync(CancellationToken.None));
        var report = NativeWorkflow.EmptyReport(input);
        foreach (string id in new[] { "actor-binding", "policy-binding", "read", "read-native", "denied-read", "runtime-write-denied" })
        {
            int index = Array.IndexOf(NativeWorkflow.CaseIds, id);
            report.Cases[index] = new(id, "passed", "observed");
        }
        await Assert.That(() => LocalProfileConformance.ValidateReport(report, report.Binding, proof))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ProtectedLedgerRetainsExactRecoveryCoordinatesWithoutCredentialOrFixtureMaterial()
    {
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-proof-ledger-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "ledger.jsonl");
        try
        {
            var clock = new ProofTime();
            var backend = new CausalBackend(clock);
            await using var server = new ProofServer(backend.Handle);
            using var sandbox = Sandbox(server.Origin);
            await using var proof = new LocalNativeProof(sandbox, Selection(server.Origin),
                LocalProfileAdmissionTests.Binding, path, clock);
            var input = proof.AdmitProduced(await proof.ProduceAsync(CancellationToken.None));
            string[] rows = await File.ReadAllLinesAsync(path);
            using var row = JsonDocument.Parse(rows[^1]);
            await Assert.That(row.RootElement.GetProperty("resources").EnumerateArray()
                .Any(r => r.GetProperty("coordinates").EnumerateArray()
                    .Any(c => c.GetString() == input.Settings.ProjectId))).IsTrue();
            string ledger = string.Join('\n', rows);
            foreach (string material in new[] { input.Settings.Runtime.Token, input.Settings.Writer.Token,
                input.Settings.Issuance!.ExpectedReadValue, input.Settings.Issuance.ForeignValue })
                await Assert.That(ledger.Contains(material, StringComparison.Ordinal)).IsFalse();
            if (!OperatingSystem.IsWindows())
                await Assert.That(File.GetUnixFileMode(path)).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PendingApprovalCannotBecomeCompleteProducerCleanupWithoutAnOwnedTeardownInterface(
        bool applyDespitePending)
    {
        var clock = new ProofTime();
        var backend = new CausalBackend(clock)
        { SubmitApproval = true, ApplyDespitePending = applyDespitePending };
        await using var server = new ProofServer(backend.Handle);
        using var sandbox = Sandbox(server.Origin);
        var selection = Selection(server.Origin) with { ApprovalKey = "SDK_12345678_APPROVAL" };
        await using var proof = new LocalNativeProof(sandbox, selection,
            LocalProfileAdmissionTests.Binding, timeProvider: clock);
        var input = proof.AdmitProduced(await proof.ProduceAsync(CancellationToken.None));
        using var observer = new LocalNativeTokens(input.Settings.Observer.Token);
        using var handler = Handler();
        await using var witness = new InfisicalClient(server.Origin, observer,
            new()
            {
                AllowLoopbackDevelopmentHttp = true,
                Transport = InfisicalTransportOptions.HostControlled(handler)
            });
        var approvalReference = new SecretReference(witness.Authority,
            new InfisicalSecretAddress(input.Settings.ProjectId, input.Settings.Environment,
                input.Settings.Folder, input.Settings.ApprovalKey!));
        var before = await witness.ReadNativeAsync(approvalReference, CancellationToken.None);
        await Assert.That(before.Status).IsEqualTo(SecretStatus.Absent);
        proof.BeginChild();
        var report = NativeWorkflow.EmptyReport(input);
        await NativeWorkflow.ExecuteAsync(input, report, CancellationToken.None, () => Task.CompletedTask,
            proof.ExchangeAsync, proof.AcknowledgeRenewalAsync, clock, clock.Probe);
        proof.ObserveChildReport(report);
        await Assert.That(report.Cases.Single(c => c.Id == "pending-approval").Status).IsEqualTo("unavailable");
        await Assert.That(report.Cases.Single(c => c.Id == "pending-approval").Reason)
            .IsEqualTo("observation-unavailable");
        await Assert.That(report.ApprovalEffect).IsEqualTo(DispatchEvidence.Pending);
        var after = await witness.ReadNativeAsync(approvalReference, CancellationToken.None);
        await Assert.That(after.IsSuccess).IsEqualTo(applyDespitePending);
        if (after.IsSuccess) after.Value.Dispose();
        else await Assert.That(after.Status).IsEqualTo(SecretStatus.Absent);
        await LocalProfileConformance.ReconcileCleanupAsync(report, () => proof.RemoveSecretAsync(input.Settings.ProjectId,
            input.Settings.Environment, input.Settings.Folder, input.Settings.WriteKey, CancellationToken.None),
            () => Task.CompletedTask);
        var cleanup = await proof.CleanupAsync(CancellationToken.None);
        await Assert.That(cleanup).IsEqualTo(new LocalProducerCleanup("incomplete", 0, 1));
        await Assert.That(backend.ApprovalSubmissions).IsEqualTo(1);
    }

    private static SocketsHttpHandler Handler() => new()
    { AllowAutoRedirect = false, UseCookies = false, ActivityHeadersPropagator = null };
    private static LocalNativeSettings Selection(Uri origin)
    {
        var request = LocalProfileAdmissionTests.Request();
        request["settings"]!["origin"] = origin.AbsoluteUri;
        request["settings"]!["authentication"] = null;
        return LocalProfileConformance.Admit(JsonSerializer.SerializeToUtf8Bytes(request,
            NativeWorkflow.JsonOptions), LocalProfileAdmissionTests.Binding).Settings;
    }
    private static OwnedSandbox Sandbox(Uri origin)
    {
        using var setup = SecretMaterial.FromText("setup-token-canary");
        var sandbox = new OwnedSandbox(origin, "secretkit-sdk-12345678",
            "20000000-0000-0000-0000-000000000001", setup);
        sandbox.ObserveInspection("""{"secretkit-sdk-owned":"true"}""", OwnedSandbox.AppDigest,
            $"8080/tcp -> 127.0.0.1:{origin.Port}");
        return sandbox;
    }

    [Test]
    public async Task RevisionOnlyUpdateDoesNotSatisfyReplacementObservation()
    {
        await using var server = new ProofServer();
        var request = LocalProfileAdmissionTests.Request();
        request["settings"]!["origin"] = server.Origin.AbsoluteUri;
        request["settings"]!["authentication"] = null;
        var input = LocalProfileConformance.Admit(JsonSerializer.SerializeToUtf8Bytes(request,
            NativeWorkflow.JsonOptions), LocalProfileAdmissionTests.Binding);
        var report = NativeWorkflow.EmptyReport(input);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await NativeWorkflow.ExecuteAsync(input, report, deadline.Token, () => Task.CompletedTask);
        await Assert.That(report.Cases.Single(c => c.Id == "create").Status).IsEqualTo("passed");
        await Assert.That(report.Cases.Single(c => c.Id == "update-value").Status).IsEqualTo("failed");
    }

    [Test]
    public async Task PreDispatchReportPreservesAllSixOrderedTrialObligations()
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(LocalProfileAdmissionTests.Request(),
            NativeWorkflow.JsonOptions);
        var input = LocalProfileConformance.Admit(bytes, LocalProfileAdmissionTests.Binding);
        using var report = JsonDocument.Parse(JsonSerializer.Serialize(
            NativeWorkflow.EmptyReport(input), NativeWorkflow.JsonOptions));
        await Assert.That(report.RootElement.TryGetProperty("supplementalCases", out _)).IsTrue();
        string[] expected = ["Q01", "Q02", "Q03", "Q04", "Q05", "Q06"];
        await Assert.That(report.RootElement.GetProperty("supplementalCases").EnumerateArray()
            .Select(c => c.GetProperty("id").GetString()).SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task PreDispatchReportCannotConfuseSecretCleanupWithProducerCleanup()
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(LocalProfileAdmissionTests.Request(),
            NativeWorkflow.JsonOptions);
        var input = LocalProfileConformance.Admit(bytes, LocalProfileAdmissionTests.Binding);
        using var report = JsonDocument.Parse(JsonSerializer.Serialize(
            NativeWorkflow.EmptyReport(input), NativeWorkflow.JsonOptions));
        await Assert.That(report.RootElement.TryGetProperty("producerCleanup", out _)).IsTrue();
        await Assert.That(report.RootElement.GetProperty("producerCleanup")
            .GetProperty("status").GetString()).IsEqualTo("unavailable");
    }

    private sealed class ProofTime : TimeProvider
    {
        private DateTimeOffset now = new(2026, 10, 24, 12, 0, 0, TimeSpan.Zero);
        private readonly List<ProofTimer> timers = [];
        public override DateTimeOffset GetUtcNow() => now;
        public override long GetTimestamp() => now.UtcTicks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ProofTimer(this, callback, state);
            timers.Add(timer);
            timer.Change(dueTime, period);
            return timer;
        }
        internal Task Probe(DateTimeOffset at, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            NativeWorkflow.Require(at >= now);
            now = at;
            foreach (var timer in timers.ToArray()) timer.Fire(now);
            return Task.CompletedTask;
        }
        private sealed class ProofTimer(ProofTime clock, TimerCallback callback, object? state) : ITimer
        {
            private DateTimeOffset? due;
            private TimeSpan period;
            public bool Change(TimeSpan dueTime, TimeSpan interval)
            {
                due = dueTime == Timeout.InfiniteTimeSpan ? null : clock.now + dueTime;
                period = interval;
                return true;
            }
            internal void Fire(DateTimeOffset at)
            {
                if (due is not { } instant || instant > at) return;
                due = period == Timeout.InfiniteTimeSpan ? null : at + period;
                callback(state);
            }
            public void Dispose() => due = null;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }

    // Stateful native protocol model: SDK/management parsers and actual loopback
    // HTTP remain in the path. This is deliberately not native qualification.
    private sealed class CausalBackend(ProofTime clock)
    {
        private const string Org = "20000000-0000-0000-0000-000000000001";
        private const string Primary = "30000000-0000-0000-0000-000000000001";
        private const string Date = "2026-10-24T12:00:00Z";
        private readonly Dictionary<string, JsonObject> projects = [];
        private readonly Dictionary<string, JsonObject> identities = [];
        private readonly Dictionary<(string, string), (string Id, string Role)> memberships = [];
        private readonly Dictionary<string, JsonObject> configurations = [];
        private readonly Dictionary<string, BootstrapState> bootstraps = [];
        private readonly Dictionary<string, TokenState> tokens = [];
        private readonly Dictionary<(string Project, string Environment, string Folder, string Key), JsonObject> values = [];
        internal bool PermitForeignRuntime { get; init; }
        internal bool FailFixtureCreate { get; init; }
        internal bool SubmitApproval { get; init; }
        internal bool ApplyDespitePending { get; init; }
        internal bool LoseForeignMembershipAcknowledgement { get; init; }
        internal int ApprovalSubmissions { get; private set; }
        internal string? RenewalFault { get; set; }
        internal int ForeignRuntimeReads { get; private set; }
        internal int ForeignObserverReads { get; private set; }
        internal int OneUseReads { get; private set; }
        internal int OneUseRenewals { get; private set; }
        internal int ConsumedBootstrapAttempts { get; private set; }
        internal int RecoveryBootstraps { get; private set; }
        internal bool OwnedResourcesRemain => projects.Count != 0 || identities.Count != 0 || memberships.Count != 0 ||
            configurations.Count != 0 || bootstraps.Count != 0 || values.Count != 0 || tokens.Values.Any(t => !t.Revoked);
        internal bool OnlyUncertainForeignMembershipAndBothParentsRemain =>
            memberships.Count == 1 && projects.Count == 1 && identities.Count == 1 &&
            memberships.Keys.All(pair => projects.ContainsKey(pair.Item1) && identities.ContainsKey(pair.Item2)) &&
            configurations.Count == 0 && bootstraps.Count == 0 && values.Count == 0 &&
            tokens.Values.All(token => token.Revoked);

        internal (int, object) Handle(string method, Uri uri, Dictionary<string, string> headers, string body)
        {
            string path = uri.AbsolutePath;
            string[] parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            JsonObject data = body.Length == 0 ? new() : JsonNode.Parse(body)!.AsObject();
            if (path == "/api/v1/auth/universal-auth/login")
            {
                string secret = data["clientSecret"]!.GetValue<string>();
                if (!bootstraps.TryGetValue(secret, out var bootstrap) ||
                    data["clientId"]!.GetValue<string>() != configurations[bootstrap.Actor]["clientId"]!.GetValue<string>())
                    return (403, new { });
                if (bootstrap.Limit == 1 && bootstrap.Uses == 1)
                {
                    ConsumedBootstrapAttempts++;
                    return (403, new { });
                }
                bootstrap.Uses++;
                return Issue(bootstrap.Actor);
            }
            if (path == "/api/v1/auth/token/revoke")
            {
                if (!tokens.TryGetValue(data["accessToken"]!.GetValue<string>(), out var selected)) return (403, new { });
                selected.Revoked = true;
                return (200, new { message = "revoked" });
            }
            if (path == "/api/v1/auth/token/renew")
            {
                string current = data["accessToken"]!.GetValue<string>();
                TokenState selected = tokens[current];
                if (Purpose(selected.Actor) == "Q05") OneUseRenewals++;
                if (RenewalFault == "denied" || RenewalFault == "q06-denied" && Purpose(selected.Actor) == "Q06")
                    return (403, new { });
                if (RenewalFault == "unknown") return (200, new { malformed = true });
                if (selected.Revoked || clock.GetUtcNow() >= selected.Expiry ||
                    selected.Period == 0 && clock.GetUtcNow() >= selected.Ceiling) return (403, new { });
                return Issue(selected.Actor, selected.Ceiling);
            }
            if (path == "/api/v1/projects" && method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                var row = new JsonObject
                {
                    ["id"] = id,
                    ["_id"] = id,
                    ["orgId"] = Org,
                    ["name"] = data["projectName"]!.DeepClone(),
                    ["slug"] = data["slug"]!.DeepClone(),
                    ["type"] = "secret-manager",
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["environments"] = new JsonArray(),
                    ["deletedEnvironments"] = new JsonArray()
                };
                projects.Add(id, row);
                return (200, new { project = row });
            }
            if (parts.Length == 4 && parts[2] == "projects" && method == "DELETE")
            {
                JsonObject row = projects[parts[3]];
                projects.Remove(parts[3]);
                row.Remove("_id");
                row.Remove("environments");
                row.Remove("deletedEnvironments");
                return (200, new { project = row });
            }
            if (path == "/api/v1/identities" && method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                var row = new JsonObject
                {
                    ["id"] = id,
                    ["name"] = data["name"]!.DeepClone(),
                    ["orgId"] = Org,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["authMethods"] = new JsonArray(),
                    ["metadata"] = new JsonArray()
                };
                identities.Add(id, row);
                return (200, new { identity = row });
            }
            if (parts.Length == 4 && parts[2] == "identities")
            {
                string id = parts[3];
                var identity = identities[id].DeepClone().AsObject();
                if (method == "DELETE")
                {
                    identities.Remove(id);
                    identity.Remove("authMethods");
                    identity.Remove("metadata");
                    return (200, new { identity });
                }
                identity["activeLockoutAuthMethods"] = new JsonArray();
                identity.Remove("createdAt");
                identity.Remove("updatedAt");
                identity.Remove("metadata");
                return (200, new
                {
                    identity = new
                    {
                        id = Guid.NewGuid().ToString(),
                        orgId = Org,
                        identityId = id,
                        role = "no-access",
                        createdAt = Date,
                        updatedAt = Date,
                        metadata = Array.Empty<object>(),
                        identity
                    }
                });
            }
            if (parts.Length == 7 && parts[2] == "projects" && parts[4] == "memberships")
            {
                string project = parts[3], actor = parts[6];
                if (method == "POST")
                {
                    memberships.Add((project, actor), (Guid.NewGuid().ToString(), data["roles"]![0]!["role"]!.GetValue<string>()));
                    if (LoseForeignMembershipAcknowledgement && project != Primary && Purpose(actor) == "observer")
                        return (200, new { malformed = true });
                }
                var membership = memberships[(project, actor)];
                if (method == "GET")
                {
                    var identity = identities[actor].DeepClone().AsObject();
                    identity.Remove("createdAt");
                    identity.Remove("updatedAt");
                    return (200, new
                    {
                        identityMembership = new
                        {
                            id = membership.Id,
                            createdAt = Date,
                            updatedAt = Date,
                            identity,
                            roles = new[]
                            {
                                new { id = Guid.NewGuid().ToString(), role = membership.Role, isTemporary = false }
                            }
                        }
                    });
                }
                if (method == "DELETE") memberships.Remove((project, actor));
                return (200, new
                {
                    identityMembership = new { id = membership.Id, projectId = project, identityId = actor, createdAt = Date, updatedAt = Date }
                });
            }
            if (path == "/api/v2/identity-project-additional-privilege") return (200, new { privileges = Array.Empty<object>() });
            if (parts.Length >= 6 && parts[3] == "universal-auth" && parts[4] == "identities")
            {
                string actor = parts[5];
                if (parts.Length == 6)
                {
                    if (method == "POST")
                    {
                        data["id"] = Guid.NewGuid().ToString();
                        data["identityId"] = actor;
                        data["clientId"] = "client-" + actor;
                        data["createdAt"] = Date;
                        data["updatedAt"] = Date;
                        configurations.Add(actor, data);
                    }
                    var configuration = configurations[actor];
                    if (method == "DELETE") configurations.Remove(actor);
                    return (200, new { identityUniversalAuth = configuration });
                }
                if (parts.Length == 7 && method == "POST")
                {
                    string secret = "bootstrap-" + Guid.NewGuid().ToString("N");
                    var bootstrap = new BootstrapState(Guid.NewGuid().ToString(), actor, data["numUsesLimit"]!.GetValue<int>());
                    bootstraps.Add(secret, bootstrap);
                    if (Purpose(actor) == "Q06") RecoveryBootstraps++;
                    return (200, new { clientSecret = secret, clientSecretData = SecretRow(bootstrap) });
                }
                var pair = bootstraps.Single(p => p.Value.Id == parts[7]);
                object row = SecretRow(pair.Value);
                if (parts.Length == 9)
                {
                    bootstraps.Remove(pair.Key);
                    // The parser preserves revoked metadata independently of material.
                    var revoked = JsonSerializer.SerializeToNode(row)!.AsObject();
                    revoked["isClientSecretRevoked"] = true;
                    row = revoked;
                }
                return (200, new { clientSecretData = row });
            }
            if (path.StartsWith("/api/v4/secrets", StringComparison.Ordinal))
            {
                var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
                string project = method == "GET" ? query["projectId"]! : data["projectId"]!.GetValue<string>();
                string environment = method == "GET" ? query["environment"]! : data["environment"]!.GetValue<string>();
                string folder = method == "GET" ? query["secretPath"]! : data["secretPath"]!.GetValue<string>();
                bool setup = headers["Authorization"] == "Bearer setup-token-canary";
                string key = Uri.UnescapeDataString(parts.Last());
                if (!setup)
                {
                    string bearer = headers["Authorization"]["Bearer ".Length..];
                    if (!tokens.TryGetValue(bearer, out TokenState? selected)) return (403, new { });
                    string purpose = Purpose(selected.Actor);
                    if (purpose == "Q05") OneUseReads++;
                    if (project != Primary && method == "GET")
                    {
                        if (purpose == "runtime") ForeignRuntimeReads++;
                        if (purpose == "observer") ForeignObserverReads++;
                    }
                    bool foreignOverride = project != Primary && purpose == "runtime" && PermitForeignRuntime;
                    if (selected.Revoked || clock.GetUtcNow() >= selected.Expiry ||
                        selected.Limit != 0 && selected.Uses >= selected.Limit) return (403, new { });
                    selected.Uses++;
                    if (!foreignOverride && !memberships.ContainsKey((project, selected.Actor))) return (403, new { });
                    if (method != "GET" && memberships[(project, selected.Actor)].Role != "member") return (403, new { });
                }
                if (method == "DELETE")
                {
                    var deleted = new List<object>();
                    foreach (JsonNode? item in data["secrets"]!.AsArray())
                    {
                        string name = item!["secretKey"]!.GetValue<string>();
                        var address = (project, environment, folder, name);
                        if (!values.Remove(address, out var row)) return (404, new { });
                        deleted.Add(row);
                    }
                    return (200, new { secrets = deleted });
                }
                if (path == "/api/v4/secrets" && method == "GET") return (200, new { secrets = Array.Empty<object>() });
                var target = (project, environment, folder, key);
                if (method is "POST" or "PATCH")
                {
                    bool pending = SubmitApproval && key == "SDK_12345678_APPROVAL";
                    if (pending && !ApplyDespitePending)
                    {
                        ApprovalSubmissions++;
                        return (200, new { approval = new { id = Guid.NewGuid().ToString(), hasMerged = false } });
                    }
                    if (FailFixtureCreate) return (403, new { });
                    int version = values.TryGetValue(target, out var previous) ? previous["version"]!.GetValue<int>() + 1 : 1;
                    values[target] = new()
                    {
                        ["id"] = previous?["id"]?.DeepClone() ?? JsonValue.Create(Guid.NewGuid().ToString()),
                        ["workspace"] = project,
                        ["environment"] = environment,
                        ["secretPath"] = folder,
                        ["secretKey"] = key,
                        ["secretValue"] = data["secretValue"]!.DeepClone(),
                        ["secretValueHidden"] = false,
                        ["version"] = version,
                        ["type"] = "shared"
                    };
                    if (pending)
                    {
                        ApprovalSubmissions++;
                        return (200, new { approval = new { id = Guid.NewGuid().ToString(), hasMerged = false } });
                    }
                }
                return values.TryGetValue(target, out var secretValue) ? (200, new { secret = secretValue }) : (404, new { });
            }
            throw new InvalidOperationException("Unexpected controlled protocol request.");
        }
        private string Purpose(string actor) => identities[actor]["name"]!.GetValue<string>().Split('-')[1];
        private (int, object) Issue(string actor, DateTimeOffset? originalCeiling = null)
        {
            JsonObject config = configurations[actor];
            int period = config["accessTokenPeriod"]!.GetValue<int>();
            int ttl = period > 0 ? period : config["accessTokenTTL"]!.GetValue<int>();
            int maximum = config["accessTokenMaxTTL"]!.GetValue<int>();
            DateTimeOffset ceiling = originalCeiling ?? clock.GetUtcNow().AddSeconds(maximum);
            DateTimeOffset expiry = clock.GetUtcNow().AddSeconds(ttl);
            if (period == 0 && expiry > ceiling) expiry = ceiling;
            string token = "issued-" + Guid.NewGuid().ToString("N");
            tokens.Add(token, new(actor, expiry, ceiling, period, config["accessTokenNumUsesLimit"]!.GetValue<int>()));
            return (200, new
            {
                accessToken = token,
                expiresIn = (expiry - clock.GetUtcNow()).TotalSeconds,
                accessTokenMaxTTL = period > 0 ? 0 : maximum,
                tokenType = "Bearer"
            });
        }
        private object SecretRow(BootstrapState secret) => new
        {
            id = secret.Id,
            identityUAId = configurations[secret.Actor]["id"]!.GetValue<string>(),
            description = "owned",
            clientSecretPrefix = "prefix",
            createdAt = Date,
            updatedAt = Date,
            clientSecretTTL = 600,
            clientSecretNumUses = secret.Uses,
            clientSecretNumUsesLimit = secret.Limit,
            isClientSecretRevoked = false
        };
        private sealed class BootstrapState(string id, string actor, int limit)
        {
            internal string Id { get; } = id;
            internal string Actor { get; } = actor;
            internal int Limit { get; } = limit;
            internal int Uses { get; set; }
        }
        private sealed class TokenState(string actor, DateTimeOffset expiry, DateTimeOffset ceiling, int period, int limit)
        {
            internal string Actor { get; } = actor;
            internal DateTimeOffset Expiry { get; } = expiry;
            internal DateTimeOffset Ceiling { get; } = ceiling;
            internal int Period { get; } = period;
            internal int Limit { get; } = limit;
            internal int Uses { get; set; }
            internal bool Revoked { get; set; }
        }
    }

    internal sealed class ProofServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly Task accept;
        private readonly List<Task> requests = [];
        private string value = "independent-initial-value";
        private int version = 1;
        internal Uri Origin { get; }
        private readonly Func<string, Uri, Dictionary<string, string>, string, (int Status, object Body)>? respond;
        internal ProofServer(Func<string, Uri, Dictionary<string, string>, string, (int Status, object Body)>? respond = null)
        {
            this.respond = respond;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }
        private async Task AcceptAsync()
        {
            try
            {
                while (true)
                {
                    var client = await listener.AcceptTcpClientAsync(shutdown.Token);
                    requests.Add(ServeAsync(client));
                }
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }
        private async Task ServeAsync(TcpClient client)
        {
            using (client)
            {
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                string[] first = (await reader.ReadLineAsync(shutdown.Token))!.Split(' ');
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string? line;
                while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(shutdown.Token)))
                {
                    int split = line.IndexOf(':');
                    headers.Add(line[..split], line[(split + 1)..].Trim());
                }
                string body = "";
                if (headers.TryGetValue("Content-Length", out string? length))
                {
                    char[] payload = new char[int.Parse(length, System.Globalization.CultureInfo.InvariantCulture)];
                    if (payload.Length > 0)
                        NativeWorkflow.Require(await reader.ReadBlockAsync(payload, shutdown.Token) == payload.Length);
                    body = new(payload);
                }
                var uri = new Uri(Origin, first[1]);
                if (respond is not null)
                {
                    var selectedResponse = respond(first[0], uri, headers, body);
                    await Reply(stream, selectedResponse.Status, selectedResponse.Body);
                    return;
                }
                var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
                string key = Uri.UnescapeDataString(uri.AbsolutePath.Split('/').Last());
                int status = 200;
                if (headers["Authorization"] == "Bearer denied-token-canary" ||
                    first[0] != "GET" && headers["Authorization"] == "Bearer runtime-token-canary")
                    status = 403;
                else if (first[0] == "POST")
                {
                    using var doc = JsonDocument.Parse(body);
                    value = doc.RootElement.GetProperty("secretValue").GetString()!;
                    version = 1;
                }
                else if (first[0] == "PATCH") version++;
                object secret = new
                {
                    id = "40000000-0000-0000-0000-000000000001",
                    workspace = query["projectId"] ?? "30000000-0000-0000-0000-000000000001",
                    environment = query["environment"] ?? "sensitive-environment",
                    secretPath = query["secretPath"] ?? "/secretkit-sdk-12345678",
                    type = "shared",
                    secretKey = key,
                    secretValue = value,
                    secretValueHidden = false,
                    version
                };
                object response = uri.AbsolutePath == "/api/v4/secrets" ? new { secrets = Array.Empty<object>() } :
                    new { secret };
                await Reply(stream, status, response);
            }
        }
        private async Task Reply(Stream stream, int status, object response)
        {
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(response);
            try
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                await stream.WriteAsync(bytes, shutdown.Token);
            }
            catch (IOException) { /* The cancelled SDK peer owns its disconnect. State assertions still apply. */ }
        }
        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            listener.Stop();
            await accept;
            await Task.WhenAll(requests);
            shutdown.Dispose();
        }
    }
}
