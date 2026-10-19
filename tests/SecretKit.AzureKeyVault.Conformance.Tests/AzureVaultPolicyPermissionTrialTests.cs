using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultPolicyPermissionTrial;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

// Offline native SDK evidence only. These tests neither prepare a cloud fixture
// nor establish the declared principal's identity or an actual permission grant.
public sealed class AzureVaultPolicyPermissionTrialTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string Version = "0123456789abcdef0123456789abcdef";
    private const string Material = "owned-permission-material";
    private static string Digest => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Material)));
    private static readonly byte[] Backup = [1, 2, 255, 254];

    [Test]
    [Arguments(SecretPermission.Get)]
    [Arguments(SecretPermission.List)]
    [Arguments(SecretPermission.Set)]
    [Arguments(SecretPermission.Delete)]
    [Arguments(SecretPermission.Recover)]
    [Arguments(SecretPermission.Backup)]
    [Arguments(SecretPermission.Restore)]
    [Arguments(SecretPermission.Purge)]
    public async Task EveryPermissionUsesItsNativeActionAndIndependentDeniedAuthority(SecretPermission permission)
    {
        await using var f = new Fixture(permission);
        var result = await f.Collect();
        var intended = result.Observations.Single(x => x.Permission == permission && !x.DeniedAuthority);
        var denied = result.Observations.Single(x => x.Permission == permission && x.DeniedAuthority);
        await Assert.That(intended.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(denied.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(intended.NativeRequestId).IsEqualTo("intended-request");
        await Assert.That(denied.NativeRequestId).IsEqualTo("denied-request");
        await Assert.That(intended.SdkSucceeded).IsTrue();
        await Assert.That(intended.Accepted).IsEqualTo(Mutates(permission));
        await Assert.That(intended.RemoteSettled).IsEqualTo(permission is not (SecretPermission.Delete or SecretPermission.Recover));
        await Assert.That(denied.RemoteSettled).IsTrue();
        await Assert.That(result.PrincipalQualified || result.EgressQualified).IsFalse();
        await Assert.That(result.IntendedPrincipal).IsEqualTo(f.Claim);
        await Assert.That(result.Binding).IsEqualTo(f.Binding);
        await Assert.That(result.Observations.Count).IsEqualTo(16);
        await Assert.That(result.Observations.Where(x => x.Permission != permission)
            .All(x => !x.Attempted && x.Status == SecretStatus.Unavailable)).IsTrue();
        foreach (var backend in new[] { f.Intended, f.Denied })
        {
            var row = backend.Requests.Single();
            await Assert.That(row.Uri).IsEqualTo(backend.Route);
            await Assert.That(row.Method).IsEqualTo(backend.Method);
            await Assert.That(row.Authorization).IsEqualTo("Bearer " + backend.Token);
            if (permission == SecretPermission.Set)
            {
                using var body = JsonDocument.Parse(row.Body!);
                await Assert.That(body.RootElement.GetProperty("value").GetString()).IsEqualTo(Material);
            }
            else if (permission == SecretPermission.Restore)
            {
                using var body = JsonDocument.Parse(row.Body!);
                await Assert.That(body.RootElement.GetProperty("value").GetString()).IsEqualTo(Encode(Backup));
            }
            else await Assert.That(row.Body).IsNull();
        }
        foreach (var credential in new[] { f.IntendedCredential, f.DeniedCredential })
        {
            await Assert.That(credential.Calls).IsEqualTo(1);
            await Assert.That(credential.Scope).IsEqualTo(C.Audience);
            await Assert.That(credential.Tenant is null && credential.Claims is null).IsTrue();
        }
        if (permission is SecretPermission.Delete or SecretPermission.Recover)
            await Assert.That(intended.NativeHandle).IsNotNull();
        var journal = f.Journal.Read(f.Owner, f.Binding.Selector);
        var resource = journal.Resources.Single(r => r.Id == f.Resource(f.Intended.Name));
        await Assert.That(resource.InvocationTerminated).IsTrue();
        await Assert.That(resource.ActiveDispatch != Guid.Empty).IsEqualTo(permission is SecretPermission.Delete or SecretPermission.Recover);
        await Assert.That(f.Intended.Storage.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(f.Intended.Disposed || f.Denied.Disposed ||
            f.IntendedCredential.Disposed || f.DeniedCredential.Disposed).IsFalse();
    }

    [Test]
    [Arguments(403)]
    [Arguments(404)]
    [Arguments(200)]
    public async Task AuthorityLabelsAndOriginalPolicyVariantsDoNotProjectOutcomes(int status)
    {
        var member = VaultAdministrationEffects.Members.Single(m => m.Operation == M.Operation(M.QueryKind.ChangeAccessPolicies));
        foreach (string variant in member.Variants)
        {
            await using var f = new Fixture(SecretPermission.Get, variant: variant);
            f.Intended.Status = status;
            f.Denied.Status = 200;
            var result = await f.Collect();
            await Assert.That(result.Observations.Single(x => x.Permission == SecretPermission.Get && !x.DeniedAuthority).Status)
                .IsEqualTo(status == 403 ? SecretStatus.Denied : status == 404 ? SecretStatus.Absent : SecretStatus.Success);
            await Assert.That(result.Observations.Single(x => x.Permission == SecretPermission.Get && x.DeniedAuthority).Status)
                .IsEqualTo(SecretStatus.Success);
        }
    }

    [Test]
    [Arguments("borrowed-secret")]
    [Arguments("borrowed-vault")]
    [Arguments("unknown-secret")]
    [Arguments("foreign-owner")]
    [Arguments("foreign-lease")]
    [Arguments("closing")]
    [Arguments("active")]
    [Arguments("uncertain")]
    [Arguments("unknown-state")]
    public async Task UnpreparedOrUnownedResourcesNeverReachCredentialsOrTransport(string fault)
    {
        await using var f = new Fixture(SecretPermission.Set, fault);
        var result = await f.Collect();
        await Assert.That(result.Observations.All(x => x.Status == SecretStatus.Unavailable)).IsTrue();
        await Assert.That(f.IntendedCredential.Calls + f.DeniedCredential.Calls).IsEqualTo(0);
        await Assert.That(f.Intended.Requests.Count + f.Denied.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("scope")]
    [Arguments("operation")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("vault")]
    public async Task FullBindingAndPrivateMembershipAreCheckedBeforeWindowConsumption(string field)
    {
        await using var f = new Fixture(SecretPermission.Get);
        var window = f.Source.Arm(f.Manifest);
        var b = f.Binding;
        var changed = field switch
        {
            "nonce" => b with { Selector = b.Selector with { Nonce = Guid.NewGuid() } },
            "lease" => b with { LeaseId = Guid.NewGuid() },
            "scope" => b with { Selector = b.Selector with { Scope = "foreign" } },
            "operation" => b with { Selector = b.Selector with { Operation = "foreign" } },
            "variant" => b with { Selector = b.Selector with { Variant = "change.Remove" } },
            "case" => b with { Selector = b.Selector with { Case = "selected-contract" } },
            _ => b with { VaultName = "foreign-vault" }
        };
        await Assert.That(async () => await f.Source.CollectAsync(window, changed)).Throws<InvalidOperationException>();
        await using var other = new Fixture(SecretPermission.Get);
        await Assert.That(async () => await other.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
        await Assert.That((await f.Source.CollectAsync(window, b)).Observations.Any(x => x.Status == SecretStatus.Success)).IsTrue();
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.Arm(f.Manifest)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    public async Task SourceLocalBindingReuseFailsWhileSeparateSourcesShareOriginalBinding(string reused)
    {
        await using var f = new Fixture(SecretPermission.Get);
        await using var other = f.Reopen();
        var first = f.Source.Arm(f.Manifest);
        var second = other.Arm(f.Manifest);
        var changed = f.Binding with
        {
            LeaseId = reused == "nonce" ? Guid.NewGuid() : f.Binding.LeaseId,
            Selector = reused == "lease" ? f.Binding.Selector with { Nonce = Guid.NewGuid() } : f.Binding.Selector
        };
        await Assert.That(() => f.Source.Arm(f.Manifest with { Original = changed })).Throws<InvalidOperationException>();
        await Assert.That(() => other.Arm(f.Manifest)).Throws<InvalidOperationException>();
        foreach (var result in new[]
        {
            await f.Source.CollectAsync(first, f.Binding),
            await other.CollectAsync(second, f.Binding)
        })
        {
            await Assert.That(result.Binding).IsEqualTo(f.Binding);
            await Assert.That(result.Observations.Count).IsEqualTo(16);
            await Assert.That(result.Observations.Single(o => o.Permission == SecretPermission.Get && !o.DeniedAuthority).Status)
                .IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Observations.Single(o => o.Permission == SecretPermission.Get && o.DeniedAuthority).Status)
                .IsEqualTo(SecretStatus.Denied);
        }
        await Assert.That(f.Intended.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Denied.Requests.Count).IsEqualTo(2);
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Resources.All(r =>
            r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted)).IsTrue();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("accepted")]
    public async Task MutationUncertaintyStopsTheSharedRootWithoutReplayOrStatusGet(string mode)
    {
        await using var f = new Fixture(SecretPermission.Set);
        // The denied label is not a denial guarantee. Its real successful write
        // must fence the intended trial, even if the policy variant says Remove.
        f.Denied.Status = mode == "accepted" ? 202 : 200;
        f.Denied.Throw = mode == "lost";
        var result = await f.Collect();
        var first = result.Observations.Single(x => x.Permission == SecretPermission.Set && x.DeniedAuthority);
        var second = result.Observations.Single(x => x.Permission == SecretPermission.Set && !x.DeniedAuthority);
        await Assert.That(first.Status).IsEqualTo(mode == "lost" ? SecretStatus.Unavailable : SecretStatus.Success);
        await Assert.That(first.RemoteSettled).IsFalse();
        await Assert.That(second.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(second.Attempted).IsFalse();
        await Assert.That(f.Denied.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Intended.Requests.Count).IsEqualTo(0);
        var state = f.Journal.Read(f.Owner, f.Binding.Selector);
        await Assert.That(state.Resources.Any(r => r.ActiveDispatch != Guid.Empty && r.InvocationTerminated)).IsTrue();
        var root = f.Journal.Close(f.Owner, f.Binding.Selector);
        await Assert.That(root.Released).IsFalse();
        await Assert.That(() => f.Journal.RecordAbsence(f.Owner, f.Binding.Selector, f.Resource(f.Denied.Name)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ClosingBetweenCredentialAndInitialSendWinsTheJournalRace()
    {
        await using var f = new Fixture(SecretPermission.Set);
        f.DeniedCredential.BeforeReturn = () => f.Journal.Close(f.Owner, f.Binding.Selector);
        var result = await f.Collect();
        await Assert.That(result.Observations.All(x => !x.Attempted)).IsTrue();
        await Assert.That(f.Denied.Requests.Count + f.Intended.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("foreign-id")]
    [Arguments("wrong-value")]
    [Arguments("duplicate")]
    [Arguments("case")]
    [Arguments("depth")]
    [Arguments("nodes")]
    [Arguments("body")]
    [Arguments("headers")]
    [Arguments("length")]
    [Arguments("redirect")]
    [Arguments("next")]
    public async Task NativeResponseBoundsAndCoordinatesFailClosedBeforeSdkParsing(string fault)
    {
        await using var f = new Fixture(SecretPermission.Get);
        f.Intended.Fault = fault;
        var result = await f.Collect();
        var observed = result.Observations.Single(x => x.Permission == SecretPermission.Get && !x.DeniedAuthority);
        await Assert.That(observed.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(observed.SdkSucceeded).IsFalse();
        await Assert.That(f.Intended.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Intended.Storage.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments(403, false)]
    [Arguments(404, false)]
    [Arguments(401, true)]
    [Arguments(429, true)]
    [Arguments(500, true)]
    public async Task OnlyValidatedNativeErrorsDistinguishDeniedFromAbsent(int status, bool validCode)
    {
        await using var f = new Fixture(SecretPermission.Get);
        f.Intended.Status = status;
        f.Intended.Fault = validCode ? null : "wrong-code";
        var result = await f.Collect();
        await Assert.That(result.Observations.Single(x => x.Permission == SecretPermission.Get && !x.DeniedAuthority).Status)
            .IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(f.Intended.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(SecretPermission.Set)]
    [Arguments(SecretPermission.Restore)]
    public async Task ArmedMaterialIsAnOwnedSnapshotAndReturnedCoordinatesCannotNominateTargets(SecretPermission permission)
    {
        await using var f = new Fixture(permission);
        var window = f.Source.Arm(f.Manifest);
        foreach (var item in f.Manifest.Fixtures)
        {
            item.OwnedSet?.Dispose();
            item.Backup?.Dispose();
        }
        f.Intended.Fault = "foreign-id";
        var result = await f.Source.CollectAsync(window, f.Binding);
        await Assert.That(f.Intended.Requests.Single().Uri).IsEqualTo(f.Intended.Route);
        await Assert.That(result.Observations.Single(x => x.Permission == permission && !x.DeniedAuthority).Status)
            .IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Resources.Any(r =>
            r.Id == f.Resource(f.Intended.Name) && r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("wall")]
    [Arguments("monotonic")]
    [Arguments("wall-rollback")]
    [Arguments("monotonic-rollback")]
    public async Task MinimumClockBudgetAndRollbackBlockBeforeCredential(string clock)
    {
        await using var f = new Fixture(SecretPermission.Get);
        var window = f.Source.Arm(f.Manifest);
        if (clock == "wall") f.Clock.Wall += TimeSpan.FromSeconds(11);
        if (clock == "monotonic") f.Clock.Stamp += TimeSpan.FromSeconds(11).Ticks;
        if (clock == "wall-rollback") f.Clock.Wall -= TimeSpan.FromTicks(1);
        if (clock == "monotonic-rollback") f.Clock.Stamp--;
        var result = await f.Source.CollectAsync(window, f.Binding);
        await Assert.That(result.Observations.All(x => x.Status == SecretStatus.Unavailable)).IsTrue();
        await Assert.That(f.IntendedCredential.Calls + f.DeniedCredential.Calls).IsEqualTo(0);
    }

    [Test]
    [Arguments("wall")]
    [Arguments("monotonic")]
    [Arguments("wall-rollback")]
    [Arguments("monotonic-rollback")]
    public async Task ClockChangesDuringCredentialAcquisitionBlockTheInitialSend(string clock)
    {
        await using var f = new Fixture(SecretPermission.Get);
        f.DeniedCredential.BeforeReturn = () =>
        {
            if (clock == "wall") f.Clock.Wall += TimeSpan.FromSeconds(11);
            if (clock == "monotonic") f.Clock.Stamp += TimeSpan.FromSeconds(11).Ticks;
            if (clock == "wall-rollback") f.Clock.Wall -= TimeSpan.FromTicks(1);
            if (clock == "monotonic-rollback") f.Clock.Stamp--;
        };
        var result = await f.Collect();
        await Assert.That(result.Observations.All(x => x.Status == SecretStatus.Unavailable)).IsTrue();
        await Assert.That(f.DeniedCredential.Calls).IsEqualTo(1);
        await Assert.That(f.IntendedCredential.Calls).IsEqualTo(0);
        await Assert.That(f.Intended.Requests.Count + f.Denied.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("initializer", false)]
    [Arguments("credential", false)]
    [Arguments("send", false)]
    [Arguments("body", false)]
    [Arguments("sdk", false)]
    [Arguments("initializer", true)]
    [Arguments("credential", true)]
    [Arguments("send", true)]
    [Arguments("body", true)]
    [Arguments("sdk", true)]
    public async Task CancellationAndDeadlineDrainActualBorrowersBeforeOwnedStorageIsCleared(string phase, bool deadline)
    {
        await using var f = new Fixture(SecretPermission.Set);
        using var cancel = new CancellationTokenSource();
        var gate = new Barrier();
        if (phase == "initializer") f.Denied.InitializerGate = gate;
        if (phase == "credential") f.DeniedCredential.Gate = gate;
        if (phase == "send") f.Denied.SendGate = gate;
        if (phase == "body") f.Denied.BodyGate = gate;
        if (phase == "sdk") f.Denied.SdkGate = gate;
        int sequence = 0, borrowerExit = 0, collectorExit = 0;
        gate.OnExit = () => borrowerExit = Interlocked.Increment(ref sequence);
        // SDK error parsing may synchronously read. A worker here belongs to the
        // test harness only, and is joined before fixture disposal.
        var pending = phase is "sdk" or "initializer" ? Task.Run(Observe) : Observe();
        try
        {
            await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            if (deadline) f.Clock.Advance(TimeSpan.FromSeconds(11));
            else cancel.Cancel();
            bool bodyLive = phase != "body" || f.Denied.LastBody!.Destination!.Any(b => b != 0);
            bool sdkLive = phase != "sdk" || f.Denied.Storage.Single().Any(b => b != 0);
            gate.Release.TrySetResult();
            if (deadline)
                await Assert.That((await pending.WaitAsync(TimeSpan.FromSeconds(5)))!.Observations
                    .All(x => x.Status == SecretStatus.Unavailable)).IsTrue();
            else
                await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5))).Throws<OperationCanceledException>();
            await Assert.That(bodyLive && sdkLive && gate.LiveAtExit).IsTrue();
            await Assert.That(borrowerExit > 0 && collectorExit > borrowerExit).IsTrue();
            await Assert.That(f.Denied.Storage.All(b => b.All(v => v == 0))).IsTrue();
            if (phase == "body")
                await Assert.That(f.Denied.LastBody!.Destination!.All(b => b == 0)).IsTrue();
            await Assert.That(f.Intended.Requests.Count).IsEqualTo(0);
        }
        finally { gate.Release.TrySetResult(); try { await pending; } catch (OperationCanceledException) { } }

        async Task<C.Measurement?> Observe()
        {
            try { return await f.Source.CollectAsync(f.Source.Arm(f.Manifest), f.Binding, cancel.Token); }
            finally { collectorExit = Interlocked.Increment(ref sequence); }
        }
    }

    [Test]
    public async Task DisposalJoinsTheActualSendAndDoesNotDisposeBorrowedResources()
    {
        await using var f = new Fixture(SecretPermission.Set);
        var barrier = f.Denied.SendGate = new();
        var pending = f.Collect().AsTask();
        try
        {
            await barrier.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var disposal = f.Source.DisposeAsync().AsTask();
            barrier.Release.TrySetResult();
            await pending.WaitAsync(TimeSpan.FromSeconds(5));
            await disposal.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(barrier.LiveAtExit).IsTrue();
            await Assert.That(f.Denied.Disposed || f.DeniedCredential.Disposed).IsFalse();
            await Assert.That(f.Denied.Storage.All(b => b.All(v => v == 0))).IsTrue();
        }
        finally { barrier.Release.TrySetResult(); await pending; }
    }

    [Test]
    public async Task WarmSdkChallengeAndColdTransportIssueOnlyOneNormalizedAuthorityToken()
    {
        await using var f = new Fixture(SecretPermission.Get);
        using var warmer = new Backend(SecretPermission.Get, f.Intended.Origin, f.Intended.Name, "warm", "warm-token")
        { Challenge = true };
        using var http = new HttpClient(warmer);
        var credential = new Credential("warm-token");
        var native = new SecretClient(new(f.Intended.Origin), credential,
            new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = new HttpClientTransport(http) });
        await native.GetSecretAsync(f.Intended.Name, Version);
        await Assert.That(warmer.Requests.Count).IsEqualTo(2);
        await f.Collect();
        foreach (var item in new[] { f.IntendedCredential, f.DeniedCredential })
        {
            await Assert.That(item.Calls).IsEqualTo(1);
            await Assert.That(item.Tenant is null && item.Claims is null).IsTrue();
        }
        await Assert.That(f.Intended.Requests.Single().Authorization).IsEqualTo("Bearer intended-token");
        await Assert.That(f.Denied.Requests.Single().Authorization).IsEqualTo("Bearer denied-token");
    }

    [Test]
    public async Task OversizedTopologyAndCanaryTargetsAreRejectedWithoutCreatingJournalChildren()
    {
        await using var f = new Fixture(SecretPermission.Get);
        var tooMany = f.Manifest with { Fixtures = Enumerable.Repeat(f.Manifest.Fixtures[0], 16).ToArray() };
        await Assert.That(() => f.Source.Arm(tooMany)).Throws<ArgumentException>();
        var canary = f.Manifest with { Fixtures = [f.Manifest.Fixtures[0] with { Name = "canary" }] };
        await Assert.That(() => f.Source.Arm(canary)).Throws<ArgumentException>();
        await Assert.That(Directory.GetFiles(f.Directory, "*.journal").Length).IsEqualTo(1);
        await Assert.That(f.Intended.Requests.Count + f.Denied.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("fixture")]
    [Arguments("hash")]
    [Arguments("backup")]
    [Arguments("set")]
    public async Task MissingPreparationIsUnavailableWithoutSubstitutionOrImplicitPreparation(string missing)
    {
        var permission = missing == "backup" ? SecretPermission.Restore :
            missing == "set" ? SecretPermission.Set : SecretPermission.Get;
        await using var f = new Fixture(permission);
        var changed = f.Manifest with
        {
            Fixtures = missing == "fixture" ? [] : f.Manifest.Fixtures.Select(x => missing switch
            {
                "hash" => x with { Sha256 = null },
                "backup" => x with { Backup = null },
                _ => x with { OwnedSet = null }
            }).ToArray()
        };
        var result = await f.Source.CollectAsync(f.Source.Arm(changed), f.Binding);
        await Assert.That(result.Observations.All(x => x.Status == SecretStatus.Unavailable && !x.Attempted)).IsTrue();
        await Assert.That(f.IntendedCredential.Calls + f.DeniedCredential.Calls).IsEqualTo(0);
        await Assert.That(Directory.GetFiles(f.Directory, "*.journal").Length).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PreCanceledOrBackendCanceledWindowsCannotPublishSuccessfulObservations(bool atResponse)
    {
        await using var f = new Fixture(SecretPermission.Get);
        using var cancel = new CancellationTokenSource();
        var window = f.Source.Arm(f.Manifest);
        if (atResponse) f.Denied.BeforeReturn = cancel.Cancel;
        else cancel.Cancel();
        await Assert.That(async () => await f.Source.CollectAsync(window, f.Binding, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Intended.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Denied.Requests.Count).IsEqualTo(atResponse ? 1 : 0);
        await Assert.That(f.Denied.Storage.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    [Arguments("independent-effect")]
    public async Task OriginalCaseRemainsBoundWithoutSelectingAnOutcome(string selectedCase)
    {
        await using var f = new Fixture(SecretPermission.Get, selectedCase: selectedCase);
        var result = await f.Collect();
        await Assert.That(result.Binding.Selector.Case).IsEqualTo(selectedCase);
        await Assert.That(result.Observations.Count(x => x.Status == SecretStatus.Success)).IsEqualTo(1);
        await Assert.That(result.Observations.Count(x => x.Status == SecretStatus.Denied)).IsEqualTo(1);
    }

    [Test]
    public async Task ActualExceptionsFormattingAndDefaultJsonNeverExposeProtectedInputs()
    {
        await using var f = new Fixture(SecretPermission.Get);
        f.Intended.Throw = true;
        var window = f.Source.Arm(f.Manifest);
        var result = await f.Source.CollectAsync(window, f.Binding);
        foreach (object item in new object[] { f.Source, f.Manifest, f.Manifest.Fixtures[0], f.Claim, window,
            result, result.Observations[0] })
        {
            await Assert.That(JsonSerializer.Serialize(item)).IsEqualTo("{}");
            await Redacted(item.ToString()!);
        }
        Exception? actual = null;
        try { await f.Source.CollectAsync(window, f.Binding); }
        catch (Exception error) { actual = error; }
        await Assert.That(actual is InvalidOperationException).IsTrue();
        await Redacted(actual!.ToString() + actual.Message + actual.InnerException);
        await Assert.That(actual.InnerException).IsNull();
        actual = null;
        try { f.Source.Arm(f.Manifest with { ApiRevision = Material }); }
        catch (Exception error) { actual = error; }
        await Assert.That(actual is ArgumentException).IsTrue();
        await Redacted(actual!.ToString() + actual.Message + actual.InnerException);

        async Task Redacted(string text)
        {
            foreach (string secret in new[] { Material, Version, Digest, f.Intended.Origin, f.Owner,
                "intended-token", "denied-token", "native-sensitive-error", Encode(Backup) })
                await Assert.That(text.Contains(secret, StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    [Arguments(SecretPermission.Set)]
    [Arguments(SecretPermission.Restore)]
    public async Task CredentialCannotReplaceValidatedOwnedWriteBytes(SecretPermission permission)
    {
        await using var f = new Fixture(permission);
        f.DeniedCredential.BeforeReturn = () =>
            f.Denied.LastRequest!.Content = RequestContent.Create(
                Encoding.UTF8.GetBytes("""{"value":"substituted-after-validation"}"""));
        var result = await f.Collect();
        using var body = JsonDocument.Parse(f.Denied.Requests.Single().Body!);
        await Assert.That(body.RootElement.GetProperty("value").GetString())
            .IsEqualTo(permission == SecretPermission.Set ? Material : Encode(Backup));
        await Assert.That(result.Observations.Single(x => x.Permission == permission && x.DeniedAuthority).Status)
            .IsEqualTo(SecretStatus.Denied);
    }

    [Test]
    [Arguments(SecretPermission.Set)]
    [Arguments(SecretPermission.Restore)]
    public async Task WarmNativeChallengePreservesTheOwnedWriteBody(SecretPermission permission)
    {
        await using var f = new Fixture(permission);
        using var warmer = new Backend(SecretPermission.Get, f.Intended.Origin, f.Intended.Name, "warm", "warm-token")
        { Challenge = true };
        using var http = new HttpClient(warmer);
        var native = new SecretClient(new(f.Intended.Origin), new Credential("warm-token"),
            new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
            { Transport = new HttpClientTransport(http) });
        await native.GetSecretAsync(f.Intended.Name, Version);
        var result = await f.Collect();
        await Assert.That(result.Observations.Single(x => x.Permission == permission && !x.DeniedAuthority).Status)
            .IsEqualTo(SecretStatus.Success);
        await Assert.That(f.IntendedCredential.Calls).IsEqualTo(1);
        await Assert.That(f.DeniedCredential.Calls).IsEqualTo(1);
        foreach (var backend in new[] { f.Intended, f.Denied })
        {
            using var body = JsonDocument.Parse(backend.Requests.Single().Body!);
            await Assert.That(body.RootElement.GetProperty("value").GetString())
                .IsEqualTo(permission == SecretPermission.Set ? Material : Encode(Backup));
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ReentrantClockDisposalCannotPublishAnUnownedProtectedSnapshot(bool timestamp)
    {
        await using var f = new Fixture(SecretPermission.Set);
        bool disposed = false;
        void DisposeFromClock()
        {
            f.Clock.BeforeWall = null;
            f.Clock.BeforeStamp = null;
            f.Source.DisposeAsync().AsTask().GetAwaiter().GetResult();
            disposed = true;
        }
        if (timestamp) f.Clock.BeforeStamp = DisposeFromClock;
        else f.Clock.BeforeWall = DisposeFromClock;
        await Assert.That(() => f.Source.Arm(f.Manifest)).Throws<InvalidOperationException>();
        await Assert.That(disposed).IsTrue();
        await Assert.That(f.Denied.Requests.Count + f.Intended.Requests.Count).IsEqualTo(0);
        await Assert.That(() => f.Source.Arm(f.Manifest)).Throws<InvalidOperationException>();
    }

    private static bool Mutates(SecretPermission permission) =>
        permission is not (SecretPermission.Get or SecretPermission.List or SecretPermission.Backup);
    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly string Directory = Path.Combine(Path.GetTempPath(), "policy-trial-" + Guid.NewGuid().ToString("N"));
        internal readonly string Owner = "private-owner";
        internal readonly RoleFixtureJournal Journal;
        internal readonly Clock Clock = new();
        internal readonly C.PrincipalClaim Claim = new(Guid.NewGuid(), Guid.NewGuid(), null);
        internal readonly Credential IntendedCredential = new("intended-token"), DeniedCredential = new("denied-token");
        internal readonly Backend Intended, Denied;
        internal readonly M.Binding Binding;
        internal readonly C.Manifest Manifest;
        internal readonly C Source;
        private readonly HttpClient intendedHttp, deniedHttp;
        internal Fixture(SecretPermission permission, string? fault = null, string variant = "change.Add",
            string selectedCase = "independent-effect")
        {
            System.IO.Directory.CreateDirectory(Directory);
            Journal = new(Directory);
            string vault = "p" + Guid.NewGuid().ToString("N")[..20];
            var selector = new FixtureSelector(Guid.NewGuid(), "owned", M.Operation(M.QueryKind.ChangeAccessPolicies),
                variant, selectedCase);
            var original = new M.Binding(selector, Guid.Empty, M.QueryKind.ChangeAccessPolicies, M.ReadKind.GetVault,
                Guid.Parse("11111111-1111-1111-1111-111111111111"), "owned-group", "eastus", vault, null);
            string vaultId = $"/subscriptions/{original.SubscriptionId:D}/resourceGroups/owned-group/providers/Microsoft.KeyVault/vaults/{vault}";
            string name = permission.ToString().ToLowerInvariant();
            Intended = new(permission, "https://" + vault + ".vault.azure.net", name + "-intended", "intended-request", "intended-token");
            Denied = new(permission, Intended.Origin, name + "-denied", "denied-request", "denied-token") { Status = 403 };
            RoleFixtureJournal.Resource[] resources =
            [
                new(vaultId, fault == "borrowed-vault"),
                new(vaultId + "/secrets/" + (fault == "unknown-secret" ? "unknown" : Intended.Name), fault == "borrowed-secret"),
                new(vaultId + "/secrets/" + (fault == "unknown-secret" ? "unknown-denied" : Denied.Name), fault == "borrowed-secret")
            ];
            var prepared = Journal.Prepare(Owner, selector, resources);
            foreach (var row in resources.Where(r => !r.Borrowed))
            {
                var dispatch = Journal.BeginDispatch(Owner, selector, row.Id, delete: false);
                Journal.EndDispatch(Owner, selector, row.Id, dispatch);
            }
            Binding = original with { LeaseId = fault == "foreign-lease" ? Guid.NewGuid() : prepared.LeaseId };
            if (fault == "closing") Journal.Close(Owner, selector);
            if (fault is "active" or "uncertain")
            {
                var dispatch = Journal.BeginSelectedUpdate(Owner, selector, resources[1].Id);
                if (fault == "uncertain") Journal.EndDispatch(Owner, selector, resources[1].Id, dispatch, nativeSettled: false);
            }
            C.PreparedState state = fault == "unknown-state" ? C.PreparedState.Unknown : permission switch
            {
                SecretPermission.Recover or SecretPermission.Purge => C.PreparedState.Deleted,
                SecretPermission.Set or SecretPermission.Restore => C.PreparedState.Absent,
                _ => C.PreparedState.Active
            };
            Manifest = new(fault == "foreign-owner" ? "another-owner" : Owner, Binding, C.Revision,
                [Entry(Intended.Name, false), Entry(Denied.Name, true)]);
            intendedHttp = new(Intended);
            deniedHttp = new(Denied);
            Source = Reopen();

            C.PreparedFixture Entry(string target, bool denied) => new(permission, denied, target,
                permission == SecretPermission.Set ? null : Version, state, Digest,
                permission == SecretPermission.Set ? SecretMaterial.FromText(Material) : null,
                permission == SecretPermission.Restore ? AzureSecretBackup.FromBytes(Backup) : null);
        }
        internal C Reopen() => new(Journal, Claim,
            new("intended-declaration", IntendedCredential, new SpyTransport(new HttpClientTransport(intendedHttp), Intended)),
            new("denied-declaration", DeniedCredential, new SpyTransport(new HttpClientTransport(deniedHttp), Denied)),
            new(8192, 4096, 4096, 128, 16, 8, TimeSpan.FromSeconds(10)), Clock);
        internal string Resource(string name) =>
            $"/subscriptions/{Binding.SubscriptionId:D}/resourceGroups/{Binding.ResourceGroup}/providers/Microsoft.KeyVault/vaults/{Binding.VaultName}/secrets/{name}";
        internal ValueTask<C.Measurement> Collect() => Source.CollectAsync(Source.Arm(Manifest), Binding);
        public async ValueTask DisposeAsync()
        {
            await Source.DisposeAsync();
            intendedHttp.Dispose();
            deniedHttp.Dispose();
            IntendedCredential.Dispose();
            DeniedCredential.Dispose();
            foreach (var fixture in Manifest.Fixtures) { fixture.OwnedSet?.Dispose(); fixture.Backup?.Dispose(); }
            System.IO.Directory.Delete(Directory, recursive: true);
        }
    }

    private sealed class Barrier
    {
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Action? OnExit;
        internal bool LiveAtExit;
        internal async Task Enter() { Entered.TrySetResult(); await Release.Task; }
        internal void Exit(bool live = true) { LiveAtExit = live; OnExit?.Invoke(); }
    }

    private sealed class Credential(string token) : TokenCredential, IDisposable
    {
        internal int Calls;
        internal string? Scope, Tenant, Claims;
        internal bool Disposed;
        internal Barrier? Gate;
        internal Action? BeforeReturn;
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Calls++;
            Scope = requestContext.Scopes.Single();
            Tenant = requestContext.TenantId;
            Claims = requestContext.Claims;
            try
            {
                if (Gate is { } gate) await gate.Enter();
                BeforeReturn?.Invoke();
                return new(token, DateTimeOffset.MaxValue);
            }
            finally { Gate?.Exit(); }
        }
        public void Dispose() => Disposed = true;
    }

    private sealed record Sent(string Uri, HttpMethod Method, string? Authorization, string? Body);
    private sealed class Backend(SecretPermission permission, string origin, string name, string requestId, string token) : HttpMessageHandler
    {
        internal string Origin => origin;
        internal string Name => name;
        internal string Token => token;
        internal readonly List<Sent> Requests = [];
        internal readonly List<byte[]> Storage = [];
        internal int Status = permission == SecretPermission.Purge ? 204 : 200;
        internal bool Throw, Disposed, Challenge;
        internal string? Fault;
        internal Barrier? InitializerGate, SendGate, BodyGate, SdkGate;
        internal Action? BeforeReturn;
        internal RawBody? LastBody;
        internal Request? LastRequest;
        internal string Route => origin + (permission switch
        {
            SecretPermission.Get => "/secrets/" + name + "/" + Version,
            SecretPermission.List => "/secrets/",
            SecretPermission.Recover => "/deletedsecrets/" + name + "/recover",
            SecretPermission.Backup => "/secrets/" + name + "/backup",
            SecretPermission.Restore => "/secrets/restore",
            SecretPermission.Purge => "/deletedsecrets/" + name,
            _ => "/secrets/" + name
        }) + "?api-version=2025-07-01";
        internal HttpMethod Method => permission switch
        {
            SecretPermission.Get or SecretPermission.List => HttpMethod.Get,
            SecretPermission.Set => HttpMethod.Put,
            SecretPermission.Delete or SecretPermission.Purge => HttpMethod.Delete,
            _ => HttpMethod.Post
        };
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new(request.RequestUri!.AbsoluteUri, request.Method, request.Headers.Authorization?.ToString(),
                request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken)));
            if (Challenge && Requests.Count == 1)
            {
                var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    "Bearer authorization=\"https://login.windows.net/11111111-1111-1111-1111-111111111111\", resource=\"https://vault.azure.net\"");
                return challenge;
            }
            try
            {
                if (SendGate is { } gate) await gate.Enter();
                if (Throw) throw new HttpRequestException(origin + Material + "native-sensitive-error");
                string id = origin + "/secrets/" + (Fault == "foreign-id" ? "foreign" : name) + "/" + Version;
                string body = JsonSerializer.Serialize(new
                {
                    id,
                    value = Fault == "wrong-value" ? "wrong" : Material,
                    attributes = new { enabled = true }
                });
                if (permission == SecretPermission.List)
                    body = JsonSerializer.Serialize(new { value = new[] { new { id = origin + "/secrets/" + name, attributes = new { enabled = true } } } });
                if (permission == SecretPermission.Delete)
                    body = JsonSerializer.Serialize(new { id, recoveryId = origin + "/deletedsecrets/" + name, attributes = new { enabled = true } });
                if (permission == SecretPermission.Backup) body = JsonSerializer.Serialize(new { value = Encode(Backup) });
                if (Status == 204) body = "";
                if (Status >= 400)
                    body = JsonSerializer.Serialize(new
                    {
                        error = new
                        {
                            code = Fault == "wrong-code" ? "Unknown" : Status == 403 ? "Forbidden" : Status == 404 ? "SecretNotFound" : "Failure",
                            message = Material + "native-sensitive-error"
                        }
                    });
                if (Fault == "duplicate") body = body[..^1] + ",\"id\":\"duplicate\"}";
                if (Fault == "case") body = body.Replace("\"value\"", "\"Value\"", StringComparison.Ordinal);
                if (Fault == "depth") body = new string('[', 12) + "{}" + new string(']', 12);
                if (Fault == "nodes") body = "{\"value\":[" + string.Join(",", Enumerable.Repeat("0", 200)) + "]}";
                if (Fault == "body") body = new string('x', 9000);
                if (Fault == "next") body = body[..^1] + ",\"nextLink\":\"https://foreign.invalid/\"}";
                var response = new HttpResponseMessage((HttpStatusCode)Status);
                response.Headers.TryAddWithoutValidation("x-ms-request-id", requestId);
                if (Fault == "headers") response.Headers.TryAddWithoutValidation("X-Oversize", new string('x', 17000));
                if (Fault == "redirect") response.Headers.Location = new("https://foreign.invalid/");
                LastBody = new(Encoding.UTF8.GetBytes(body), BodyGate);
                response.Content = new StreamContent(LastBody);
                response.Content.Headers.ContentType = new("application/json");
                response.Content.Headers.ContentLength = Encoding.UTF8.GetByteCount(body) + (Fault == "length" ? 1 : 0);
                BeforeReturn?.Invoke();
                return response;
            }
            finally { SendGate?.Exit(); }
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    // Composition, not MemoryStream inheritance: both async overloads reach the
    // same actual borrower, including native code using the legacy overload.
    private sealed class RawBody(byte[] bytes, Barrier? gate) : Stream
    {
        private readonly MemoryStream inner = new(bytes);
        private bool entered;
        internal byte[]? Destination;
        internal bool Disposed;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("async-only");
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) Destination = segment.Array;
            bool first = !entered;
            entered = true;
            try
            {
                if (first && gate is not null) { buffer.Span.Fill(0x5a); await gate.Enter(); }
                return await inner.ReadAsync(buffer, CancellationToken.None);
            }
            finally { if (first) gate?.Exit(Destination!.Any(b => b != 0) && !Disposed); }
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { Disposed = true; inner.Dispose(); base.Dispose(disposing); }
    }

    private sealed class SpyTransport(HttpPipelineTransport inner, Backend backend) : HttpPipelineTransport
    {
        public override Request CreateRequest()
        {
            try
            {
                backend.InitializerGate?.Enter().GetAwaiter().GetResult();
                return backend.LastRequest = inner.CreateRequest();
            }
            finally { backend.InitializerGate?.Exit(); }
        }
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            message.Response = new SpyResponse(message.Response, backend);
        }
    }
    private sealed class SpyResponse(Response inner, Backend backend) : Response
    {
        public override int Status => inner.Status;
        public override string ReasonPhrase => inner.ReasonPhrase;
        public override string ClientRequestId { get => inner.ClientRequestId; set => inner.ClientRequestId = value; }
        public override Stream? ContentStream
        {
            get => inner.ContentStream;
            set
            {
                if (backend.Storage.Count == 0 && value is MemoryStream memory && memory.TryGetBuffer(out var segment))
                {
                    backend.Storage.Add(segment.Array!);
                    inner.ContentStream = backend.SdkGate is { } gate ? new ParserBody(memory, segment.Array!, gate) : memory;
                }
                else inner.ContentStream = value;
            }
        }
        public override void Dispose() => inner.Dispose();
        protected override bool ContainsHeader(string name) => inner.Headers.Contains(name);
        protected override IEnumerable<HttpHeader> EnumerateHeaders() => inner.Headers;
        protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) => inner.Headers.TryGetValue(name, out value);
        protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
            inner.Headers.TryGetValues(name, out values);
    }
    private sealed class ParserBody(Stream inner, byte[] storage, Barrier gate) : Stream
    {
        private bool entered;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            bool first = !entered;
            entered = true;
            try
            {
                if (first) gate.Enter().GetAwaiter().GetResult();
                return inner.Read(buffer, offset, count);
            }
            finally { if (first) gate.Exit(storage.Any(b => b != 0)); }
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            bool first = !entered;
            entered = true;
            try
            {
                if (first) await gate.Enter();
                return await inner.ReadAsync(buffer, CancellationToken.None);
            }
            finally { if (first) gate.Exit(storage.Any(b => b != 0)); }
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { inner.Dispose(); base.Dispose(disposing); }
    }
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Wall = Now;
        internal long Stamp;
        internal Action? BeforeWall, BeforeStamp;
        private readonly List<Timer> timers = [];
        public override DateTimeOffset GetUtcNow() { BeforeWall?.Invoke(); return Wall; }
        public override long GetTimestamp() { BeforeStamp?.Invoke(); return Stamp; }
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Timer(this, callback, state);
            timer.Change(dueTime, period);
            timers.Add(timer);
            return timer;
        }
        internal void Advance(TimeSpan duration)
        {
            Wall += duration;
            Stamp += duration.Ticks;
            foreach (var timer in timers.ToArray())
                if (timer.Due <= Stamp) timer.Fire();
        }
        private sealed class Timer(Clock clock, TimerCallback callback, object? state) : ITimer
        {
            internal long Due;
            internal void Fire() { Due = long.MaxValue; callback(state); }
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                Due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : clock.Stamp + dueTime.Ticks;
                return true;
            }
            public void Dispose() => Due = long.MaxValue;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
