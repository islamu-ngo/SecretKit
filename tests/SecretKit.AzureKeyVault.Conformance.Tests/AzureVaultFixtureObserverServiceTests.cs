using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Collector = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;
using Effects = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using Provisioner = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;
using Service = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

[ParallelLimiter<AzureVaultFixtureProvisionerTests.VaultJournalConcurrency>]
public sealed partial class AzureVaultFixtureProvisionerTests
{
    // Every native step flushes ownership to disk. Bound contention rather
    // than extending fixture deadlines when adding larger owned histories.
    public sealed class VaultJournalConcurrency : TUnit.Core.Interfaces.IParallelLimit
    {
        public int Limit => 4;
    }

    [Test]
    public async Task SecondPrincipalCredentialBorrowerBlocksWholeRootReleaseUntilActualExit()
    {
        await using var f = new VaultServiceFixture(policyVariant: "policies.multiple");
        var lease = await f.PrepareAndBaseline();
        await f.Select(lease);
        f.SecondCredentialEntered = Signal();
        f.SecondCredentialResume = Signal();
        var post = f.Post(lease).AsTask();
        await f.SecondCredentialEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            // Each source is denied-first: the second denied Get has already
            // completed when its intended credential borrower enters.
            await Assert.That(f.TrialSends).IsEqualTo(17);
            await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
            await Assert.That(f.Native.Wire.Active).IsTrue();
            await Assert.That(post.IsCompleted).IsFalse();
        }
        finally { f.SecondCredentialResume.TrySetResult(); }
        try { await post; } catch (NativeCaseFailureException) { }
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("native-application")]
    [Arguments("metadata-application")]
    public async Task MultiplePolicyApplicationSubstitutionCannotQualifyOriginalEffects(string fault)
    {
        await using var f = new VaultServiceFixture(policyVariant: "policies.multiple",
            applications: [Guid.NewGuid(), Guid.NewGuid()]);
        f.SelectedFault = fault;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        if (fault == "native-application")
        {
            await Assert.That(f.TrialSends).IsEqualTo(0);
            await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        }
        else await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalMultiplePolicyHandlerKeepsBothPrincipalsOnOneOwnedVault(string boundary)
    {
        await using var f = new VaultServiceFixture(boundary, policyVariant: "policies.multiple");
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.SelectedSends).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(24);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("omitted")]
    [Arguments("different")]
    [Arguments("mixed")]
    public async Task MultiplePrincipalWindowsProjectThirtyTwoNativeObservationsUnderOneLease(string applications)
    {
        Guid?[] ids = applications switch
        {
            "different" => [Guid.NewGuid(), Guid.NewGuid()],
            "mixed" => [null, Guid.NewGuid()],
            _ => [null, null]
        };
        await using var f = new VaultServiceFixture(policyVariant: "policies.multiple", applications: ids);
        var lease = await f.PrepareAndBaseline();
        await f.Select(lease);
        var measured = await f.Post(lease);
        await Assert.That(measured.PolicyEffects.Length).IsEqualTo(16);
        await Assert.That(measured.PolicyEffects.Select(e => (e.PrincipalId, e.Permission)).Distinct().Count()).IsEqualTo(16);
        await Assert.That(f.TrialSends).IsEqualTo(32);
        await Assert.That(measured.PolicyEffects.All(e => e.IntendedStatus == SecretStatus.Success &&
            e.DeniedStatus == SecretStatus.Denied)).IsTrue();
        await Assert.That(lease.Facts.OwnedResourceIds.Length).IsEqualTo(24);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("order")]
    [Arguments("principal")]
    [Arguments("omitted-application")]
    [Arguments("swapped-application")]
    public async Task MultiplePolicyPrepareCannotSubstituteConfiguredPairs(string field)
    {
        await using var f = new VaultServiceFixture(policyVariant: "policies.multiple",
            applications: [Guid.NewGuid(), Guid.NewGuid()]);
        var original = f.PrepareRequest();
        var first = f.Policies[0];
        var second = f.Policies[1];
        Effects.Policy[] changed = field switch
        {
            "order" => [second, first],
            "principal" => [first, second with { PrincipalId = first.PrincipalId }],
            "omitted-application" => [first, second with { ApplicationId = null }],
            _ => [first with { ApplicationId = second.ApplicationId }, second with { ApplicationId = first.ApplicationId }]
        };
        await Assert.That(async () => await f.Observer.PostAsync<Effects.Prepare, Effects.Lease>(
            "vault/prepare", original with { IntendedPolicies = changed }, default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    public async Task PartialNativeMultiplePolicyApplicationCannotBecomeCompleteEffects()
    {
        await using var f = new VaultServiceFixture(policyVariant: "policies.multiple");
        f.SelectedFault = "partial";
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedSends).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalExplicitApplicationPolicyRetainsConfiguredIdentityAcrossService(string boundary)
    {
        await using var f = new VaultServiceFixture(boundary, policyVariant: "applicationId.value");
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.Requested.ApplicationId).IsNotNull();
        await Assert.That(f.SelectedSends).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("policy")]
    [Arguments("argument")]
    public async Task ExplicitApplicationPolicyCannotSubstituteItsConfiguredIdentity(string field)
    {
        await using var f = new VaultServiceFixture(policyVariant: "applicationId.value");
        var original = f.PrepareRequest();
        var changed = field == "policy"
            ? original with { IntendedPolicies = [f.Requested with { ApplicationId = Guid.NewGuid() }] }
            : original with { ApplicationId = Guid.NewGuid() };
        await Assert.That(async () => await f.Observer.PostAsync<Effects.Prepare, Effects.Lease>(
            "vault/prepare", changed, default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments("permission.Get")]
    [Arguments("permission.List")]
    [Arguments("permission.Set")]
    [Arguments("permission.Delete")]
    [Arguments("permission.Recover")]
    [Arguments("permission.Backup")]
    [Arguments("permission.Restore")]
    [Arguments("permission.Purge")]
    [Arguments("permissions.empty")]
    [Arguments("applicationId.omitted")]
    public async Task OriginalPermissionVariantMeasuresActualRightsAcrossAllFiveBoundaries(string variant)
    {
        foreach (string boundary in new[] { "selected-contract", "independent-effect", "denied-authority",
            "cancellation-boundary", "lost-response-no-replay" })
        {
            await using var f = new VaultServiceFixture(boundary, policyVariant: variant);
            var result = await f.RunOriginal();
            await Assert.That(result.Passed).IsTrue();
            await Assert.That(f.SelectedSends).IsEqualTo(1);
            await Assert.That(f.Native.Read().Released).IsTrue();
            await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(14);
        }
    }

    [Test]
    [Arguments("permission.Get")]
    [Arguments("permission.Purge")]
    [Arguments("permissions.empty")]
    public async Task PermissionVariantCannotPrepareDifferentRequestedRights(string variant)
    {
        await using var f = new VaultServiceFixture(policyVariant: variant);
        var input = f.PrepareRequest() with
        {
            IntendedPolicies = [f.Requested with { Permissions = Enum.GetValues<SecretPermission>() }]
        };
        await Assert.That(async () => await f.Observer.PostAsync<Effects.Prepare, Effects.Lease>(
            "vault/prepare", input, default)).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    public async Task NumericPermissionSelectorCannotCreateNativeOwnership()
    {
        await using var f = new VaultServiceFixture();
        f.Native.Selector = f.Native.Selector with { Variant = "permission.0" };
        await Assert.That(async () => await f.Prepare()).Throws<NativeCaseFailureException>();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalPolicyReplacementMeasuresNewPermissionsFromContrastingBaseline(string boundary)
    {
        await using var f = new VaultServiceFixture(boundary, replacement: true);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.PolicyWrites).IsEqualTo(boundary == "denied-authority" ? 0 : 1);
        await Assert.That(f.SelectedSends).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(14);
    }

    [Test]
    public async Task OriginalPolicyReplacementRejectsSdkSuccessWithOnlyBaselinePermissions()
    {
        await using var f = new VaultServiceFixture(replacement: true);
        f.SelectedFault = "no-effect";
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.PolicyWrites).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalPolicyRemovalUsesActualDenialEffectsOnTheSameOwnedVault(string boundary)
    {
        await using var f = new VaultServiceFixture(boundary, removal: true);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.PolicyWrites).IsEqualTo(boundary == "denied-authority" ? 0 : 1);
        await Assert.That(f.SelectedSends).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(14);
    }

    [Test]
    public async Task OriginalPolicyRemovalRejectsSdkAcknowledgementWithUnchangedBackendPolicy()
    {
        await using var f = new VaultServiceFixture(removal: true);
        f.SelectedFault = "no-effect";
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.PolicyWrites).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task ThrowingSelectedResponseDisposalCannotStrandServiceActivity()
    {
        var f = new VaultServiceFixture();
        try
        {
            var lease = await f.PrepareAndBaseline();
            f.ThrowResponseDisposal = true;
            try { await f.Select(lease); } catch (InvalidOperationException) { }
            await Assert.That(f.ResponseDisposals > 0).IsTrue();
            await Assert.That(f.ResponseStorage is not null && f.ResponseStorage.All(b => b == 0)).IsTrue();
            var release = await f.Release();
            await Assert.That(release.ActiveDispatches).IsEqualTo(0);
            RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
            await f.Source.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally { await f.DisposeHostResources(); }
    }

    [Test]
    public async Task ForeignReceiptCannotLeaveANeverDispatchedSelectedFence()
    {
        await using var f = new VaultServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var client = new VaultAdministration(new VaultSelectedCredential(), f.Source.SelectedTransport);
        var foreign = new VaultAdministration(new VaultSelectedCredential(), f.Source.SelectedTransport);
        var scope = new VaultScope(new(new(Subscription), "fixture-group"), lease.VaultName);
        try
        {
            await f.Source.RunChangeAccessPoliciesAsync(f.Native.Selector, client, scope, AccessPolicyChange.Add,
                [f.Requested.Build()], foreign.PrepareReceipt(scope, ManagementMutation.AddAccessPolicy), default);
        }
        catch (InvalidOperationException) { }
        await Assert.That(f.SelectedSends).IsEqualTo(0);
        var release = await f.Release();
        await Assert.That(release.ActiveDispatches).IsEqualTo(0);
        RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalPolicyHandlerUsesNativeServiceWitnessAndOriginalCleanup(string boundary)
    {
        await using var f = new VaultServiceFixture(boundary);
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(f.PolicyWrites).IsEqualTo(boundary == "denied-authority" ? 0 : 1);
        await Assert.That(f.SelectedSends).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(14);
        await Assert.That(f.Native.Wire.Active || f.Native.Wire.Deleted).IsFalse();
    }

    [Test]
    public async Task OriginalPolicyHandlerRejectsSdkSuccessWithoutNativePolicyEffect()
    {
        await using var f = new VaultServiceFixture("independent-effect");
        f.SelectedFault = "no-effect";
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch");
        await Assert.That(f.PolicyWrites).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("pending")]
    [Arguments("foreign")]
    [Arguments("duplicate")]
    [Arguments("malformed")]
    [Arguments("oversized")]
    [Arguments("continuation")]
    [Arguments("length")]
    [Arguments("missing-secrets")]
    public async Task UnprovenOriginalNativePolicyResponseRetainsFenceAndPreventsTrials(string fault)
    {
        await using var f = new VaultServiceFixture();
        var lease = await f.PrepareAndBaseline();
        f.SelectedFault = fault;
        try { await f.Select(lease); } catch (Exception) { }
        await Assert.That(f.TrialSends).IsEqualTo(0);
        await Assert.That(async () => await f.Post(lease)).Throws<NativeCaseFailureException>();
        await Assert.That(f.TrialSends).IsEqualTo(0);
        var release = await f.Release();
        await Assert.That(release.ActiveDispatches > 0).IsTrue();
        await Assert.That(f.Native.Wire.Active).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    [Arguments("lease")]
    [Arguments("subscription")]
    [Arguments("phase")]
    public async Task AlteredObservationCannotConsumeOriginalPostWindow(string field)
    {
        await using var f = new VaultServiceFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Select(lease);
        var original = f.PostRequest(lease);
        var changed = field switch
        {
            "lease" => original with { LeaseId = Guid.NewGuid() },
            "subscription" => original with { SubscriptionId = Guid.NewGuid() },
            _ => original with { Phase = "caller-provided-result" }
        };
        await Assert.That(async () => await f.Observer.PostAsync<ObserveLease, Effects.Measurement>(
            "vault/observe", changed, default)).Throws<NativeCaseFailureException>();
        await Assert.That(f.TrialSends).IsEqualTo(0);
        var actual = await f.Post(lease);
        await Assert.That(actual.PolicyEffects.Length).IsEqualTo(8);
        await Assert.That(f.TrialSends).IsEqualTo(16);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    [Arguments("foreign")]
    public async Task UnusablePrepareReplyStillReleasesOriginalOwnedJournal(string fault)
    {
        await using var f = new VaultServiceFixture();
        f.PrepareReplyFault = fault;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedSends).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Native.Wire.Active || f.Native.Wire.Deleted).IsFalse();
    }

    [Test]
    [Arguments("selector")]
    [Arguments("scope")]
    [Arguments("change")]
    [Arguments("principal")]
    [Arguments("permissions")]
    public async Task ForeignSelectedInputsCannotConsumeTheOriginalInvocation(string field)
    {
        await using var f = new VaultServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var client = new VaultAdministration(new VaultSelectedCredential(), f.Source.SelectedTransport);
        var scope = new VaultScope(new(new(Subscription), "fixture-group"),
            field == "scope" ? "foreign-vault" : lease.VaultName);
        var selector = field == "selector" ? f.Native.Selector with { Case = "denied-authority" } : f.Native.Selector;
        var policy = field == "principal" ? f.Requested with { PrincipalId = Guid.NewGuid() } :
            field == "permissions" ? f.Requested with { Permissions = [SecretPermission.Get] } : f.Requested;
        await Assert.That(async () => await f.Source.RunChangeAccessPoliciesAsync(selector, client, scope,
            field == "change" ? AccessPolicyChange.Remove : AccessPolicyChange.Add, [policy.Build()],
            client.PrepareReceipt(scope, ManagementMutation.AddAccessPolicy), default)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedSends).IsEqualTo(0);
        await f.Select(lease);
        await Assert.That(f.SelectedSends).IsEqualTo(1);
    }

    [Test]
    public async Task ReleaseBeforePrepareCreatesOriginalTombstoneAndPreventsProvisioning()
    {
        await using var f = new VaultServiceFixture();
        var release = await f.Release();
        RoleFixtureRelease.Validate(release, f.Native.Selector, null);
        await Assert.That(async () => await f.Prepare()).Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Wire.Active).IsFalse();
        await Assert.That(f.SelectedSends).IsEqualTo(0);
    }

    [Test]
    [Arguments("variant")]
    [Arguments("replacement-baseline")]
    [Arguments("operation")]
    [Arguments("principal")]
    [Arguments("configuration")]
    [Arguments("application")]
    public async Task UnadmittedPolicyPrepareNeverCreatesNativeOwnership(string field)
    {
        await using var f = new VaultServiceFixture();
        var original = f.PrepareRequest();
        var invalid = field switch
        {
            "variant" => original with { Selection = original.Selection with { Variant = "change.Remove" } },
            "replacement-baseline" => original with { Selection = original.Selection with { Variant = "change.Replace" } },
            "operation" => original with { Selection = original.Selection with { Operation = "foreign" } },
            "principal" => original with { IntendedPolicies = [f.Requested with { PrincipalId = Guid.NewGuid() }] },
            "configuration" => original with { Configuration = original.Configuration with { Rbac = true } },
            _ => original with { IntendedPolicies = [f.Requested with { ApplicationId = Guid.NewGuid() }] }
        };
        await Assert.That(async () => await f.Observer.PostAsync<Effects.Prepare, Effects.Lease>(
            "vault/prepare", invalid, default)).Throws<NativeCaseFailureException>();
        await Assert.That(f.Native.Wire.Active || f.Native.Wire.Deleted).IsFalse();
        await Assert.That(File.Exists(f.Native.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments("capability")]
    [Arguments("duplicate")]
    [Arguments("unknown")]
    [Arguments("oversized")]
    public async Task IngressRejectsUntrustedPrepareBeforeNativeWork(string fault)
    {
        await using var f = new VaultServiceFixture();
        string json = JsonSerializer.Serialize(f.PrepareRequest(), ManagementAdmission.Json);
        if (fault == "duplicate") json = """{"selection":null,"selection":null}""";
        if (fault == "unknown") json = json[..^1] + ",\"selectedResult\":\"success\"}";
        if (fault == "oversized") json = "{\"padding\":\"" + new string('x', 70000) + "\"}";
        using var request = new HttpRequestMessage(HttpMethod.Post, f.Origin + "vault/prepare");
        request.Headers.Authorization = new("Bearer", fault == "capability" ? "foreign" : VaultServiceFixture.Capability);
        request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await f.Source.DispatchAsync(request, default);
        await Assert.That(response.IsSuccessStatusCode).IsFalse();
        await Assert.That(f.Native.Wire.Active).IsFalse();
    }

    [Test]
    public async Task RepeatedSelectedInvocationCannotReplayOrConsumePostObservationTwice()
    {
        await using var f = new VaultServiceFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Select(lease);
        await Assert.That(async () => await f.Select(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedSends).IsEqualTo(1);
        var result = await f.Post(lease);
        await Assert.That(result.PolicyEffects.Length).IsEqualTo(8);
        await Assert.That(async () => await f.Post(lease)).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task ReleaseAndDisposalJoinActualSelectedCredentialBeforeAllowingCleanup()
    {
        await using var f = new VaultServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var credential = new VaultSelectedCredential { Entered = Signal(), Resume = Signal() };
        var actual = f.Select(lease, credential);
        await credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var disposal = f.Source.DisposeAsync().AsTask();
        try
        {
            await Assert.That(disposal.IsCompleted).IsFalse();
            await Assert.That(f.Native.Wire.Active).IsTrue();
            await Assert.That(f.Native.Read().Resources.Single(r => r.ActiveDispatch != Guid.Empty).InvocationTerminated).IsFalse();
        }
        finally { credential.Resume.TrySetResult(); }
        try { await actual; } catch (Exception) { }
        await disposal;
        await Assert.That(f.SelectedSends).IsEqualTo(0);
        await Assert.That(f.Native.Wire.Active).IsTrue();
    }

    [Test]
    public async Task ReleaseRetainsSelectedResponseBorrowerUntilActualExit()
    {
        await using var f = new VaultServiceFixture();
        var lease = await f.PrepareAndBaseline();
        f.BodyEntered = Signal();
        f.BodyResume = Signal();
        var actual = f.Select(lease);
        await f.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            var release = await f.Release();
            await Assert.That(release.ActiveDispatches > 0).IsTrue();
            await Assert.That(f.Native.Wire.Active).IsTrue();
            await Assert.That(actual.IsCompleted).IsFalse();
        }
        finally { f.BodyResume.TrySetResult(); }
        try { await actual; } catch (Exception) { }
        var retained = f.Native.Read().Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        await Assert.That(retained.Id).IsEqualTo(f.Native.Wire.VaultId);
        await Assert.That(retained.InvocationTerminated).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RestartedServiceCleansOnlyWhenOriginalSelectedFenceIsSettled(bool lost)
    {
        await using var f = new VaultServiceFixture();
        var lease = await f.PrepareAndBaseline();
        if (lost) f.SelectedFault = "lost";
        try { await f.Select(lease); } catch (Exception) { }
        await f.Source.DisposeAsync();
        await using var restarted = f.Reopen();
        using var observer = new OwnedManagementObserver(new(f.Origin, VaultServiceFixture.Capability, TimeSpan.FromSeconds(20)),
            new VaultForwarder(restarted.DispatchAsync));
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default);
        if (lost)
        {
            await Assert.That(release.ActiveDispatches > 0).IsTrue();
            await Assert.That(f.Native.Wire.Active).IsTrue();
        }
        else
        {
            RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
            await Assert.That(f.Native.Wire.Active || f.Native.Wire.Deleted).IsFalse();
        }
        await Assert.That(f.SelectedSends).IsEqualTo(1);
    }

    [Test]
    public async Task SourcePolicyRoutesRunThroughRealLocalHttps()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        Service? service = null;
        await using var host = RoleFixtureObserverHost.Start(certificate, new(IPAddress.Loopback, 0),
            (message, token) => service!.DispatchAsync(message, token));
        await using var f = new VaultServiceFixture(origin: host.Origin);
        service = f.Source;
        using var observer = new OwnedManagementObserver(new(host.Origin, VaultServiceFixture.Capability, TimeSpan.FromSeconds(10)),
            new HttpClientHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, leaf, _, errors) => leaf is not null &&
                    (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 && leaf.RawData.AsSpan().SequenceEqual(certificate.RawData)
            });
        var lease = await observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare", f.PrepareRequest(), default);
        var subscription = await observer.SubscribeAsync("vault", lease.Facts, default);
        await observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
            new(lease.Facts.LeaseId, f.Native.Selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId), default);
        await f.Select(lease);
        var measured = await observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
            new(lease.Facts.LeaseId, f.Native.Selector.Nonce, "post-operation", subscription.SubscriptionId), default);
        await Assert.That(measured.PolicyEffects.Length).IsEqualTo(8);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default);
        RoleFixtureRelease.Validate(release, f.Native.Selector, lease.Facts);
    }

    private sealed class VaultServiceFixture : IAsyncDisposable
    {
        internal const string Capability = "private-vault-service-capability";
        internal readonly Fixture Native;
        internal readonly Service Source;
        internal readonly OwnedManagementObserver Observer;
        internal readonly Uri Origin;
        internal readonly Effects.Policy Requested = new(Tenant, Principal, Enum.GetValues<SecretPermission>(), null);
        internal readonly Effects.Policy[] Policies;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly Provisioner provisioner;
        private readonly Service.WindowSource windowSource;
        private readonly HttpPipelineTransport runtime;
        internal string? SelectedFault, PrepareReplyFault;
        internal int PolicyWrites, SelectedSends, TrialSends, ResponseDisposals;
        internal bool ThrowResponseDisposal;
        internal byte[]? ResponseStorage;
        internal TaskCompletionSource? BodyEntered, BodyResume;
        internal TaskCompletionSource? SecondCredentialEntered, SecondCredentialResume;
        private ObservationSubscription? subscription;

        internal VaultServiceFixture(string boundary = "selected-contract", Uri? origin = null,
            bool removal = false, bool replacement = false, string? policyVariant = null, Guid?[]? applications = null)
        {
            Native = new(allowPurge: true, emptyPolicies: true, policyWitness: true,
                policyRemoval: removal, policyReplacement: replacement);
            if (policyVariant is not null)
            {
                Native.Selector = Native.Selector with { Variant = policyVariant };
                Requested = Requested with
                {
                    ApplicationId = policyVariant == "applicationId.value" ? Guid.NewGuid() : null,
                    Permissions = policyVariant == "permissions.empty" ? [] :
                        policyVariant.StartsWith("permission.", StringComparison.Ordinal)
                            ? [Enum.Parse<SecretPermission>(policyVariant["permission.".Length..])]
                            : Enum.GetValues<SecretPermission>()
                };
            }
            Policies = policyVariant == "policies.multiple"
                ? [Requested with { ApplicationId = applications?[0] },
                    new(Tenant, Guid.NewGuid(), Enum.GetValues<SecretPermission>(), applications?[1])]
                : [Requested];
            Requested = Policies[0];
            Origin = origin ?? new("https://vault-fixture.invalid/");
            Native.Selector = Native.Selector with { Case = boundary };
            HttpPipelineTransport Transport(string role)
            {
                var client = new HttpClient(new VaultServiceNative(this, role));
                clients.Add(client);
                var transport = new HttpClientTransport(client);
                return role == "selected-arm" ? new VaultResponseTransport(transport, this) : transport;
            }
            var scope = new Provisioner.HostScope(Subscription, "fixture-group", "eastus", Tenant, true, true);
            provisioner = new(Native.Journal, scope, Native.Baseline,
                new("setup-arm", new Credential("setup-arm"), Transport("setup-arm")),
                new("setup-secret", new Credential("setup-secret"), Transport("setup-secret")),
                new("read-arm", new Credential("read-arm"), Transport("read-arm")),
                new("read-secret", new Credential("read-secret"), Transport("read-secret")),
                new(65536, TimeSpan.FromSeconds(20)));
            var metadata = new Collector(new("metadata", new Credential("read-arm"), Transport("read-arm")),
                new(2, 32, 65536, 8192, TimeSpan.FromSeconds(20)));
            windowSource = new(Native.Journal, provisioner, metadata,
                Policies.Select((p, i) =>
                {
                    string channel = i == 0 ? "intended-secret" : "intended-second-secret";
                    return new Service.PrincipalSource(new(Tenant, p.PrincipalId, p.ApplicationId),
                        new(channel, new VaultPrincipalCredential(new Credential(channel), this, i), Transport(channel)));
                }).ToArray(),
                new("denied", new Credential("denied-secret"), Transport("denied-secret")),
                new("observer", new Credential("read-secret"), Transport("read-secret")), Transport("selected-arm"));
            Source = Reopen();
            runtime = Transport("runtime");
            Observer = new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(Source.DispatchAsync));
        }

        internal Service Reopen() => new(Origin, Owner, "vault-source", capability,
            new(Subscription, "fixture-group", "eastus", Tenant, true, true), Native.Baseline,
            windowSource, new(65536, 1024 * 1024, TimeSpan.FromSeconds(20)));

        internal Effects.Prepare PrepareRequest() => new(Native.Selector, Subscription, "fixture-group",
            Native.Baseline, Policies, Requested.ApplicationId ?? Guid.Empty);
        internal ValueTask<Effects.Lease> Prepare() =>
            Observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare", PrepareRequest(), default);
        internal async Task<Effects.Lease> PrepareAndBaseline()
        {
            var lease = await Prepare();
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, Native.Selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId), default);
            return lease;
        }
        internal ObserveLease PostRequest(Effects.Lease lease) =>
            new(lease.Facts.LeaseId, Native.Selector.Nonce, "post-operation", subscription!.SubscriptionId);
        internal ValueTask<Effects.Measurement> Post(Effects.Lease lease) =>
            Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe", PostRequest(lease), default);
        internal ValueTask<RoleFixtureRelease.Measurement> Release() =>
            Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", Native.Selector, default);
        internal async Task<SecretOutcome<AccessPolicyObservation>> Select(Effects.Lease lease, VaultSelectedCredential? credential = null)
        {
            var client = new VaultAdministration(credential ?? new VaultSelectedCredential(), Source.SelectedTransport);
            var scope = new VaultScope(new(new(Subscription), "fixture-group"), lease.VaultName);
            var result = await Source.RunChangeAccessPoliciesAsync(Native.Selector, client, scope,
                Native.Selector.Variant switch
                {
                    "change.Remove" => AccessPolicyChange.Remove,
                    "change.Replace" => AccessPolicyChange.Replace,
                    _ => AccessPolicyChange.Add
                },
                Policies.Select(p => p.Build()).ToArray(), client.PrepareReceipt(scope, Native.Selector.Variant switch
                {
                    "change.Remove" => ManagementMutation.RemoveAccessPolicy,
                    "change.Replace" => ManagementMutation.ReplaceAccessPolicy,
                    _ => ManagementMutation.AddAccessPolicy
                }), default);
            return result;
        }

        internal async Task<NativeCaseResult> RunOriginal()
        {
            object RuntimeCredential(string value) => new { token = value, expiresAt = "2099-01-01T00:00:00Z" };
            AudienceToken Arm(string value) => new(value, DateTimeOffset.MaxValue, "https://management.azure.com/.default");
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://controlled.vault.azure.net",
                setup = RuntimeCredential("setup-secret"),
                runtime = RuntimeCredential("intended-secret"),
                denied = RuntimeCredential("denied-secret"),
                administrative = RuntimeCredential("administrative-secret"),
                observer = RuntimeCredential("observer-secret"),
                families = new Dictionary<string, object>
                {
                    ["VaultAdministration"] = new Effects.Input(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                        new(Arm("setup-arm"), Arm("selected-arm"), Arm("denied-arm"), Arm("observer-arm")),
                        Subscription, "fixture-group", Native.Baseline, Policies, Requested.ApplicationId ?? Guid.Empty,
                        2, 32, TimeSpan.FromSeconds(20))
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(json.RootElement);
            var member = Effects.Members.Single(m => m.Operation == Native.Selector.Operation);
            var definition = new NativeCaseDefinition(new("AzureKeyVault", member.Operation, Native.Selector.Variant,
                "controlled", Native.Selector.Case), member.Member);
            var registry = new NativeCaseRegistry();
            Effects.Register(registry, environment, [definition], endpoint =>
                new(endpoint, new VaultForwarder(async (request, token) =>
                {
                    if (request.RequestUri!.AbsolutePath == "/vault/prepare")
                        Native.Selector = JsonSerializer.Deserialize<Effects.Prepare>(
                            await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!.Selection;
                    var response = await Source.DispatchAsync(request, token);
                    if (request.RequestUri!.AbsolutePath != "/vault/prepare" || PrepareReplyFault is null) return response;
                    response.Dispose();
                    if (PrepareReplyFault == "lost") throw new IOException("test-lost-prepare-reply");
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(PrepareReplyFault == "malformed" ? "{" : "{}",
                            Encoding.UTF8, "application/json")
                    };
                })), Source.SelectedTransport, runtime, Source);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }

        internal async Task<HttpResponseMessage> Send(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (Native.Wire.VaultId.Length == 0 && path.Contains("/vaults/", StringComparison.Ordinal))
            {
                Native.Wire.VaultId = path;
                Native.Wire.VaultName = path[(path.LastIndexOf('/') + 1)..];
            }
            if (role == "selected-arm")
            {
                SelectedSends++;
                string action = Native.Selector.Variant switch
                {
                    "change.Remove" => "remove",
                    "change.Replace" => "replace",
                    _ => "add"
                };
                if (!path.Equals(Native.Wire.VaultId + "/accessPolicies/" + action, StringComparison.OrdinalIgnoreCase) || request.Method != HttpMethod.Put ||
                    request.RequestUri.Query != "?api-version=2026-02-01")
                    throw new InvalidOperationException("test-selected-target");
                if (request.Headers.Authorization?.Parameter == "denied-arm")
                    return Reply(403, """{"error":{"code":"Forbidden"}}""");
                if (request.Headers.Authorization?.Parameter != "selected-arm")
                    throw new InvalidOperationException("test-selected-authority");
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                JsonNode policies = JsonNode.Parse(body.RootElement.GetProperty("properties").GetProperty("accessPolicies").GetRawText())!;
                if (SelectedFault != "no-effect")
                {
                    Native.Wire.Vault!["properties"]!["accessPolicies"] = action == "remove" ? new JsonArray() :
                        SelectedFault == "partial" ? new JsonArray(policies[0]!.DeepClone()) : policies.DeepClone();
                    PolicyWrites++;
                }
                var responseBody = new JsonObject
                {
                    ["id"] = Native.Wire.VaultId,
                    ["properties"] = new JsonObject { ["accessPolicies"] = action == "remove" ? new JsonArray() : policies }
                };
                if (SelectedFault == "lost") throw new IOException("test-native-loss");
                if (SelectedFault == "foreign") responseBody["id"] = Native.Wire.VaultId + "-foreign";
                if (SelectedFault == "native-application")
                    responseBody["properties"]!["accessPolicies"]![1]!["applicationId"] = Guid.NewGuid().ToString("D");
                if (SelectedFault == "missing-secrets")
                    responseBody["properties"]!["accessPolicies"]![0]!["permissions"]!.AsObject().Remove("secrets");
                string text = responseBody.ToJsonString();
                if (SelectedFault == "malformed") text = "{";
                if (SelectedFault == "duplicate") text = text[..^1] + ",\"id\":\"foreign\"}";
                if (SelectedFault == "oversized") text = "{\"padding\":\"" + new string('x', 70000) + "\"}";
                var response = Reply(SelectedFault == "pending" ? 202 : 200, text);
                if (SelectedFault == "continuation") response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", "https://foreign.invalid/");
                if (SelectedFault == "length") response.Content.Headers.ContentLength = 1;
                if (BodyEntered is not null && BodyResume is not null)
                {
                    response.Content.Dispose();
                    response.Content = new StreamContent(new VaultSelectedBody(Encoding.UTF8.GetBytes(text), BodyEntered, BodyResume));
                    response.Content.Headers.ContentType = new("application/json");
                }
                return response;
            }
            if (role == "runtime") role = request.Headers.Authorization?.Parameter ?? "intended-secret";
            if (role is "intended-secret" or "intended-second-secret" or "denied-secret")
            {
                TrialSends++;
                var principal = Policies[role == "intended-second-secret" ? 1 : 0];
                string[] parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
                SecretPermission permission = request.Method == HttpMethod.Get
                    ? parts.Length == 1 ? SecretPermission.List : SecretPermission.Get
                    : request.Method == HttpMethod.Put ? SecretPermission.Set
                    : request.Method == HttpMethod.Delete
                        ? parts[0] == "deletedsecrets" ? SecretPermission.Purge : SecretPermission.Delete
                        : parts[0] == "deletedsecrets" ? SecretPermission.Recover
                        : parts[1] == "restore" ? SecretPermission.Restore : SecretPermission.Backup;
                bool permitted = Native.Wire.Vault?["properties"]?["accessPolicies"]?.AsArray()
                    .Any(p => p?["objectId"]?.GetValue<string>() == principal.PrincipalId.ToString("D") &&
                        p?["applicationId"]?.GetValue<string>() == principal.ApplicationId?.ToString("D") &&
                        p?["permissions"]?["secrets"]?.AsArray().Any(s =>
                            string.Equals(s?.GetValue<string>(), permission.ToString(), StringComparison.OrdinalIgnoreCase)) == true) == true;
                if (role is "intended-secret" or "intended-second-secret" && !permitted)
                    return Reply(403, """{"error":{"code":"Forbidden"}}""");
            }
            var native = await Native.Wire.Respond(request, role, token);
            if (SelectedFault == "metadata-application" && role == "read-arm" &&
                SelectedSends > 0 && request.Method == HttpMethod.Get &&
                path == Native.Wire.VaultId && native.StatusCode == HttpStatusCode.OK)
            {
                var replaced = JsonNode.Parse(await native.Content.ReadAsStringAsync(token))!;
                replaced["properties"]!["accessPolicies"]![1]!["applicationId"] = Guid.NewGuid().ToString("D");
                native.Dispose();
                return Reply(200, replaced.ToJsonString());
            }
            return native;
        }

        private static HttpResponseMessage Reply(int status, string body)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            response.Headers.TryAddWithoutValidation("x-ms-request-id", Guid.NewGuid().ToString("D"));
            return response;
        }
        public async ValueTask DisposeAsync()
        {
            await Source.DisposeAsync();
            await DisposeHostResources();
        }
        internal async ValueTask DisposeHostResources()
        {
            Observer.Dispose();
            await provisioner.DisposeAsync();
            capability.Dispose();
            foreach (var client in clients) client.Dispose();
            Native.Dispose();
        }
    }

    private sealed class VaultPrincipalCredential(TokenCredential inner, VaultServiceFixture fixture, int index) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            if (index == 1 && fixture.SecondCredentialResume is { } resume)
            {
                fixture.SecondCredentialEntered!.TrySetResult();
                await resume.Task;
            }
            return await inner.GetTokenAsync(requestContext, cancellationToken);
        }
    }

    private sealed class VaultResponseTransport(HttpPipelineTransport inner, VaultServiceFixture fixture) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (fixture.ThrowResponseDisposal) message.Response = new ThrowingVaultResponse(message.Response, fixture);
        }
    }
    private sealed class ThrowingVaultResponse(Response inner, VaultServiceFixture fixture) : Response
    {
        public override int Status => inner.Status;
        public override string ReasonPhrase => inner.ReasonPhrase;
        public override string ClientRequestId { get => inner.ClientRequestId; set => inner.ClientRequestId = value; }
        public override Stream? ContentStream
        {
            get => inner.ContentStream;
            set
            {
                if (fixture.ResponseStorage is null && value is MemoryStream memory && memory.TryGetBuffer(out var storage))
                    fixture.ResponseStorage = storage.Array;
                inner.ContentStream = value;
            }
        }
        public override void Dispose()
        {
            inner.Dispose();
            fixture.ResponseDisposals++;
            throw new InvalidOperationException("controlled-response-disposal");
        }
        protected override bool ContainsHeader(string name) => inner.Headers.Contains(name);
        protected override IEnumerable<HttpHeader> EnumerateHeaders() => inner.Headers;
        protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) => inner.Headers.TryGetValue(name, out value);
        protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
            inner.Headers.TryGetValues(name, out values);
    }

    private sealed class VaultForwarder(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
    private sealed class VaultServiceNative(VaultServiceFixture fixture, string role) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            fixture.Send(request, role, cancellationToken);
    }
    private sealed class VaultSelectedCredential : TokenCredential
    {
        internal TaskCompletionSource? Entered, Resume;
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            if (requestContext.Scopes.Single() != "https://management.azure.com/.default")
                throw new InvalidOperationException("test-selected-audience");
            Entered?.TrySetResult();
            if (Resume is not null) await Resume.Task;
            cancellationToken.ThrowIfCancellationRequested();
            return new("selected-arm", DateTimeOffset.MaxValue);
        }
    }
    private sealed class VaultSelectedBody(byte[] bytes, TaskCompletionSource entered, TaskCompletionSource resume) : MemoryStream(bytes)
    {
        private bool blocked;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!blocked) { blocked = true; entered.TrySetResult(); await resume.Task; }
            return base.Read(buffer.Span);
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }
}
