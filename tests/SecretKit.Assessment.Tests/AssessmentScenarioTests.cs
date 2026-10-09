using System.Text.Json;
using SecretKit.AzureKeyVault;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Samples.ProviderAssessment;

namespace SecretKit.Assessment.Tests;

public sealed class AssessmentScenarioTests
{
    private static readonly DateTimeOffset ObservedAt = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task AdministratorVisibilityDoesNotGrantRuntimePermission()
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader { Status = SecretStatus.Denied };
        var scenario = new AssessmentScenario(admin, intended);

        AssessmentReport report = await scenario.CheckAsync(admin.Scope, Selection(intended, required: true));

        await Assert.That(report.Inventory.VisibleItems).IsEqualTo(1);
        await Assert.That(report.Inventory.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Denied);
        await Assert.That(report.Features[0].Keys[0].ReadStatus).IsEqualTo(SecretStatus.Denied);
        await Assert.That(report.CanProceed).IsFalse();
        await Assert.That(report.Features[0].CanEnable).IsFalse();
    }

    [Test]
    [Arguments(true, false)]
    [Arguments(false, true)]
    public async Task ConsumerRequiredPolicyControlsWhetherAbsenceBlocks(bool required, bool canProceed)
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader { Status = SecretStatus.Absent };

        AssessmentReport report = await new AssessmentScenario(admin, intended)
            .CheckAsync(admin.Scope, Selection(intended, required));

        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Absent);
        await Assert.That(report.CanProceed).IsEqualTo(canProceed);
        await Assert.That(report.Features[0].CanEnable).IsFalse();
    }

    [Test]
    public async Task EverySelectedKeyIsNeededAndResultsKeepInputCorrelation()
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader
        {
            Read = (reference, _) => ValueTask.FromResult(
                reference.Address is AzureSecretAddress { Name: "missing" }
                    ? SecretOutcome<SecretRead>.Failure(SecretStatus.Absent)
                    : Success(reference))
        };
        FeatureRequirement[] requirements =
        [
            new("required", true, [Key(intended, "available")]),
            new("optional", false, [Key(intended, "available"), Key(intended, "missing")])
        ];

        AssessmentReport report = await new AssessmentScenario(admin, intended).CheckAsync(admin.Scope, requirements);

        await Assert.That(report.Features[0].FeatureIndex).IsEqualTo(0);
        await Assert.That(report.Features[1].FeatureIndex).IsEqualTo(1);
        await Assert.That(report.Features[1].Keys[1].KeyIndex).IsEqualTo(1);
        await Assert.That(report.Features[1].Keys[0].State).IsEqualTo(AssessmentState.Ready);
        await Assert.That(report.Features[1].Keys[1].State).IsEqualTo(AssessmentState.Absent);
        await Assert.That(report.Features[0].CanEnable).IsTrue();
        await Assert.That(report.Features[1].CanEnable).IsFalse();
        await Assert.That(report.CanProceed).IsTrue();
    }

    [Test]
    [Arguments(SecretStatus.Unavailable)]
    [Arguments(SecretStatus.Unknown)]
    [Arguments(SecretStatus.Throttled)]
    [Arguments(SecretStatus.ContractNotEstablished)]
    [Arguments(SecretStatus.Unsupported)]
    [Arguments(SecretStatus.EntitlementUnavailable)]
    [Arguments(SecretStatus.RecoveryRequired)]
    public async Task UnverifiedOutcomesPreserveBoundedProviderStatus(SecretStatus status)
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader { Status = status };

        AssessmentReport report = await new AssessmentScenario(admin, intended)
            .CheckAsync(admin.Scope, Selection(intended));

        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Unverified);
        await Assert.That(report.Features[0].Keys[0].ReadStatus).IsEqualTo(status);
        await Assert.That(report.CanProceed).IsFalse();
    }

    [Test]
    [Arguments(SecretValidity.Unknown, AssessmentState.Unverified)]
    [Arguments(SecretValidity.Disabled, AssessmentState.Unusable)]
    [Arguments(SecretValidity.Expired, AssessmentState.Unusable)]
    [Arguments(SecretValidity.NotYetValid, AssessmentState.Unusable)]
    public async Task SuccessfulReadDoesNotOverrideValidity(SecretValidity validity, AssessmentState state)
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader { Validity = validity };

        AssessmentReport report = await new AssessmentScenario(admin, intended)
            .CheckAsync(admin.Scope, Selection(intended));

        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(state);
        await Assert.That(report.Features[0].Keys[0].Validity).IsEqualTo(validity);
        await Assert.That(report.CanProceed).IsFalse();
        await Assert.That(() => intended.LastMaterial!.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task UncheckedAndIndirectKeysAreNotDeliveryProof()
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader();
        FeatureRequirement[] requirements =
        [
            new("feature", true,
            [
                new("unchecked", Key(intended).Reference, DeliveryKind.NotChecked),
                new("indirect", Key(intended).Reference, DeliveryKind.Indirect)
            ])
        ];

        AssessmentReport report = await new AssessmentScenario(admin, intended).CheckAsync(admin.Scope, requirements);

        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Unverified);
        await Assert.That(report.Features[0].Keys[0].ReadStatus).IsNull();
        await Assert.That(report.Features[0].Keys[1].State).IsEqualTo(AssessmentState.Indirect);
        await Assert.That(report.Features[0].Keys[1].ReadStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(report.CanProceed).IsFalse();
    }

    [Test]
    [Arguments(InfisicalResolution.Raw, false, AssessmentState.Ready)]
    [Arguments(InfisicalResolution.ExpandedReferences, false, AssessmentState.Indirect)]
    [Arguments(InfisicalResolution.Raw, true, AssessmentState.Indirect)]
    [Arguments(InfisicalResolution.ExpandedReferences, true, AssessmentState.Indirect)]
    public async Task NativeInfisicalChoicesRemainExplicitWithoutInventedResolution(
        InfisicalResolution resolution, bool includeImports, AssessmentState state)
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader
        {
            // Selected coordinates affect the observable result, not a mock call-count assertion.
            Read = (reference, _) => ValueTask.FromResult(
                reference.Address is InfisicalSecretAddress address &&
                address.ProjectId == "project" && address.Environment == "test" &&
                address.Folder == "/selected" && address.Key == "key" &&
                address.Version == 7 && address.Resolution == resolution &&
                address.IncludeImports == includeImports
                    ? Success(reference)
                    : SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid))
        };
        var reference = new SecretReference(intended.Authority,
            new InfisicalSecretAddress("project", "test", "/selected", "key", 7, resolution, includeImports));

        AssessmentReport report = await new AssessmentScenario(admin, intended).CheckAsync(admin.Scope,
            [new FeatureRequirement("feature", true, [new("key", reference, DeliveryKind.Direct)])]);

        await Assert.That(report.Features[0].Keys[0].ReadStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(state);
        await Assert.That(report.CanProceed).IsEqualTo(state == AssessmentState.Ready);
    }

    [Test]
    public async Task NativeAzurePinnedVersionIsNotReplacedByInventoryLatest()
    {
        var admin = new ControlledInventory();
        string version = new('a', 32);
        var intended = new ControlledReader
        {
            Read = (reference, _) => ValueTask.FromResult(
                reference.Address is AzureSecretAddress { Name: "selected" } address && address.Version == version
                    ? Success(reference)
                    : SecretOutcome<SecretRead>.Failure(SecretStatus.Absent))
        };
        var reference = new SecretReference(intended.Authority, new AzureSecretAddress("selected", version));

        AssessmentReport report = await new AssessmentScenario(admin, intended).CheckAsync(admin.Scope,
            [new FeatureRequirement("feature", true, [new("key", reference, DeliveryKind.Direct)])]);

        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Ready);
        await Assert.That(report.CanProceed).IsTrue();
    }

    [Test]
    public async Task AdminReferenceCannotBeSubstitutedOrRebound()
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader();
        var reference = new SecretReference(admin.Authority, new AzureSecretAddress("selected"));

        AssessmentReport report = await new AssessmentScenario(admin, intended).CheckAsync(admin.Scope,
            [new FeatureRequirement("feature", true, [new("key", reference, DeliveryKind.Direct)])]);

        await Assert.That(report.Features[0].Keys[0].ReadStatus).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Unusable);
        await Assert.That(report.CanProceed).IsFalse();
    }

    [Test]
    [Arguments(SecretStatus.Success, false)]
    [Arguments(SecretStatus.Denied, false)]
    [Arguments(SecretStatus.Unavailable, false)]
    public async Task IncompleteOrFailedInventoryDoesNotDetermineRuntimeDelivery(SecretStatus status, bool complete)
    {
        var admin = new ControlledInventory { Status = status, Complete = complete, Visible = false };
        var intended = new ControlledReader();

        AssessmentReport report = await new AssessmentScenario(admin, intended)
            .CheckAsync(admin.Scope, Selection(intended));

        await Assert.That(report.Inventory.Status).IsEqualTo(status);
        await Assert.That(report.Inventory.IsComplete).IsFalse();
        await Assert.That(report.Inventory.IsPointInTime).IsFalse();
        await Assert.That(report.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Ready);
        await Assert.That(report.CanProceed).IsTrue();
        if (status == SecretStatus.Success)
        {
            await Assert.That(report.Inventory.VisibleItems).IsEqualTo(0);
            await Assert.That(report.Inventory.StartedAt).IsEqualTo(ObservedAt);
            await Assert.That(report.Inventory.CompletedAt).IsEqualTo(ObservedAt.AddMinutes(1));
        }
    }

    [Test]
    public async Task CheckAgainAndRefreshReplaceAbsenceAndLaterDenialWithFreshEvidence()
    {
        var admin = new ControlledInventory { Visible = false };
        var intended = new ControlledReader { Status = SecretStatus.Absent };
        var scenario = new AssessmentScenario(admin, intended);
        FeatureRequirement[] requirements = Selection(intended, required: false);
        AssessmentReport absent = await scenario.CheckAsync(admin.Scope, requirements);

        admin.Visible = true;
        intended.Status = SecretStatus.Success;
        AssessmentReport available = await scenario.CheckAsync(admin.Scope, requirements);
        intended.Status = SecretStatus.Denied;
        AssessmentReport denied = await scenario.CheckAsync(admin.Scope, requirements);

        await Assert.That(absent.Inventory.VisibleItems).IsEqualTo(0);
        await Assert.That(absent.Features[0].CanEnable).IsFalse();
        await Assert.That(available.Inventory.VisibleItems).IsEqualTo(1);
        await Assert.That(available.Features[0].CanEnable).IsTrue();
        await Assert.That(denied.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Denied);
        await Assert.That(denied.Features[0].CanEnable).IsFalse();
        await Assert.That(absent.Features[0].Keys[0].State).IsEqualTo(AssessmentState.Absent);
    }

    [Test]
    public async Task CancellationDuringReadReturnsNoPartialReportAndDoesNotRetainMaterial()
    {
        var admin = new ControlledInventory();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        SecretMaterial? firstMaterial = null;
        var intended = new ControlledReader
        {
            Read = async (reference, token) =>
            {
                if (reference.Address is AzureSecretAddress { Name: "second" })
                {
                    entered.SetResult();
                    await release.Task.WaitAsync(token);
                }

                SecretOutcome<SecretRead> result = Success(reference);
                if (reference.Address is AzureSecretAddress { Name: "first" })
                {
                    firstMaterial = result.Value.Material;
                }

                return result;
            }
        };
        var scenario = new AssessmentScenario(admin, intended);
        FeatureRequirement[] requirements =
            [new("feature", true, [Key(intended, "first"), Key(intended, "second")])];
        using var cancellation = new CancellationTokenSource();
        Task<AssessmentReport> pending = scenario.CheckAsync(admin.Scope, requirements, cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();

        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(() => firstMaterial!.Reveal()).Throws<ObjectDisposedException>();
        intended.Read = null;
        AssessmentReport fresh = await scenario.CheckAsync(admin.Scope, requirements);
        await Assert.That(fresh.Features[0].Keys.Count).IsEqualTo(2);
        await Assert.That(fresh.CanProceed).IsTrue();
    }

    [Test]
    public async Task CancellationDuringInventoryPropagatesWithoutPublishingAssessment()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var admin = new ControlledInventory
        {
            Inspect = async token =>
            {
                entered.SetResult();
                await release.Task.WaitAsync(token);
                return SecretOutcome<SecretInventory>.Failure(SecretStatus.Unavailable);
            }
        };
        var intended = new ControlledReader();
        using var cancellation = new CancellationTokenSource();
        Task<AssessmentReport> pending = new AssessmentScenario(admin, intended)
            .CheckAsync(admin.Scope, Selection(intended), cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();

        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task PreCancelledCheckPropagatesCancellation()
    {
        var admin = new ControlledInventory();
        var intended = new ControlledReader();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.That(async () => await new AssessmentScenario(admin, intended)
            .CheckAsync(admin.Scope, Selection(intended), cancellation.Token)).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task CancellationAfterSuccessfulReadStillDisposesOwnedMaterial()
    {
        var admin = new ControlledInventory();
        using var cancellation = new CancellationTokenSource();
        SecretMaterial? material = null;
        var intended = new ControlledReader
        {
            Read = (reference, _) =>
            {
                SecretOutcome<SecretRead> outcome = Success(reference);
                material = outcome.Value.Material;
                cancellation.Cancel();
                return ValueTask.FromResult(outcome);
            }
        };

        await Assert.That(async () => await new AssessmentScenario(admin, intended)
            .CheckAsync(admin.Scope, Selection(intended), cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(() => material!.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task SerializationAndFormattingCannotExportMaterialOrConsumerCoordinates()
    {
        var admin = new ControlledInventory();
        string value = Guid.NewGuid().ToString("N");
        string coordinate = "coordinate-" + Guid.NewGuid().ToString("N");
        string version = Guid.NewGuid().ToString("N");
        string feature = "feature-" + Guid.NewGuid().ToString("N");
        string key = "key-" + Guid.NewGuid().ToString("N");
        SecretMaterial? material = null;
        var intended = new ControlledReader
        {
            Read = (reference, _) =>
            {
                material = SecretMaterial.FromText(value);
                return ValueTask.FromResult(SecretOutcome<SecretRead>.Success(new(material,
                    new(reference, version, ObservedAt, SecretValidity.Valid))));
            }
        };
        var requirement = new FeatureRequirement(feature, true,
            [new(key, new SecretReference(intended.Authority, new AzureSecretAddress(coordinate, version)),
                DeliveryKind.Direct)]);

        AssessmentReport report = await new AssessmentScenario(admin, intended).CheckAsync(admin.Scope, [requirement]);
        string output = JsonSerializer.Serialize(report) + report + report.Features[0] +
            report.Features[0].Keys[0] + JsonSerializer.Serialize(requirement) + requirement +
            JsonSerializer.Serialize(requirement.Keys[0]) + requirement.Keys[0];

        foreach (string canary in new[] { value, coordinate, version, feature, key })
        {
            await Assert.That(output.Contains(canary, StringComparison.Ordinal)).IsFalse();
        }

        await Assert.That(report.CanProceed).IsTrue();
        await Assert.That(() => material!.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task SameClientCannotServeAsAdminAndIntendedIdentity()
    {
        var combined = new CombinedIdentity();

        await Assert.That(() => new AssessmentScenario(combined, combined)).Throws<ArgumentException>();
    }

    private static FeatureRequirement[] Selection(ControlledReader reader, bool required = true) =>
        [new("feature", required, [Key(reader)])];

    private static KeyRequirement Key(ControlledReader reader, string name = "selected") =>
        new(name, new SecretReference(reader.Authority, new AzureSecretAddress(name)), DeliveryKind.Direct);

    private static SecretOutcome<SecretRead> Success(SecretReference reference,
        SecretValidity validity = SecretValidity.Valid) =>
        SecretOutcome<SecretRead>.Success(new(SecretMaterial.FromText(Guid.NewGuid().ToString("N")),
            new(reference, null, ObservedAt, validity)));

    private sealed class ControlledInventory : ISecretInventory
    {
        public SecretAuthority Authority { get; } = new();
        public AzureInventoryScope Scope => new(Authority);
        public SecretStatus Status { get; set; } = SecretStatus.Success;
        public bool Complete { get; set; } = true;
        public bool Visible { get; set; } = true;
        public Func<CancellationToken, ValueTask<SecretOutcome<SecretInventory>>>? Inspect { get; init; }

        public ValueTask<SecretOutcome<SecretInventory>> InspectAsync(SecretInventoryScope scope,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!scope.BelongsTo(Authority))
            {
                return ValueTask.FromResult(SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid));
            }

            if (Inspect is not null)
            {
                return Inspect(cancellationToken);
            }

            SecretObservation[] items = Visible
                ? [new(new(Authority, new AzureSecretAddress("selected")), null, ObservedAt, SecretValidity.Unknown)]
                : [];
            return ValueTask.FromResult(Status == SecretStatus.Success
                ? SecretOutcome<SecretInventory>.Success(new(items, ObservedAt, ObservedAt.AddMinutes(1), Complete))
                : SecretOutcome<SecretInventory>.Failure(Status));
        }
    }

    private sealed class ControlledReader : ISecretReader
    {
        public SecretAuthority Authority { get; } = new();
        public SecretStatus Status { get; set; } = SecretStatus.Success;
        public SecretValidity Validity { get; init; } = SecretValidity.Valid;
        public Func<SecretReference, CancellationToken, ValueTask<SecretOutcome<SecretRead>>>? Read { get; set; }
        public SecretMaterial? LastMaterial { get; private set; }

        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!reference.BelongsTo(Authority))
            {
                return ValueTask.FromResult(SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid));
            }

            if (Read is not null)
            {
                return Read(reference, cancellationToken);
            }

            if (Status != SecretStatus.Success)
            {
                return ValueTask.FromResult(SecretOutcome<SecretRead>.Failure(Status));
            }

            SecretOutcome<SecretRead> outcome = Success(reference, Validity);
            LastMaterial = outcome.Value.Material;
            return ValueTask.FromResult(outcome);
        }
    }

    private sealed class CombinedIdentity : ISecretInventory, ISecretReader
    {
        public SecretAuthority Authority { get; } = new();

        public ValueTask<SecretOutcome<SecretInventory>> InspectAsync(SecretInventoryScope scope,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(SecretOutcome<SecretInventory>.Failure(SecretStatus.Denied));

        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(SecretOutcome<SecretRead>.Failure(SecretStatus.Denied));
    }
}
