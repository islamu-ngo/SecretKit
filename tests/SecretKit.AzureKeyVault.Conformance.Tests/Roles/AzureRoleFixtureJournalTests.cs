using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureRoleFixtureJournalTests
{
    private const string Owned = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/owned/providers/Microsoft.KeyVault/vaults/fixture";
    private const string Borrowed = "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/22222222-2222-2222-2222-222222222222";
    private static FixtureSelector Selector() => new(Guid.NewGuid(), "scope", "operation", "variant", "case");

    [Test]
    public async Task OriginalRecoverJournalCopiesRestorationPairAndRejectsGenericAdmission()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector() with
        {
            Operation = "a.management.VaultAdministration.RecoverVaultAsync",
            Variant = "accessPolicies.selected", Case = "selected-contract"
        };
        SecretPermission[] permissions = [SecretPermission.Get];
        Guid tenant = Guid.NewGuid();
        var configuration = new VaultAdministrationEffects.Configuration("eastus", tenant,
            VaultSku.Standard, false, true, 23, false, [new(tenant, Guid.NewGuid(), permissions, null)]);
        RoleFixtureJournal.Resource[] resources =
        [
            new(Owned, false),
            new(Owned + "/secrets/canary", false, CleanupOnly: true),
            new("/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/fixture",
                false)
        ];
        var prepared = fixture.Journal.Prepare("owner", selector, resources,
            recoverVaultBaseline: configuration, recoverVaultSelected: configuration);
        permissions[0] = SecretPermission.Purge;
        var observed = fixture.Journal.Read("owner", selector).RecoverVault!;
        await Assert.That(observed.Baseline.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        await Assert.That(observed.Selected.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        observed.Baseline.Policies[0].Permissions[0] = SecretPermission.Set;
        observed.Selected.Policies[0].Permissions[0] = SecretPermission.Delete;
        var reread = fixture.Journal.Read("owner", selector).RecoverVault!;
        await Assert.That(reread.Baseline.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        await Assert.That(reread.Selected.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        await Assert.That(() => fixture.Journal.BeginSelectedDispatch("owner", selector, Owned, false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.BeginSelectedRead("owner", selector, prepared.LeaseId, Owned))
            .Throws<InvalidOperationException>();
        await Assert.That(fixture.Journal.Read("owner", selector).Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    public async Task OriginalCreateJournalOwnsBothConfigurationsAndRejectsGenericAdmission()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector() with
        {
            Operation = "a.management.VaultAdministration.CreateOrUpdateVaultAsync",
            Variant = "publicNetworkAccess.true",
            Case = "selected-contract"
        };
        SecretPermission[] permissions = [SecretPermission.Get];
        Guid tenant = Guid.NewGuid();
        var baseline = new VaultAdministrationEffects.Configuration("eastus", tenant,
            VaultSku.Standard, false, false, 23, false,
            [new(tenant, Guid.NewGuid(), permissions, null)]);
        var selected = baseline with { PublicNetworkAccess = true };
        RoleFixtureJournal.Resource[] resources =
        [
            new(Owned, false),
            new(Owned + "/secrets/canary", false, CleanupOnly: true),
            new("/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/fixture",
                false, CleanupOnly: true)
        ];
        var prepared = fixture.Journal.Prepare("owner", selector, resources,
            createOrUpdateVaultBaseline: baseline, createOrUpdateVaultSelected: selected);
        permissions[0] = SecretPermission.Purge;
        var observed = fixture.Journal.Read("owner", selector).CreateOrUpdateVault!;
        await Assert.That(observed.Baseline.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        await Assert.That(observed.Selected.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        observed.Baseline.Policies[0].Permissions[0] = SecretPermission.Set;
        observed.Selected.Policies[0].Permissions[0] = SecretPermission.Delete;
        var reread = fixture.Journal.Read("owner", selector).CreateOrUpdateVault!;
        await Assert.That(reread.Baseline.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        await Assert.That(reread.Selected.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        await Assert.That(() => fixture.Journal.BeginSelectedUpdate("owner", selector, Owned)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.BeginSelectedDispatch("owner", selector, Owned, false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.BeginSelectedRead("owner", selector, prepared.LeaseId, Owned))
            .Throws<InvalidOperationException>();
        var after = fixture.Journal.Read("owner", selector);
        await Assert.That(after.LeaseId).IsEqualTo(prepared.LeaseId);
        await Assert.That(after.CreateOrUpdateVault!.InvocationDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(after.Resources.Any(row => row.SelectedAttempted)).IsFalse();
    }

    [Test]
    public async Task OriginalPurgeJournalOwnsItsBaselineAndRejectsGenericSelectedAdmission()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector() with
        {
            Operation = "a.management.VaultAdministration.PurgeDeletedVaultAsync",
            Variant = "input.scope",
            Case = "selected-contract"
        };
        SecretPermission[] permissions = [SecretPermission.Get];
        Guid tenant = Guid.NewGuid();
        var baseline = new VaultAdministrationEffects.Configuration("eastus", tenant,
            VaultSku.Premium, false, false, 23, false,
            [new(tenant, Guid.NewGuid(), permissions, null)]);
        RoleFixtureJournal.Resource[] resources =
        [
            new(Owned, false),
            new(Owned + "/secrets/canary", false, CleanupOnly: true),
            new("/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/fixture",
                false)
        ];
        var prepared = fixture.Journal.Prepare("owner", selector, resources, purgeDeletedVaultBaseline: baseline);
        permissions[0] = SecretPermission.Purge;
        var observed = fixture.Journal.Read("owner", selector);
        await Assert.That(observed.PurgeDeletedVault!.Baseline.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        observed.PurgeDeletedVault.Baseline.Policies[0].Permissions[0] = SecretPermission.Set;
        await Assert.That(fixture.Journal.Read("owner", selector).PurgeDeletedVault!.Baseline.Policies[0].Permissions.Single())
            .IsEqualTo(SecretPermission.Get);
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        await Assert.That(() => fixture.Journal.BeginSelectedUpdate("owner", selector, Owned)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.BeginSelectedDispatch("owner", selector, resources[2].Id, false))
            .Throws<InvalidOperationException>();
        var after = fixture.Journal.Read("owner", selector);
        await Assert.That(after.LeaseId).IsEqualTo(prepared.LeaseId);
        await Assert.That(after.PurgeDeletedVault!.InvocationDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(after.Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    public async Task OriginalDeleteJournalOwnsItsBaselineAndRejectsGenericSelectedAdmission()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector() with
        {
            Operation = "a.management.VaultAdministration.DeleteVaultAsync",
            Variant = "input.scope",
            Case = "selected-contract"
        };
        SecretPermission[] permissions = [SecretPermission.Get];
        Guid tenant = Guid.NewGuid();
        var baseline = new VaultAdministrationEffects.Configuration("eastus", tenant,
            VaultSku.Premium, false, false, 23, false,
            [new(tenant, Guid.NewGuid(), permissions, null)]);
        RoleFixtureJournal.Resource[] resources =
        [
            new(Owned, false),
            new(Owned + "/secrets/canary", false, CleanupOnly: true),
            new("/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/fixture",
                false, CleanupOnly: true)
        ];
        var prepared = fixture.Journal.Prepare("owner", selector, resources, deleteVaultBaseline: baseline);
        permissions[0] = SecretPermission.Purge;
        var observed = fixture.Journal.Read("owner", selector);
        await Assert.That(observed.DeleteVault!.Baseline.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        observed.DeleteVault.Baseline.Policies[0].Permissions[0] = SecretPermission.Set;
        await Assert.That(fixture.Journal.Read("owner", selector).DeleteVault!.Baseline.Policies[0].Permissions.Single())
            .IsEqualTo(SecretPermission.Get);
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        await Assert.That(() => fixture.Journal.BeginSelectedUpdate("owner", selector, Owned)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.BeginSelectedDispatch("owner", selector, Owned, false))
            .Throws<InvalidOperationException>();
        var after = fixture.Journal.Read("owner", selector);
        await Assert.That(after.LeaseId).IsEqualTo(prepared.LeaseId);
        await Assert.That(after.DeleteVault!.InvocationDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(after.Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    public async Task SettingsJournalPreservesIndependentConfigurationSnapshotAndRejectsGenericSelectedAdmission()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector() with
        {
            Operation = "a.management.VaultAdministration.UpdateSettingsAsync",
            Variant = "rbac.true",
            Case = "selected-contract"
        };
        SecretPermission[] permissions = [SecretPermission.Get];
        Guid tenant = Guid.NewGuid();
        var baseline = new VaultAdministrationEffects.Configuration("eastus", tenant,
            VaultSku.Premium, false, false, 23, false,
            [new(tenant, Guid.NewGuid(), permissions, null)]);
        RoleFixtureJournal.Resource[] resources =
        [
            new(Owned, false),
            new(Owned + "/secrets/canary", false, CleanupOnly: true),
            new("/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/fixture",
                false, CleanupOnly: true)
        ];
        var prepared = fixture.Journal.Prepare("owner", selector, resources, settingsBaseline: baseline);
        permissions[0] = SecretPermission.Purge;
        var observed = fixture.Journal.Read("owner", selector);
        await Assert.That(observed.Settings!.Baseline.Policies[0].Permissions.Single()).IsEqualTo(SecretPermission.Get);
        observed.Settings.Baseline.Policies[0].Permissions[0] = SecretPermission.Set;
        await Assert.That(fixture.Journal.Read("owner", selector).Settings!.Baseline.Policies[0].Permissions.Single())
            .IsEqualTo(SecretPermission.Get);
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        await Assert.That(() => fixture.Journal.BeginSelectedUpdate("owner", selector, Owned)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.BeginSelectedDispatch("owner", selector, Owned, false))
            .Throws<InvalidOperationException>();
        var after = fixture.Journal.Read("owner", selector);
        await Assert.That(after.LeaseId).IsEqualTo(prepared.LeaseId);
        await Assert.That(after.Settings!.InvocationDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(after.Resources.Any(r => r.SelectedAttempted)).IsFalse();
    }

    [Test]
    [Arguments(24, true)]
    [Arguments(25, false)]
    public async Task JournalResourceCapacityAcceptsTwentyFourAndRejectsTwentyFive(int count, bool accepted)
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        RoleFixtureJournal.Resource[] resources = Enumerable.Range(0, count)
            .Select(i => new RoleFixtureJournal.Resource(Owned + "/secrets/resource-" + i, i % 2 == 0)).ToArray();
        if (!accepted)
        {
            await Assert.That(() => fixture.Journal.Prepare("owner", selector, resources))
                .Throws<InvalidOperationException>();
            await Assert.That(Directory.GetFiles(fixture.Path).Length).IsEqualTo(0);
            return;
        }
        Guid lease = fixture.Journal.Prepare("owner", selector, resources).LeaseId;
        var reopened = new RoleFixtureJournal(fixture.Path).Read("owner", selector);
        await Assert.That(reopened.Resources.SequenceEqual(resources)).IsTrue();
        await Assert.That(reopened.LeaseId).IsEqualTo(lease);
    }

    [Test]
    [Arguments(65536, true)]
    [Arguments(65537, false)]
    public async Task PreparePreflightsEscapedMaximumFrameRatherThanOnlyInitialFrame(int maximumBytes, bool accepted)
    {
        using var fixture = new DirectoryFixture();
        string owner = new('\u0001', 128);
        var selector = EscapedSelector();
        var maximum = FrameSizedSnapshot(owner, selector, maximumBytes);
        var initial = maximum with
        {
            Resources = maximum.Resources.Select(r => r with { ActiveDispatch = Guid.Empty }).ToArray()
        };
        await Assert.That(FrameBytes(1, initial).Length < 64 * 1024).IsTrue();
        await Assert.That(FrameBytes(long.MaxValue, maximum).Length).IsEqualTo(maximumBytes);
        await Assert.That(maximum.Resources.Any(r => r.Id.Length == 2048)).IsTrue();
        if (!accepted)
        {
            await Assert.That(() => fixture.Journal.Prepare(owner, selector, initial.Resources))
                .Throws<InvalidOperationException>();
            string path = JournalPath(fixture, selector);
            await Assert.That(new FileInfo(path).Length).IsEqualTo(0L);
            await Assert.That(() => fixture.Journal.BeginDispatch(owner, selector, initial.Resources[0].Id, false))
                .Throws<InvalidOperationException>();
            await Assert.That(new FileInfo(path).Length).IsEqualTo(0L);
            return;
        }
        fixture.Journal.Prepare(owner, selector, initial.Resources);
        Guid dispatch = fixture.Journal.BeginDispatch(owner, selector, initial.Resources[0].Id, false);
        var actual = new RoleFixtureJournal(fixture.Path).Read(owner, selector);
        await Assert.That(actual.Resources[0].ActiveDispatch).IsEqualTo(dispatch);
        await Assert.That(FrameBytes(long.MaxValue, actual).Length <= maximumBytes).IsTrue();
    }

    [Test]
    public async Task MaximumFramePlanCompletesTwoHundredFortyTwoSnapshotLifecycleBeyondOneMiB()
    {
        using var fixture = new DirectoryFixture();
        string owner = new('\u0001', 128);
        var selector = EscapedSelector();
        var maximum = FrameSizedSnapshot(owner, selector, 64 * 1024);
        RoleFixtureJournal.Resource[] resources = maximum.Resources
            .Select(r => r with { ActiveDispatch = Guid.Empty }).ToArray();
        Guid lease = fixture.Journal.Prepare(owner, selector, resources).LeaseId;
        foreach (var resource in resources)
        {
            Guid setup = fixture.Journal.BeginDispatch(owner, selector, resource.Id, false);
            fixture.Journal.EndDispatch(owner, selector, resource.Id, setup);
        }
        foreach (var resource in resources)
        {
            Guid selected = fixture.Journal.BeginSelectedUpdate(owner, selector, resource.Id);
            fixture.Journal.EndDispatch(owner, selector, resource.Id, selected, nativeSettled: false);
            fixture.Journal.AdmitStatusRead(owner, selector, lease, resource.Id, selected);
            fixture.Journal.EndDispatch(owner, selector, resource.Id, selected, nativeSettled: false);
            fixture.Journal.SettleDispatch(owner, selector, resource.Id, selected);
        }
        fixture.Journal.Close(owner, selector);
        foreach (var resource in resources)
        {
            Guid cleanup = fixture.Journal.BeginDispatch(owner, selector, resource.Id, true);
            fixture.Journal.EndDispatch(owner, selector, resource.Id, cleanup);
        }
        foreach (var resource in resources)
            fixture.Journal.RecordAbsence(owner, selector, resource.Id);
        var reopened = new RoleFixtureJournal(fixture.Path).Read(owner, selector);
        await Assert.That(reopened.Released && reopened.LeaseId == lease).IsTrue();
        byte[] history = File.ReadAllBytes(JournalPath(fixture, selector));
        await Assert.That(history.Length > 1024 * 1024 && history.Length <= 16 * 1024 * 1024).IsTrue();
        int position = 0;
        long sequence = 0;
        string previous = new('0', 64);
        while (position < history.Length)
        {
            int length = BinaryPrimitives.ReadInt32LittleEndian(history.AsSpan(position, 4));
            await Assert.That(length is > 0 and <= 64 * 1024).IsTrue();
            byte[] payload = history.AsSpan(position + 4, length).ToArray();
            byte[] digest = history.AsSpan(position + 4 + length, 32).ToArray();
            await Assert.That(SHA256.HashData(payload).SequenceEqual(digest)).IsTrue();
            using JsonDocument frame = JsonDocument.Parse(payload);
            await Assert.That(frame.RootElement.GetProperty("sequence").GetInt64()).IsEqualTo(++sequence);
            await Assert.That(frame.RootElement.GetProperty("previous").GetString()).IsEqualTo(previous);
            var snapshot = frame.RootElement.GetProperty("state")
                .Deserialize<RoleFixtureJournal.Snapshot>(ManagementAdmission.Json)!;
            await Assert.That(snapshot.Owner == owner && snapshot.Selector == selector && snapshot.LeaseId == lease).IsTrue();
            await Assert.That(FrameBytes(long.MaxValue, snapshot).Length <= FrameBytes(long.MaxValue, maximum).Length).IsTrue();
            previous = Convert.ToHexString(digest);
            position += length + 36;
        }
        await Assert.That(sequence).IsEqualTo(242L);
        await Assert.That(position).IsEqualTo(history.Length);
    }

    [Test]
    public async Task CumulativeExhaustionRejectsAppendWithoutChangingAnyHistoryOrOwnership()
    {
        using var fixture = new DirectoryFixture();
        string owner = new('\u0001', 128);
        var selector = EscapedSelector();
        var maximum = FrameSizedSnapshot(owner, selector, 64 * 1024);
        var state = fixture.Journal.Prepare(owner, selector,
            maximum.Resources.Select(r => r with { ActiveDispatch = Guid.Empty }).ToArray());
        state = fixture.Journal.Close(owner, selector);
        string path = JournalPath(fixture, selector);
        for (long sequence = 3; sequence <= 300; sequence++)
        {
            var next = state with
            {
                Resources = state.Resources.Select((r, i) => i == 0 ? r with { Absent = !r.Absent } : r).ToArray()
            };
            if (new FileInfo(path).Length + FrameBytes(sequence, next).Length + 36 > 16 * 1024 * 1024)
            {
                byte[] history = File.ReadAllBytes(path);
                await Assert.That(() =>
                {
                    if (state.Resources[0].Absent) fixture.Journal.RecordPresence(owner, selector, state.Resources[0].Id);
                    else fixture.Journal.RecordAbsence(owner, selector, state.Resources[0].Id);
                }).Throws<InvalidOperationException>();
                await Assert.That(File.ReadAllBytes(path).SequenceEqual(history)).IsTrue();
                var reopened = new RoleFixtureJournal(fixture.Path).Read(owner, selector);
                await Assert.That(reopened.Owner == owner && reopened.Selector == selector &&
                    reopened.LeaseId == state.LeaseId && reopened.Closing && !reopened.Released).IsTrue();
                await Assert.That(reopened.Resources.SequenceEqual(state.Resources)).IsTrue();
                await Assert.That(history.Length > 1024 * 1024 && history.Length <= 16 * 1024 * 1024).IsTrue();
                await Assert.That(() => fixture.Journal.Prepare(owner, selector, [new(Owned, false)]))
                    .Throws<InvalidOperationException>();
                await Assert.That(File.ReadAllBytes(path).SequenceEqual(history)).IsTrue();
                return;
            }
            state = state.Resources[0].Absent
                ? fixture.Journal.RecordPresence(owner, selector, state.Resources[0].Id)
                : fixture.Journal.RecordAbsence(owner, selector, state.Resources[0].Id);
        }
        throw new InvalidOperationException("journal-budget-was-not-enforced");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SelectedNativeMutationIsOwnedBeforeDispatchAndCannotEscapeClosing(bool delete)
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false)]);
        if (delete)
        {
            Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
            fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        }
        Guid selected = fixture.Journal.BeginSelectedDispatch("owner", selector, Owned, delete);
        var active = new RoleFixtureJournal(fixture.Path).Read("owner", selector);
        await Assert.That(active.Resources[0].CreateAttempted && active.Resources[0].SelectedAttempted).IsTrue();
        fixture.Journal.Close("owner", selector);
        await Assert.That(() => fixture.Journal.BeginSelectedDispatch("owner", selector, Owned, delete))
            .Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.RecordAbsence("owner", selector, Owned)).Throws<InvalidOperationException>();
        fixture.Journal.EndDispatch("owner", selector, Owned, selected);
        Guid cleanup = fixture.Journal.BeginDispatch("owner", selector, Owned, true);
        fixture.Journal.EndDispatch("owner", selector, Owned, cleanup);
        await Assert.That(fixture.Journal.RecordAbsence("owner", selector, Owned).Released).IsTrue();
    }

    [Test]
    public async Task SelectedUpdateRequiresPreparedOwnedResourceAndFencesCleanup()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false), new(Borrowed, true)]);
        await Assert.That(() => fixture.Journal.BeginSelectedUpdate("owner", selector, Owned))
            .Throws<InvalidOperationException>();
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        await Assert.That(() => fixture.Journal.BeginSelectedUpdate("owner", selector, Borrowed))
            .Throws<InvalidOperationException>();
        Guid update = fixture.Journal.BeginSelectedUpdate("owner", selector, Owned);
        var reopened = new RoleFixtureJournal(fixture.Path);
        await Assert.That(reopened.Read("owner", selector).Resources[0].ActiveDispatch).IsEqualTo(update);
        await Assert.That(() => reopened.BeginSelectedUpdate("owner", selector, Owned)).Throws<InvalidOperationException>();
        reopened.Close("owner", selector);
        await Assert.That(() => reopened.RecordAbsence("owner", selector, Owned)).Throws<InvalidOperationException>();
        await Assert.That(() => reopened.BeginDispatch("owner", selector, Owned, true)).Throws<InvalidOperationException>();
        reopened.EndDispatch("owner", selector, Owned, update, nativeSettled: false);
        await Assert.That(reopened.Read("owner", selector).Released).IsFalse();
        reopened.SettleDispatch("owner", selector, Owned, update);
        await Assert.That(() => reopened.BeginSelectedUpdate("owner", selector, Owned)).Throws<InvalidOperationException>();
        Guid cleanup = reopened.BeginDispatch("owner", selector, Owned, true);
        reopened.EndDispatch("owner", selector, Owned, cleanup);
        await Assert.That(reopened.RecordAbsence("owner", selector, Owned).Released).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SetupCannotAdmitFromIdleSnapshotAfterAnotherDispatchStarts(bool selected)
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        string secret = Owned + "/secrets/canary";
        string otherResource = Owned + "/secrets/other";
        fixture.Journal.Prepare("owner", selector, [new(Owned, false), new(secret, false), new(otherResource, false)]);
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        var idle = fixture.Journal.Read("owner", selector);
        await Assert.That(idle.Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        var other = new RoleFixtureJournal(fixture.Path);
        Guid active = selected
            ? other.BeginSelectedUpdate("owner", selector, Owned)
            : other.BeginDispatch("owner", selector, otherResource, false);
        await Assert.That(() => fixture.Journal.BeginDispatch("owner", selector, secret, false))
            .Throws<InvalidOperationException>();
        await Assert.That(other.Read("owner", selector).Resources.Count(r => r.ActiveDispatch != Guid.Empty)).IsEqualTo(1);
        await Assert.That(other.Read("owner", selector).Resources.Single(r => r.ActiveDispatch != Guid.Empty).ActiveDispatch)
            .IsEqualTo(active);
    }

    [Test]
    public async Task LocalTerminationCannotEraseUnsettledNativeWork()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false)]);
        Guid dispatch = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        await Assert.That(() => fixture.Journal.SettleDispatch("owner", selector, Owned, dispatch))
            .Throws<InvalidOperationException>();
        fixture.Journal.EndDispatch("owner", selector, Owned, dispatch, nativeSettled: false);
        var reopened = new RoleFixtureJournal(fixture.Path);
        reopened.Close("owner", selector);
        await Assert.That(() => reopened.RecordAbsence("owner", selector, Owned)).Throws<InvalidOperationException>();
        await Assert.That(reopened.Read("owner", selector).Released).IsFalse();
        reopened.SettleDispatch("owner", selector, Owned, dispatch);
        await Assert.That(reopened.RecordAbsence("owner", selector, Owned).Released).IsTrue();
    }

    [Test]
    public async Task LostPrepareReplyRetainsNonceCleanupAuthority()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false), new(Borrowed, true)]);
        Guid dispatch = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        var reopened = new RoleFixtureJournal(fixture.Path);
        await Assert.That(reopened.Close("owner", selector).Released).IsFalse();
        reopened.EndDispatch("owner", selector, Owned, dispatch);
        Guid deletion = reopened.BeginDispatch("owner", selector, Owned, true);
        reopened.EndDispatch("owner", selector, Owned, deletion);
        await Assert.That(reopened.Read("owner", selector).Released).IsFalse();
        var measured = reopened.RecordAbsence("owner", selector, Owned);
        await Assert.That(measured.Released).IsTrue();
        await Assert.That(measured.Resources.Single(r => r.Borrowed).Id).IsEqualTo(Borrowed);
    }

    [Test]
    public async Task ReleaseBeforePrepareLeavesDurableTombstone()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        await Assert.That(fixture.Journal.Close("owner", selector).Released).IsTrue();
        var reopened = new RoleFixtureJournal(fixture.Path);
        await Assert.That(() => reopened.Prepare("owner", selector, [new(Owned, false)]))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RepeatedAbsenceDoesNotGrowHistoryWhileAnotherResourceRemains()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        string other = Owned + "/secrets/canary";
        fixture.Journal.Prepare("owner", selector, [new(Owned, false), new(other, false)]);
        fixture.Journal.Close("owner", selector);
        fixture.Journal.RecordAbsence("owner", selector, Owned);
        string path = System.IO.Path.Combine(fixture.Path, selector.Nonce.ToString("N") + ".journal");
        long length = new FileInfo(path).Length;
        for (int i = 0; i < 20; i++) fixture.Journal.RecordAbsence("owner", selector, Owned);
        await Assert.That(new FileInfo(path).Length).IsEqualTo(length);
        await Assert.That(fixture.Journal.RecordAbsence("owner", selector, other).Released).IsTrue();
    }

    [Test]
    public async Task RepeatedCloseDoesNotGrowOrChangeTombstone()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        var first = fixture.Journal.Close("owner", selector);
        string path = System.IO.Path.Combine(fixture.Path, selector.Nonce.ToString("N") + ".journal");
        long length = new FileInfo(path).Length;
        var second = new RoleFixtureJournal(fixture.Path).Close("owner", selector);
        await Assert.That(second.Released && second.Selector == first.Selector).IsTrue();
        await Assert.That(new FileInfo(path).Length).IsEqualTo(length);
    }

    [Test]
    public async Task CrossResourceDispatchInvalidatesEarlierAbsenceAndRequiresGlobalDrain()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        string deleted = Owned + "/deleted-marker";
        fixture.Journal.Prepare("owner", selector, [new(Owned, false), new(deleted, false, CleanupOnly: true)]);
        Guid create = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, create);
        fixture.Journal.Close("owner", selector);
        fixture.Journal.RecordAbsence("owner", selector, deleted);
        Guid deletion = fixture.Journal.BeginDispatch("owner", selector, Owned, true);
        await Assert.That(fixture.Journal.Read("owner", selector).Resources.Single(r => r.Id == deleted).Absent).IsFalse();
        await Assert.That(() => fixture.Journal.RecordAbsence("owner", selector, deleted)).Throws<InvalidOperationException>();
        fixture.Journal.EndDispatch("owner", selector, Owned, deletion);
        await Assert.That(fixture.Journal.RecordAbsence("owner", selector, Owned).Released).IsFalse();
        Guid purge = fixture.Journal.BeginDispatch("owner", selector, deleted, true);
        fixture.Journal.EndDispatch("owner", selector, deleted, purge);
        await Assert.That(fixture.Journal.RecordAbsence("owner", selector, deleted).Released).IsFalse();
        await Assert.That(fixture.Journal.RecordAbsence("owner", selector, Owned).Released).IsTrue();
        await Assert.That(() => fixture.Journal.BeginDispatch("owner", selector, deleted, true)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task WrongOwnerOrSelectorCannotClose(bool wrongOwner)
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false)]);
        await Assert.That(() => fixture.Journal.Close(wrongOwner ? "other" : "owner",
            wrongOwner ? selector : selector with { Case = "substituted" })).Throws<InvalidOperationException>();
        await Assert.That(fixture.Journal.Read("owner", selector).Closing).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BorrowedResourceCannotDispatchOrBeMarkedAbsent(bool absence)
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false), new(Borrowed, true)]);
        if (absence) fixture.Journal.Close("owner", selector);
        await Assert.That(() =>
        {
            if (absence) fixture.Journal.RecordAbsence("owner", selector, Borrowed);
            else fixture.Journal.BeginDispatch("owner", selector, Borrowed, false);
        }).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ActiveDispatchSurvivesRestartAndCannotBeErasedByAbsence()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false)]);
        Guid dispatch = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        var reopened = new RoleFixtureJournal(fixture.Path);
        reopened.Close("owner", selector);
        await Assert.That(() => reopened.RecordAbsence("owner", selector, Owned)).Throws<InvalidOperationException>();
        await Assert.That(() => reopened.EndDispatch("owner", selector, Owned, Guid.NewGuid()))
            .Throws<InvalidOperationException>();
        await Assert.That(reopened.Read("owner", selector).Resources[0].ActiveDispatch).IsEqualTo(dispatch);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CompletedDispatchCannotBeReplayed(bool delete)
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false)]);
        Guid create = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, create);
        if (delete)
        {
            fixture.Journal.Close("owner", selector);
            Guid remove = fixture.Journal.BeginDispatch("owner", selector, Owned, true);
            fixture.Journal.EndDispatch("owner", selector, Owned, remove);
        }
        await Assert.That(() => fixture.Journal.BeginDispatch("owner", selector, Owned, delete))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ClosingPreventsNewDispatchOnPartiallyProvisionedPlan()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false)]);
        fixture.Journal.Close("owner", selector);
        await Assert.That(() => fixture.Journal.BeginDispatch("owner", selector, Owned, false))
            .Throws<InvalidOperationException>();
        await Assert.That(fixture.Journal.RecordAbsence("owner", selector, Owned).Released).IsTrue();
    }

    [Test]
    public async Task DuplicatePrepareCannotReplayProvisioning()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        Guid lease = fixture.Journal.Prepare("owner", selector, [new(Owned, false)]).LeaseId;
        await Assert.That(() => fixture.Journal.Prepare("owner", selector, [new(Owned, false)]))
            .Throws<InvalidOperationException>();
        await Assert.That(fixture.Journal.Read("owner", selector).LeaseId).IsEqualTo(lease);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TornOrCorruptedHistoryNeverAcknowledgesCleanup(bool torn)
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false)]);
        string path = System.IO.Path.Combine(fixture.Path, selector.Nonce.ToString("N") + ".journal");
        using (var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            if (torn) file.SetLength(file.Length - 1);
            else
            {
                file.Position = file.Length - 1;
                int value = file.ReadByte();
                file.Position--;
                file.WriteByte((byte)(value ^ 1));
            }
            file.Flush(true);
        }
        long length = new FileInfo(path).Length;
        await Assert.That(() => fixture.Journal.Close("owner", selector)).Throws<InvalidOperationException>();
        await Assert.That(new FileInfo(path).Length).IsEqualTo(length);
    }

    [Test]
    public async Task ConcurrentWriterFailsClosedWithoutChangingHistory()
    {
        using var fixture = new DirectoryFixture();
        FixtureSelector selector = Selector();
        fixture.Journal.Prepare("owner", selector, [new(Owned, false)]);
        string path = System.IO.Path.Combine(fixture.Path, selector.Nonce.ToString("N") + ".journal");
        using (var held = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            await Assert.That(() => fixture.Journal.Close("owner", selector)).Throws<InvalidOperationException>();
        await Assert.That(fixture.Journal.Read("owner", selector).Closing).IsFalse();
    }

    [Test]
    public async Task ReadAdmissionIsReusableWithoutConsumingMutationHistoryAndStillFencesClose()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        Guid lease = fixture.Journal.Prepare("owner", selector, [new(Owned, false)]).LeaseId;
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        for (int i = 0; i < 3; i++)
        {
            Guid read = fixture.Journal.BeginSelectedRead("owner", selector, lease, Owned);
            var active = new RoleFixtureJournal(fixture.Path).Read("owner", selector).Resources.Single();
            await Assert.That(active.ActiveDispatch).IsEqualTo(read);
            await Assert.That(active.SelectedAttempted || active.InvocationTerminated).IsFalse();
            await Assert.That(() => fixture.Journal.BeginSelectedUpdate("owner", selector, Owned)).Throws<InvalidOperationException>();
            fixture.Journal.EndDispatch("owner", selector, Owned, read);
        }
        Guid last = fixture.Journal.BeginSelectedRead("owner", selector, lease, Owned);
        fixture.Journal.Close("owner", selector);
        await Assert.That(() => fixture.Journal.BeginSelectedRead("owner", selector, lease, Owned)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.RecordAbsence("owner", selector, Owned)).Throws<InvalidOperationException>();
        fixture.Journal.EndDispatch("owner", selector, Owned, last);
        await Assert.That(fixture.Journal.RecordAbsence("owner", selector, Owned).Released).IsTrue();
    }

    [Test]
    [Arguments("lease")]
    [Arguments("borrowed")]
    [Arguments("unprepared")]
    [Arguments("selected")]
    [Arguments("active")]
    [Arguments("uncertain")]
    [Arguments("closed")]
    public async Task ReadAdmissionCannotEscapePreparedOwnershipOrDurableFences(string fault)
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        Guid lease = fixture.Journal.Prepare("owner", selector, [new(Owned, fault == "borrowed")]).LeaseId;
        if (fault is not ("borrowed" or "unprepared"))
        {
            Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
            fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        }
        if (fault is "selected" or "active" or "uncertain")
        {
            Guid dispatch = fixture.Journal.BeginSelectedUpdate("owner", selector, Owned);
            if (fault != "active")
                fixture.Journal.EndDispatch("owner", selector, Owned, dispatch, nativeSettled: fault != "uncertain");
        }
        if (fault == "closed") fixture.Journal.Close("owner", selector);
        var before = fixture.Journal.Read("owner", selector);
        await Assert.That(() => fixture.Journal.BeginSelectedRead("owner", selector,
            fault == "lease" ? Guid.NewGuid() : lease, Owned)).Throws<InvalidOperationException>();
        var after = fixture.Journal.Read("owner", selector);
        await Assert.That(after.Resources.Single()).IsEqualTo(before.Resources.Single());
        await Assert.That(after.Closing).IsEqualTo(before.Closing);
    }

    [Test]
    public async Task ExactRetainedStatusAdmissionOwnsItsBorrowerUntilDrainEvenWhenCloseWinsLater()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        Guid lease = fixture.Journal.Prepare("owner", selector, [new(Owned, false)]).LeaseId;
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        Guid mutation = fixture.Journal.BeginSelectedUpdate("owner", selector, Owned);
        fixture.Journal.EndDispatch("owner", selector, Owned, mutation, nativeSettled: false);
        fixture.Journal.AdmitStatusRead("owner", selector, lease, Owned, mutation);
        var active = new RoleFixtureJournal(fixture.Path).Read("owner", selector).Resources.Single();
        await Assert.That(active.ActiveDispatch).IsEqualTo(mutation);
        await Assert.That(active.InvocationTerminated).IsFalse();
        await Assert.That(() => fixture.Journal.AdmitStatusRead("owner", selector, lease, Owned, mutation)).Throws<InvalidOperationException>();
        fixture.Journal.Close("owner", selector);
        await Assert.That(() => fixture.Journal.SettleDispatch("owner", selector, Owned, mutation)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Journal.RecordAbsence("owner", selector, Owned)).Throws<InvalidOperationException>();
        fixture.Journal.EndDispatch("owner", selector, Owned, mutation, nativeSettled: false);
        await Assert.That(() => fixture.Journal.AdmitStatusRead("owner", selector, lease, Owned, mutation)).Throws<InvalidOperationException>();
        await Assert.That(fixture.Journal.Read("owner", selector).Released).IsFalse();
    }

    [Test]
    [Arguments("lease")]
    [Arguments("dispatch")]
    [Arguments("running")]
    [Arguments("closed")]
    public async Task StatusAdmissionNeverAuthorizesAnotherOrAlreadyClosedInvocation(string fault)
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        Guid lease = fixture.Journal.Prepare("owner", selector, [new(Owned, false)]).LeaseId;
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        Guid mutation = fixture.Journal.BeginSelectedUpdate("owner", selector, Owned);
        if (fault != "running")
            fixture.Journal.EndDispatch("owner", selector, Owned, mutation, nativeSettled: false);
        if (fault == "closed") fixture.Journal.Close("owner", selector);
        await Assert.That(() => fixture.Journal.AdmitStatusRead("owner", selector,
            fault == "lease" ? Guid.NewGuid() : lease, Owned,
            fault == "dispatch" ? Guid.NewGuid() : mutation)).Throws<InvalidOperationException>();
        await Assert.That(fixture.Journal.Read("owner", selector).Resources.Single().ActiveDispatch).IsEqualTo(mutation);
    }

    [Test]
    public async Task DispatchDependencyPredicateSeesAbsenceBeforeItsOwnInvalidation()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        string child = Owned + "/providers/Microsoft.EventGrid/eventSubscriptions/owned-child";
        fixture.Journal.Prepare("owner", selector, [new(Owned, false), new(child, false)]);
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        fixture.Journal.Close("owner", selector);
        fixture.Journal.RecordAbsence("owner", selector, child);
        Guid deletion = fixture.Journal.BeginDispatch("owner", selector, Owned, true,
            snapshot => snapshot.Resources.Single(r => r.Id == child) is { Absent: true, ActiveDispatch: var active } &&
                active == Guid.Empty);
        var after = fixture.Journal.Read("owner", selector);
        await Assert.That(after.Resources.Single(r => r.Id == child).Absent).IsFalse();
        await Assert.That(after.Resources.Single(r => r.Id == Owned).ActiveDispatch).IsEqualTo(deletion);
    }

    [Test]
    public async Task ConcurrentPresenceWinsOverPreviouslyReadCleanupDependencies()
    {
        using var fixture = new DirectoryFixture();
        var selector = Selector();
        string child = Owned + "/providers/Microsoft.EventGrid/eventSubscriptions/owned-child";
        fixture.Journal.Prepare("owner", selector, [new(Owned, false), new(child, false)]);
        Guid setup = fixture.Journal.BeginDispatch("owner", selector, Owned, false);
        fixture.Journal.EndDispatch("owner", selector, Owned, setup);
        fixture.Journal.Close("owner", selector);
        fixture.Journal.RecordAbsence("owner", selector, child);
        var inspected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var continueDispatch = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task attempt = Task.Run(async () =>
        {
            var before = fixture.Journal.Read("owner", selector);
            await Assert.That(before.Resources.Single(r => r.Id == child).Absent).IsTrue();
            inspected.TrySetResult();
            await continueDispatch.Task;
            fixture.Journal.BeginDispatch("owner", selector, Owned, true,
                snapshot => snapshot.Resources.Single(r => r.Id == child).Absent);
        });
        try
        {
            await inspected.Task.WaitAsync(TimeSpan.FromSeconds(10));
            new RoleFixtureJournal(fixture.Path).RecordPresence("owner", selector, child);
            long bytes = new FileInfo(JournalPath(fixture, selector)).Length;
            continueDispatch.TrySetResult();
            await Assert.That(async () => await attempt.WaitAsync(TimeSpan.FromSeconds(10))).Throws<InvalidOperationException>();
            await Assert.That(new FileInfo(JournalPath(fixture, selector)).Length).IsEqualTo(bytes);
            var after = fixture.Journal.Read("owner", selector);
            await Assert.That(after.Resources.Single(r => r.Id == Owned).DeleteAttempted).IsFalse();
            await Assert.That(after.Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        }
        finally { continueDispatch.TrySetResult(); }
    }

    private static FixtureSelector EscapedSelector()
    {
        string field = new('\u0001', 1024);
        return new(Guid.NewGuid(), field, field, field, field);
    }

    private sealed record JournalFrame(long Sequence, string Previous, RoleFixtureJournal.Snapshot State);

    private static byte[] FrameBytes(long sequence, RoleFixtureJournal.Snapshot snapshot) =>
        JsonSerializer.SerializeToUtf8Bytes(new JournalFrame(sequence, new string('F', 64), snapshot), ManagementAdmission.Json);

    private static RoleFixtureJournal.Snapshot FrameSizedSnapshot(string owner, FixtureSelector selector, int bytes)
    {
        Guid lease = Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff");
        RoleFixtureJournal.Resource[] resources = Enumerable.Range(0, 24)
            .Select(i => new RoleFixtureJournal.Resource(Owned + "/" + i.ToString("D2"), false, ActiveDispatch: lease)).ToArray();
        var snapshot = new RoleFixtureJournal.Snapshot(owner, selector, lease, false, resources);
        int remaining = bytes - FrameBytes(long.MaxValue, snapshot).Length;
        for (int i = 0; i < resources.Length && remaining > 0; i++)
        {
            int escaped = Math.Min(remaining / 6, 2048 - resources[i].Id.Length);
            resources[i] = resources[i] with { Id = resources[i].Id + new string('\u0001', escaped) };
            remaining -= escaped * 6;
            int plain = Math.Min(remaining, Math.Min(5, 2048 - resources[i].Id.Length));
            resources[i] = resources[i] with { Id = resources[i].Id + new string('x', plain) };
            remaining -= plain;
        }
        if (remaining != 0) throw new InvalidOperationException("frame-fixture-does-not-fit");
        return snapshot;
    }

    private static string JournalPath(DirectoryFixture fixture, FixtureSelector selector) =>
        System.IO.Path.Combine(fixture.Path, selector.Nonce.ToString("N") + ".journal");

    private sealed class DirectoryFixture : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "secretkit-role-journal-" + Guid.NewGuid().ToString("N"));
        internal RoleFixtureJournal Journal { get; }
        internal DirectoryFixture()
        {
            Directory.CreateDirectory(Path);
            Journal = new(Path);
        }
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
