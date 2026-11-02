using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Notification = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationFixtureProvisioner;
using Provisioner = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    private static readonly TimeSpan OwnedBound = TimeSpan.FromSeconds(10);

    [Test]
    public async Task OwnedNotificationDeclaresFourRowsBeforeAnyNativeWork()
    {
        using var f = new Fixture();
        string[] names = ["selected-notification"];
        var parent = f.Plan(notifications: names);
        names[0] = "replacement-notification";
        await using var n = new OwnedNotifications(f, parent);
        long declaredBytes = new FileInfo(f.JournalPath).Length;
        var child = n.Source.PlanDeclaredSubscription(parent, "selected-notification", Notification.Preparation.Present);
        await Assert.That(new FileInfo(f.JournalPath).Length).IsEqualTo(declaredBytes);
        await Assert.That(f.Read().Resources.Length).IsEqualTo(4);
        await Assert.That(f.Read().Resources.All(r => !r.Borrowed && !r.CreateAttempted)).IsTrue();
        await Assert.That(parent.OwnedNotificationNames.Single()).IsEqualTo("selected-notification");
        await Assert.That(parent.OwnedNotificationIds.Single()).IsEqualTo(child.ResourceId);
        await Assert.That(ReferenceEquals(child.ObjectPlan, parent)).IsTrue();
        await Assert.That(child.LeaseId).IsEqualTo(parent.LeaseId);
        await Assert.That(child.Manifest.SequenceEqual(parent.Manifest)).IsTrue();
        await Assert.That(f.Backends.SelectMany(b => b.Requests).Any() || n.Requests.Count != 0).IsFalse();
        var exposed = f.Read();
        exposed.Resources[0] = exposed.Resources[0] with { Borrowed = true };
        await Assert.That(parent.Manifest.All(r => !r.Borrowed)).IsTrue();
        using var material = SecretMaterial.FromText(Material);
        await Assert.That((await f.Source.ProvisionAsync(parent, material)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(n.Requests.Count).IsEqualTo(0);
        using var ready = await n.Source.ProvisionAsync(child);
        await Assert.That(ready.State).IsEqualTo(Notification.State.Ready);
        await Assert.That(n.Resources.ContainsKey(child.ResourceId)).IsTrue();
        await Assert.That(n.Prejournaled).IsTrue();
        await Assert.That(ready.Journal.LeaseId).IsEqualTo(parent.LeaseId);
        await Assert.That(ready.Journal.Resources.Length).IsEqualTo(4);
        await Assert.That(ready.Journal.Resources.Single(r => r.Id == child.ResourceId).CreateAttempted).IsTrue();
    }

    [Test]
    [Arguments(20, 1, 0)]
    [Arguments(19, 2, 0)]
    [Arguments(0, 21, 0)]
    [Arguments(0, 8, 13)]
    public async Task OwnedNotificationsShareOneTwentyFourRowBudget(int secrets, int notifications, int borrowed)
    {
        using var f = new Fixture();
        using var material = SecretMaterial.FromText("owned-budget-material");
        var children = Enumerable.Range(0, secrets).Select(i =>
            new Provisioner.PolicyChildSpecification("secret-" + i, Provisioner.Preparation.Active, material)).ToArray();
        string[] names = Enumerable.Range(0, notifications).Select(i => "notification-" + i).ToArray();
        string[] dependencies = Enumerable.Range(0, borrowed).Select(i => Group + "/providers/Example/items/item-" + i).ToArray();
        var parent = f.Plan(seedCanary: false, children: children, notifications: names, borrowed: dependencies);
        await using var n = new OwnedNotifications(f, parent);
        long declaredBytes = new FileInfo(f.JournalPath).Length;
        foreach (string name in names) n.Source.PlanDeclaredSubscription(parent, name, Notification.Preparation.Absent);
        await Assert.That(f.Read().Resources.Length).IsEqualTo(24);
        await Assert.That(parent.Manifest.Count).IsEqualTo(24);
        await Assert.That(new FileInfo(f.JournalPath).Length).IsEqualTo(declaredBytes);
        await Assert.That(f.Writes + n.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(21, 1, 0)]
    [Arguments(0, 22, 0)]
    [Arguments(0, 1, 14)]
    public async Task OwnedNotificationOverBudgetRejectsBeforeJournalDeclaration(int secrets, int notifications, int borrowed)
    {
        using var f = new Fixture();
        using var material = SecretMaterial.FromText("owned-budget-material");
        var children = Enumerable.Range(0, secrets).Select(i =>
            new Provisioner.PolicyChildSpecification("secret-" + i, Provisioner.Preparation.Active, material)).ToArray();
        await Assert.That(() => f.Plan(seedCanary: false, children: children,
            notifications: Enumerable.Range(0, notifications).Select(i => "notification-" + i).ToArray(),
            borrowed: Enumerable.Range(0, borrowed).Select(i => Group + "/providers/Example/items/item-" + i).ToArray()))
            .Throws<InvalidOperationException>();
        await Assert.That(File.Exists(f.JournalPath)).IsFalse();
        await Assert.That(f.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments("ab")]
    [Arguments("bad/name")]
    [Arguments("bad_name")]
    [Arguments("non-ascii-\u00e9")]
    public async Task OwnedNotificationNameGrammarRejectsBeforeDeclaration(string name)
    {
        using var f = new Fixture();
        await Assert.That(() => f.Plan(notifications: [name])).Throws<InvalidOperationException>();
        await Assert.That(File.Exists(f.JournalPath)).IsFalse();
    }

    [Test]
    public async Task OwnedNotificationNamesAreUniqueAndRequireActiveParentPreparation()
    {
        using var f = new Fixture();
        await Assert.That(() => f.Plan(notifications: ["one-child", "ONE-child"])).Throws<InvalidOperationException>();
        await Assert.That(() => f.Plan(Provisioner.Preparation.Absent, false, notifications: ["one-child"]))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Plan(Provisioner.Preparation.Deleted, false, notifications: ["one-child"]))
            .Throws<InvalidOperationException>();
        await Assert.That(File.Exists(f.JournalPath)).IsFalse();
    }

    [Test]
    [Arguments("nested-secret")]
    [Arguments("nested-notification")]
    [Arguments("foreign-owned")]
    [Arguments("cleanup-notification")]
    [Arguments("borrowed-notification")]
    [Arguments("borrowed-secret")]
    public async Task RestoredTopologyRejectsUnknownAndBorrowedOwnedDescendants(string fault)
    {
        using var f = new Fixture();
        string vault = Group + "/providers/Microsoft.KeyVault/vaults/skv" + new string('a', 21);
        string deleted = $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/skv" + new string('a', 21);
        string notification = vault + Provisioner.NotificationPrefix + "one-child";
        RoleFixtureJournal.Resource extra = fault switch
        {
            "nested-secret" => new RoleFixtureJournal.Resource(vault + "/secrets/child/versions/foreign", false),
            "nested-notification" => new(notification + "/providers/foreign/type", false),
            "foreign-owned" => new(vault + "/providers/Microsoft.Authorization/roleAssignments/foreign", false),
            "cleanup-notification" => new(notification, false, CleanupOnly: true),
            "borrowed-notification" => new(notification, true),
            _ => new(vault + "/secrets/child", true)
        };
        f.Journal.Prepare(Owner, f.Selector,
            [new(vault, false), new(vault + "/secrets/canary", false), new(deleted, false, CleanupOnly: true), extra]);
        long bytes = new FileInfo(f.JournalPath).Length;
        await using var cleanup = f.Cleanup();
        await Assert.That(() => cleanup.OpenCleanupPlan(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(() => cleanup.CloseSelectedRoot(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(new FileInfo(f.JournalPath).Length).IsEqualTo(bytes);
        await Assert.That(f.Read().Closing).IsFalse();
        await Assert.That(f.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task OwnedChildNeedsPrivateParentReadinessWithoutConsumingPreparation()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Absent);
        await Assert.That(async () => await n.Source.ProvisionAsync(child)).Throws<InvalidOperationException>();
        await Assert.That(child.Consumed).IsEqualTo(0);
        await Assert.That(n.Requests.Count).IsEqualTo(0);
        await Assert.That((await f.Source.ProvisionAsync(parent)).State).IsEqualTo(Provisioner.State.Ready);
        using var beforePreparation = await n.Source.ObserveAsync(Owner, f.Selector, "one-child");
        await Assert.That(beforePreparation.State).IsEqualTo(Notification.State.Incomplete);
        using var absent = await n.Source.ProvisionAsync(child);
        await Assert.That(absent.State).IsEqualTo(Notification.State.Ready);
        await Assert.That(absent.Present).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).CreateAttempted).IsFalse();
        await Assert.That(n.Requests.All(r => r.Method == HttpMethod.Get)).IsTrue();
    }

    [Test]
    public async Task CopiedSourceTokenAndManifestCannotForgeOriginalParentPlan()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var forged = new Provisioner.Plan(parent.Source, parent.Owner, parent.Selector, parent.LeaseId,
            parent.VaultId, parent.DeletedId, parent.Preparation, parent.SeedCanary,
            ownedNotificationNames: parent.OwnedNotificationNames.ToArray(), manifest: parent.Manifest.ToArray());
        long bytes = new FileInfo(f.JournalPath).Length;
        await Assert.That(() => n.Source.PlanDeclaredSubscription(forged, "one-child", Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        await Assert.That(() => n.Source.PlanDeclaredSubscription(parent, "undeclared-child", Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        await Assert.That(() => n.Source.PlanDeclaredSubscription(parent, "ONE-child", Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        await Assert.That(new FileInfo(f.JournalPath).Length).IsEqualTo(bytes);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        await Assert.That(ReferenceEquals(child.ObjectPlan, parent)).IsTrue();
        await Assert.That(() => n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        await using var siblingSource = new OwnedNotifications(f, parent);
        await Assert.That(() => siblingSource.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        await Assert.That(() => n.Source.PlanFixture(Owner, f.Selector, Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await n.Source.ObserveAsync(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(async () => await n.Source.ReleaseAsync(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(async () => await n.Source.SettleAsync(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(f.Read().Closing).IsFalse();
    }

    [Test]
    public async Task OwnedChildRejectsForeignJournalHostAndFullSelectorWithoutAppending()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        long bytes = new FileInfo(f.JournalPath).Length;
        await Assert.That(() => n.Construct(f.Journal)).Throws<InvalidOperationException>();
        await using var wrongHost = n.Construct(f.Source.Journal, new(f.Source.Scope(parent).ResourceGroup, "foreign-vault"));
        await Assert.That(() => wrongHost.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        await Assert.That(async () => await n.Source.ObserveAsync(Owner, f.Selector with { Variant = "foreign" }, "one-child"))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await n.Source.ObserveAsync("foreign-owner", f.Selector, "one-child"))
            .Throws<InvalidOperationException>();
        await Assert.That(new FileInfo(f.JournalPath).Length).IsEqualTo(bytes);
    }

    [Test]
    public async Task OwnedNotificationsNeverAdoptExistingNativeChildren()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        await f.Source.ProvisionAsync(parent);
        n.Seed(child);
        using var result = await n.Source.ProvisionAsync(child);
        await Assert.That(result.State).IsEqualTo(Notification.State.Uncertain);
        using var release = await n.Source.ReleaseAsync(Owner, f.Selector, "one-child");
        await Assert.That(release.State).IsEqualTo(Notification.State.Uncertain);
        await Assert.That(n.Requests.All(r => r.Method == HttpMethod.Get)).IsTrue();
        await Assert.That(f.Read().Released).IsFalse();
    }

    [Test]
    public async Task NativeCompositeCleanupRefreshesSiblingsAfterEveryParentMutation()
    {
        using var f = new Fixture(allowPurge: true);
        var parent = f.Plan(seedCanary: false, notifications: ["first-child", "second-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var first = n.Source.PlanDeclaredSubscription(parent, "first-child", Notification.Preparation.Present);
        var second = n.Source.PlanDeclaredSubscription(parent, "second-child", Notification.Preparation.Present);
        await f.Source.ProvisionAsync(parent);
        using var firstReady = await n.Source.ProvisionAsync(first);
        using var secondReady = await n.Source.ProvisionAsync(second);
        await Assert.That(firstReady.State).IsEqualTo(Notification.State.Ready);
        await Assert.That(secondReady.State).IsEqualTo(Notification.State.Ready);
        int writes = f.Writes;
        await f.Source.ReleaseAsync(Owner, f.Selector, purge: true);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(f.Wire.Active).IsTrue();
        using var firstReleased = await n.Source.ReleaseAsync(Owner, f.Selector, "first-child");
        await Assert.That(firstReleased.State).IsEqualTo(Notification.State.Closing);
        using var secondReleased = await n.Source.ReleaseAsync(Owner, f.Selector, "second-child");
        await Assert.That(f.Read().Resources.Single(r => r.Id == first.ResourceId).Absent).IsFalse();
        using var firstRefreshed = await n.Source.ObserveAsync(Owner, f.Selector, "first-child");
        await Assert.That(firstRefreshed.Present).IsFalse();
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Closing);
        await Assert.That(f.Writes).IsEqualTo(writes + 1);
        await Assert.That(f.Wire.Deleted).IsTrue();
        await Assert.That(f.Read().Resources.Where(r => parent.OwnedNotificationIds.Contains(r.Id)).All(r => !r.Absent)).IsTrue();
        using var firstAfterDelete = await n.Source.ObserveAsync(Owner, f.Selector, "first-child");
        using var secondAfterDelete = await n.Source.ObserveAsync(Owner, f.Selector, "second-child");
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Closing);
        await Assert.That(f.Writes).IsEqualTo(writes + 2);
        await Assert.That(f.Wire.Active || f.Wire.Deleted).IsFalse();
        await Assert.That(f.Read().Released).IsFalse();
        using var firstAfterPurge = await n.Source.ObserveAsync(Owner, f.Selector, "first-child");
        using var secondAfterPurge = await n.Source.ObserveAsync(Owner, f.Selector, "second-child");
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Read().Resources.All(r => r.Absent && r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(n.Resources.Count).IsEqualTo(0);
        await Assert.That(n.Prejournaled).IsTrue();
    }

    [Test]
    public async Task ParentNativeAdmissionRechecksChildDependencyAfterCredentialRace()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Absent);
        await f.Source.ProvisionAsync(parent);
        using var prepared = await n.Source.ProvisionAsync(child);
        using var absent = await n.Source.ReleaseAsync(Owner, f.Selector, "one-child");
        await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).Absent).IsTrue();
        // This occurs after the release driver's independent reads but before
        // the actual parent dispatch reaches its journal transaction.
        f.BeforeSetupCredential(() => f.Journal.RecordPresence(Owner, f.Selector, child.ResourceId));
        int writes = f.Writes;
        var result = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(result.State).IsEqualTo(Provisioner.State.Uncertain);
        await Assert.That(f.Writes).IsEqualTo(writes);
        await Assert.That(f.Wire.Active).IsTrue();
        await Assert.That(f.Read().Resources.Single(r => r.Id == parent.VaultId).DeleteAttempted).IsFalse();
        await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).Absent).IsFalse();
    }

    [Test]
    [Arguments("invalid-json")]
    [Arguments("foreign-topic")]
    public async Task PositiveChildReadInvalidatesOldAbsenceBeforeParsing(string fault)
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Absent);
        await f.Source.ProvisionAsync(parent);
        using var ready = await n.Source.ProvisionAsync(child);
        using var absent = await n.Source.ReleaseAsync(Owner, f.Selector, "one-child");
        await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).Absent).IsTrue();
        n.Seed(child);
        n.ReadFault = fault;
        using var observed = await n.Source.ObserveAsync(Owner, f.Selector, "one-child");
        await Assert.That(observed.State).IsEqualTo(Notification.State.Uncertain);
        await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).Absent).IsFalse();
        int writes = f.Writes;
        await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(f.Writes).IsEqualTo(writes);
    }

    [Test]
    public async Task ParentAbsenceCannotStandInForIndependentNotificationAbsence()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Absent);
        var release = await f.Source.ReleaseAsync(Owner, f.Selector);
        await Assert.That(release.State).IsEqualTo(Provisioner.State.Closing);
        await Assert.That(f.Read().Resources.Single(r => r.Id == parent.OwnedNotificationIds.Single()).Absent).IsFalse();
        await Assert.That(f.Read().Released).IsFalse();
        using var absent = await n.Source.ObserveAsync(Owner, f.Selector, "one-child");
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Released);
    }

    [Test]
    public async Task CleanupOnlyRestartNeedsCoordinatesNotConfigurationOrMaterial()
    {
        using var f = new Fixture(allowPurge: true);
        var parent = f.Plan(notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        using var material = SecretMaterial.FromText(Material);
        await f.Source.ProvisionAsync(parent, material);
        using var prepared = await n.Source.ProvisionAsync(child);
        await n.Source.DisposeAsync();
        await f.Source.DisposeAsync();
        await using var cleanup = f.Cleanup();
        var reopened = cleanup.OpenCleanupPlan(Owner, f.Selector);
        await Assert.That(reopened.Restored).IsTrue();
        await Assert.That(reopened.Receipts.Count).IsEqualTo(0);
        await Assert.That(reopened.CanarySha256).IsNull();
        await Assert.That(reopened.CanaryVersion).IsNull();
        await Assert.That(reopened.Manifest.SequenceEqual(parent.Manifest)).IsTrue();
        await Assert.That(async () => await cleanup.ProvisionAsync(reopened)).Throws<InvalidOperationException>();
        await Assert.That(async () => await cleanup.ContinueAsync(reopened)).Throws<InvalidOperationException>();
        await Assert.That(() => cleanup.PlanFixture(Owner, f.Selector, Provisioner.Preparation.Active, []))
            .Throws<InvalidOperationException>();
        await using var children = n.Cleanup(cleanup);
        using var deleted = await children.ReleaseAsync(Owner, f.Selector, "one-child");
        await Assert.That(deleted.State).IsEqualTo(Notification.State.Closing);
        await cleanup.ReleaseAsync(Owner, f.Selector, purge: true);
        using var afterDelete = await children.ObserveAsync(Owner, f.Selector, "one-child");
        await cleanup.ReleaseAsync(Owner, f.Selector, purge: true);
        using var afterPurge = await children.ObserveAsync(Owner, f.Selector, "one-child");
        await Assert.That((await cleanup.ReleaseAsync(Owner, f.Selector, purge: true)).State).IsEqualTo(Provisioner.State.Released);
    }

    [Test]
    public async Task CleanupOnlyRestartKeepsUnknownActiveNativeDispatchFenced()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        await f.Source.ProvisionAsync(parent);
        n.CreateFault = "lost";
        using var uncertain = await n.Source.ProvisionAsync(child);
        Guid dispatch = f.Read().Resources.Single(r => r.Id == child.ResourceId).ActiveDispatch;
        await Assert.That(dispatch).IsNotEqualTo(Guid.Empty);
        await n.Source.DisposeAsync();
        await f.Source.DisposeAsync();
        await using var cleanup = f.Cleanup();
        await using var children = n.Cleanup(cleanup);
        int reads = n.Requests.Count;
        using var observation = await children.ObserveAsync(Owner, f.Selector, "one-child");
        using var settlement = await children.SettleAsync(Owner, f.Selector, "one-child");
        using var release = await children.ReleaseAsync(Owner, f.Selector, "one-child");
        await Assert.That(observation.State).IsEqualTo(Notification.State.Pending);
        await Assert.That(settlement.State).IsEqualTo(Notification.State.Pending);
        await Assert.That(release.State).IsEqualTo(Notification.State.Pending);
        await Assert.That((await cleanup.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(n.Requests.Count).IsEqualTo(reads);
        await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).ActiveDispatch).IsEqualTo(dispatch);
    }

    [Test]
    public async Task WrongHostCloseCannotChangeOriginalOpenRoot()
    {
        using var f = new Fixture();
        f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var foreign = f.Cleanup("different-group");
        long bytes = new FileInfo(f.JournalPath).Length;
        await Assert.That(() => foreign.CloseSelectedRoot(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(async () => await foreign.ReleaseAsync(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That(new FileInfo(f.JournalPath).Length).IsEqualTo(bytes);
        await Assert.That(f.Read().Closing).IsFalse();
    }

    [Test]
    public async Task EmptyCloseTombstoneNeverInventsCleanupVaultCoordinates()
    {
        using var f = new Fixture();
        await using var cleanup = f.Cleanup();
        await Assert.That(cleanup.CloseSelectedRoot(Owner, f.Selector).Released).IsTrue();
        await Assert.That(() => cleanup.OpenCleanupPlan(Owner, f.Selector)).Throws<InvalidOperationException>();
        await Assert.That((await cleanup.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task MutableReceiptAndJournalFlagsCannotPublishParentReadiness()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        Guid dispatch = f.Journal.BeginDispatch(Owner, f.Selector, parent.VaultId, false);
        f.Journal.EndDispatch(Owner, f.Selector, parent.VaultId, dispatch);
        f.Wire.Seed(parent, f.Baseline, f.Selector.Nonce);
        parent.History.Add(new(Provisioner.Action.CreateVault, parent.VaultId)
        {
            Outcome = Provisioner.State.Ready,
            Attempted = true,
            Terminated = true,
            RemoteSettled = true
        });
        await Assert.That((await f.Source.ObserveAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(async () => await n.Source.ProvisionAsync(child)).Throws<InvalidOperationException>();
        await Assert.That(child.Consumed).IsEqualTo(0);
        await Assert.That(n.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task RestoredOrDisposedParentCannotAdmitNewDeclaredChild()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        await using var reopened = f.Reopen();
        var restored = reopened.OpenCleanupPlan(Owner, f.Selector);
        await using var restoredChildren = n.ConstructFor(reopened, restored);
        await Assert.That(() => restoredChildren.PlanDeclaredSubscription(restored, "one-child", Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        await f.Source.DisposeAsync();
        await Assert.That(() => n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present))
            .Throws<InvalidOperationException>();
        await Assert.That(n.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("preflight")]
    [Arguments("credential")]
    [Arguments("transport")]
    [Arguments("parser")]
    [Arguments("status")]
    public async Task ChildHoldsParentNativeGateThroughEveryActualSdkStage(string stage)
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["first-child", "second-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var first = n.Source.PlanDeclaredSubscription(parent, "first-child", Notification.Preparation.Present);
        var second = n.Source.PlanDeclaredSubscription(parent, "second-child", Notification.Preparation.Absent);
        await f.Source.ProvisionAsync(parent);
        n.Barrier = stage;
        n.Entered = Signal();
        n.Resume = Signal();
        Task<Notification.Result> running = n.Source.ProvisionAsync(first).AsTask();
        try
        {
            await n.Entered.Task.WaitAsync(OwnedBound);
            int parentRequests = f.Backends.Sum(b => b.Requests.Count);
            await Assert.That(parent.Busy).IsEqualTo(1);
            await Assert.That((await f.Source.ObserveAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
            using var busy = await n.Source.ProvisionAsync(second);
            await Assert.That(busy.State).IsEqualTo(Notification.State.Pending);
            await Assert.That(second.Consumed).IsEqualTo(0);
            await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(parentRequests);
            Task disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted).IsFalse();
            await Assert.That(f.Read().Closing).IsTrue();
            await Assert.That(running.IsCompleted).IsFalse();
            n.Resume.TrySetResult();
            using var result = await running.WaitAsync(OwnedBound);
            await disposal.WaitAsync(OwnedBound);
            await Assert.That(parent.Busy).IsEqualTo(0);
            await Assert.That(first.Receipts.All(r => r.Terminated)).IsTrue();
            await Assert.That(f.Backends.All(b => !b.Disposed)).IsTrue();
            await Assert.That(n.Requests.All(r => r.Method != HttpMethod.Delete)).IsTrue();
        }
        finally { n.Resume.TrySetResult(); using var drained = await running.WaitAsync(OwnedBound); }
    }

    [Test]
    public async Task ChildInjectedDeadlineDoesNotReleaseParentBeforeIgnoredCancellationDrains()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        await f.Source.ProvisionAsync(parent);
        n.Barrier = "transport";
        n.Entered = Signal();
        n.Resume = Signal();
        Task<Notification.Result> running = n.Source.ProvisionAsync(child).AsTask();
        try
        {
            await n.Entered.Task.WaitAsync(OwnedBound);
            n.Clock.Advance(OwnedBound);
            await Assert.That(running.IsCompleted).IsFalse();
            await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
            await Assert.That(f.Wire.Active).IsTrue();
            Task disposal = n.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted).IsFalse();
            n.Resume.TrySetResult();
            using var result = await running.WaitAsync(OwnedBound);
            await Assert.That(result.State).IsEqualTo(Notification.State.Uncertain);
            await disposal.WaitAsync(OwnedBound);
            await Assert.That(parent.Busy).IsEqualTo(0);
            await Assert.That(child.Receipts.Single().Terminated).IsTrue();
            await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).ActiveDispatch).IsNotEqualTo(Guid.Empty);
            await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
        }
        finally { n.Resume.TrySetResult(); using var drained = await running.WaitAsync(OwnedBound); }
    }

    [Test]
    public async Task CloseDuringChildPreflightStopsMutationWithoutInventingAbsence()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        await f.Source.ProvisionAsync(parent);
        n.Barrier = "preflight";
        n.Entered = Signal();
        n.Resume = Signal();
        Task<Notification.Result> running = n.Source.ProvisionAsync(child).AsTask();
        try
        {
            await n.Entered.Task.WaitAsync(OwnedBound);
            n.Source.CloseSelectedRoot(Owner, f.Selector);
            await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
            n.Resume.TrySetResult();
            using var result = await running.WaitAsync(OwnedBound);
            await Assert.That(result.State).IsNotEqualTo(Notification.State.Ready);
            await Assert.That(n.Requests.All(r => r.Method == HttpMethod.Get)).IsTrue();
            await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).Absent).IsFalse();
            using var fresh = await n.Source.ObserveAsync(Owner, f.Selector, "one-child");
            await Assert.That(fresh.State).IsEqualTo(Notification.State.Closing);
            await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).Absent).IsTrue();
        }
        finally { n.Resume.TrySetResult(); using var drained = await running.WaitAsync(OwnedBound); }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task FailedCloseAppendStillDrainsChildBeforeDisposalFailureReturns(bool parentDisposal)
    {
        var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        await f.Source.ProvisionAsync(parent);
        n.Barrier = "transport";
        n.Entered = Signal();
        n.Resume = Signal();
        Task<Notification.Result> running = n.Source.ProvisionAsync(child).AsTask();
        try
        {
            await n.Entered.Task.WaitAsync(OwnedBound);
            Task disposal;
            using (var file = new FileStream(f.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                disposal = parentDisposal ? f.Source.DisposeAsync().AsTask() : n.Source.DisposeAsync().AsTask();
                await Assert.That(disposal.IsCompleted).IsFalse();
                await Assert.That(running.IsCompleted).IsFalse();
                await Assert.That(parent.Busy).IsEqualTo(1);
            }
            n.Resume.TrySetResult();
            using var result = await running.WaitAsync(OwnedBound);
            await Assert.That(async () => await disposal.WaitAsync(OwnedBound)).Throws<InvalidOperationException>();
            await Assert.That(parent.Busy).IsEqualTo(0);
            await Assert.That(child.Receipts.Single().Terminated).IsTrue();
            await Assert.That(n.Resources.ContainsKey(child.ResourceId)).IsTrue();
            await Assert.That(n.Requests.All(r => r.Method != HttpMethod.Delete)).IsTrue();
        }
        finally
        {
            n.Resume.TrySetResult();
            using var drained = await running.WaitAsync(OwnedBound);
            try
            {
                if (parentDisposal) await n.DisposeAsync();
                else await Assert.That(async () => await n.DisposeAsync()).Throws<InvalidOperationException>();
            }
            finally
            {
                if (parentDisposal) await Assert.That(() => f.Dispose()).Throws<InvalidOperationException>();
                else f.Dispose();
            }
        }
    }

    [Test]
    public async Task NativeResponseDisposalFailureDrainsButCannotSettleOwnedMutation()
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Present);
        await f.Source.ProvisionAsync(parent);
        n.CreateFault = "dispose";
        using var result = await n.Source.ProvisionAsync(child);
        await Assert.That(result.State).IsEqualTo(Notification.State.Uncertain);
        await Assert.That(child.Receipts.Single().Terminated).IsTrue();
        await Assert.That(parent.Busy).IsEqualTo(0);
        await Assert.That(f.Read().Resources.Single(r => r.Id == child.ResourceId).ActiveDispatch).IsNotEqualTo(Guid.Empty);
        await Assert.That((await f.Source.ReleaseAsync(Owner, f.Selector)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(n.Resources.ContainsKey(child.ResourceId)).IsTrue();
    }

    private sealed record OwnedNotificationRequest(string Role, HttpMethod Method, string Id);

    [Test]
    [Arguments("prepare")]
    [Arguments("continue")]
    [Arguments("observe")]
    [Arguments("settle")]
    [Arguments("release")]
    public async Task ReviewTimerFailureReleasesParentGate(string operation)
    {
        using var f = new Fixture();
        var clock = new OwnedNotificationClock();
        await using var source = f.Reopen(time: clock);
        var parent = source.PlanFixture(Owner, f.Selector, Provisioner.Preparation.Active, [],
            seedCanary: false, ownedNotificationNames: ["one-child"]);
        f.Wire.VaultId = parent.VaultId;
        f.Wire.VaultName = parent.VaultName;
        if (operation != "prepare") await source.ProvisionAsync(parent);
        int requests = f.Backends.Sum(b => b.Requests.Count);
        clock.ThrowOnCreate = true;
        try
        {
            try
            {
                await (operation switch
                {
                    "prepare" => source.ProvisionAsync(parent),
                    "continue" => source.ContinueAsync(parent),
                    "observe" => source.ObserveAsync(Owner, f.Selector),
                    "settle" => source.SettleAsync(parent),
                    _ => source.ReleaseAsync(Owner, f.Selector)
                });
            }
            catch (InvalidOperationException exception) when (exception.Message == "controlled-timer-failure") { }
            await Assert.That(parent.Busy).IsEqualTo(0);
            await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(requests);
            await Assert.That(f.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        }
        finally
        {
            clock.ThrowOnCreate = false;
            if (parent.Busy != 0) source.ExitNotification(parent);
        }
        await source.DisposeAsync().AsTask().WaitAsync(OwnedBound);
    }

    [Test]
    [Arguments("prepare")]
    [Arguments("observe")]
    [Arguments("settle")]
    [Arguments("release")]
    public async Task ReviewTimerFailureReleasesBothNotificationGates(string operation)
    {
        using var f = new Fixture();
        var parent = f.Plan(seedCanary: false, notifications: ["one-child"]);
        await using var n = new OwnedNotifications(f, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Absent);
        await f.Source.ProvisionAsync(parent);
        n.Clock.ThrowOnCreate = true;
        try
        {
            try
            {
                using var result = await (operation switch
                {
                    "prepare" => n.Source.ProvisionAsync(child),
                    "observe" => n.Source.ObserveAsync(Owner, f.Selector, "one-child"),
                    "settle" => n.Source.SettleAsync(Owner, f.Selector, "one-child"),
                    _ => n.Source.ReleaseAsync(Owner, f.Selector, "one-child")
                });
            }
            catch (InvalidOperationException exception) when (exception.Message == "controlled-timer-failure") { }
            await Assert.That(parent.Busy).IsEqualTo(0);
            await Assert.That(child.Gate.CurrentCount).IsEqualTo(1);
            await Assert.That(f.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
            await Assert.That(n.Requests.Count).IsEqualTo(0);
        }
        finally
        {
            // Restore only the known leaked test state after a failing assertion;
            // no actual task or native operation was started by this clock.
            n.Clock.ThrowOnCreate = false;
            if (parent.Busy != 0) f.Source.ExitNotification(parent);
            if (child.Gate.CurrentCount == 0) child.Gate.Release();
        }
        await n.Source.DisposeAsync().AsTask().WaitAsync(OwnedBound);
        await f.Source.DisposeAsync().AsTask().WaitAsync(OwnedBound);
    }

    [Test]
    public async Task ReviewOriginalRuntimeCanaryUpdatePreservesOwnedParentCleanup()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["one-child"], allowPurge: true);
        var parent = f.Fixture.Source.OpenCleanupPlan(Owner, f.Binding.Selector);
        await using var n = new OwnedNotifications(f.Fixture, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Absent);
        using var prepared = await n.Source.ProvisionAsync(child);
        var capture = await Trigger(f);
        await Assert.That(f.Source.Read(capture, f.Binding).NativeSettled).IsTrue();
        await Assert.That(f.Fixture.Read().Resources.Single(r => r.Id == parent.SecretId).SelectedAttempted).IsTrue();
        using var absent = await n.Source.ReleaseAsync(Owner, f.Binding.Selector, "one-child");
        var deleted = await f.Fixture.Source.ReleaseAsync(Owner, f.Binding.Selector, purge: true);
        await Assert.That(deleted.State).IsEqualTo(Provisioner.State.Closing);
        await Assert.That(f.Fixture.Wire.Active).IsFalse();
        using var afterDelete = await n.Source.ObserveAsync(Owner, f.Binding.Selector, "one-child");
        await f.Fixture.Source.ReleaseAsync(Owner, f.Binding.Selector, purge: true);
        using var afterPurge = await n.Source.ObserveAsync(Owner, f.Binding.Selector, "one-child");
        await Assert.That((await f.Fixture.Source.ReleaseAsync(Owner, f.Binding.Selector, purge: true)).State)
            .IsEqualTo(Provisioner.State.Released);
        await Assert.That(f.Fixture.Read().Released).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ReviewCleanupKeepsUnselectedMaterialAndUnknownDispatchFences(bool selected)
    {
        await using var f = await NotificationCaptureScope.Create("lost", notifications: ["one-child"], allowPurge: true);
        var parent = f.Fixture.Source.OpenCleanupPlan(Owner, f.Binding.Selector);
        await using var n = new OwnedNotifications(f.Fixture, parent);
        var child = n.Source.PlanDeclaredSubscription(parent, "one-child", Notification.Preparation.Absent);
        using var prepared = await n.Source.ProvisionAsync(child);
        if (selected)
        {
            using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
            var window = f.Source.Arm(f.Binding, material);
            var target = f.Target();
            await f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), new(target), default);
            await Assert.That(f.Source.Read(window, f.Binding).NativeSettled).IsFalse();
            await Assert.That(f.Fixture.Read().Resources.Single(r => r.Id == parent.SecretId).ActiveDispatch)
                .IsNotEqualTo(Guid.Empty);
        }
        else f.Fixture.Wire.Secret = "unselected-material-change";
        using var absent = await n.Source.ReleaseAsync(Owner, f.Binding.Selector, "one-child");
        int writes = f.Fixture.Writes;
        var result = await f.Fixture.Source.ReleaseAsync(Owner, f.Binding.Selector, purge: true);
        await Assert.That(result.State).IsEqualTo(selected ? Provisioner.State.Pending : Provisioner.State.Uncertain);
        await Assert.That(f.Fixture.Writes).IsEqualTo(writes);
        await Assert.That(f.Fixture.Wire.Active).IsTrue();
        await Assert.That(f.Fixture.Read().Released).IsFalse();
    }

    private sealed class OwnedNotifications : IAsyncDisposable
    {
        private const string Endpoint = "https://fixture.invalid/owned-notification";
        private readonly Fixture fixture;
        private readonly Provisioner.Plan parent;
        private readonly HttpClient[] clients;
        private readonly HttpClientTransport[] transports;
        private readonly OwnedNotificationCredential[] credentials;
        private readonly NotificationConfiguration configuration;
        private readonly Notification.Limits limits = new(65536, 65536, 65536, 16, 32, 8192, OwnedBound);
        internal readonly Notification Source;
        internal readonly Dictionary<string, JsonObject> Resources = new(StringComparer.Ordinal);
        internal readonly List<OwnedNotificationRequest> Requests = [];
        internal readonly OwnedNotificationClock Clock = new();
        internal bool Prejournaled = true;
        internal string? ReadFault, CreateFault;
        internal TaskCompletionSource? Entered, Resume;
        internal string? Barrier;
        internal JsonObject? SelectedPatch;
        internal HttpPipelineTransport SelectedBackend => transports[2];
        internal TokenCredential SelectedCredential => credentials[2];

        internal OwnedNotifications(Fixture fixture, Provisioner.Plan parent, VaultNotificationEvent[]? events = null)
        {
            this.fixture = fixture;
            this.parent = parent;
            configuration = new(Endpoint, events ?? [VaultNotificationEvent.SecretNewVersionCreated]);
            credentials = [new(this, "notification-setup"), new(this, "notification-observer"), new(this, "notification-selected")];
            clients = new[] { "notification-setup", "notification-observer", "notification-selected" }
                .Select(role => new HttpClient(new OwnedNotificationBackend(this, role))).ToArray();
            transports = clients.Select(c => new HttpClientTransport(c)).ToArray();
            Source = Construct(fixture.Source.Journal);
        }

        internal Notification Construct(RoleFixtureJournal journal, VaultScope? vault = null) =>
            new(journal, new(vault ?? fixture.Source.Scope(parent), true, true), configuration,
                new(credentials[0], transports[0]), new(credentials[1], transports[1]), limits, Clock, fixture.Source);

        internal Notification Cleanup(Provisioner source) => Notification.ForOwnedCleanup(source, Owner, fixture.Selector,
            new(credentials[0], transports[0]), new(credentials[1], transports[1]), limits, Clock);

        internal Notification ConstructFor(Provisioner source, Provisioner.Plan plan) =>
            new(source.Journal, new(source.Scope(plan), true, true), configuration,
                new(credentials[0], transports[0]), new(credentials[1], transports[1]), limits, Clock, source);

        internal void Seed(Notification.Plan plan)
        {
            Resources.Add(plan.ResourceId, new JsonObject
            {
                ["id"] = plan.ResourceId,
                ["name"] = plan.Scope.SubscriptionName,
                ["type"] = "Microsoft.EventGrid/eventSubscriptions",
                ["properties"] = new JsonObject
                {
                    ["topic"] = plan.Scope.Vault.ExportResourceId(),
                    ["provisioningState"] = "Succeeded",
                    ["labels"] = new JsonArray("secretkit-fixture-" + plan.Selector.Nonce.ToString("N")),
                    ["destination"] = new JsonObject
                    {
                        ["endpointType"] = "WebHook",
                        ["properties"] = new JsonObject { ["endpointUrl"] = Endpoint, ["deliveryAttributeMappings"] = new JsonArray() }
                    },
                    ["filter"] = new JsonObject { ["includedEventTypes"] = new JsonArray("Microsoft.KeyVault.SecretNewVersionCreated") }
                }
            });
        }

        private async Task<HttpResponseMessage> Respond(HttpRequestMessage request, string role, CancellationToken token)
        {
            string id = request.RequestUri!.AbsolutePath;
            Requests.Add(new(role, request.Method, id));
            if (request.RequestUri.Host != "management.azure.com" || request.RequestUri.Query != "?api-version=2025-02-15" ||
                !parent.OwnedNotificationIds.Contains(id) || request.Headers.Authorization?.Parameter != role ||
                role == "notification-observer" && request.Method != HttpMethod.Get)
                throw new InvalidOperationException("owned-notification-boundary");
            if (request.Method != HttpMethod.Get)
            {
                var snapshot = fixture.Read();
                Prejournaled &= snapshot.LeaseId == parent.LeaseId && snapshot.Selector == parent.Selector &&
                    snapshot.Resources.Length == parent.Manifest.Count &&
                    snapshot.Resources.Single(r => r.Id == id).ActiveDispatch != Guid.Empty;
            }
            if (request.Method == HttpMethod.Patch || request.Method == HttpMethod.Put && role == "notification-selected")
            {
                if (role != "notification-selected") throw new InvalidOperationException("foreign-notification-update");
                SelectedPatch = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
                // Separate controlled PUT and PATCH assumptions: each retains
                // the setup label and omitted mappings on an existing child.
                // Neither field is injected into the actual selected request.
                var changes = request.Method == HttpMethod.Put
                    ? SelectedPatch["properties"]!.AsObject() : SelectedPatch;
                var attributes = Resources[id]["properties"]!["destination"]!["properties"]!["deliveryAttributeMappings"]?.DeepClone();
                foreach (var field in changes)
                    Resources[id]["properties"]![field.Key] = field.Value?.DeepClone();
                if (changes["destination"]?["properties"] is JsonObject destination &&
                    !destination.ContainsKey("deliveryAttributeMappings") && attributes is not null)
                    Resources[id]["properties"]!["destination"]!["properties"]!["deliveryAttributeMappings"] = attributes;
                Resources[id]["properties"]!["provisioningState"] = "Updating";
                var response = Json(201, Resources[id].ToJsonString());
                response.Headers.TryAddWithoutValidation("Location", "https://management.azure.com" + id + "?api-version=2025-02-15");
                return response;
            }
            if (request.Method == HttpMethod.Put)
            {
                var resource = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!.AsObject();
                resource["id"] = id;
                resource["name"] = id[(id.LastIndexOf('/') + 1)..];
                resource["type"] = "Microsoft.EventGrid/eventSubscriptions";
                resource["properties"]!["topic"] = parent.VaultId;
                resource["properties"]!["provisioningState"] = "Succeeded";
                Resources.Add(id, resource);
                await Pause("transport");
                if (CreateFault == "lost") throw new IOException("controlled-notification-response-loss");
                var response = Json(201, resource.ToJsonString());
                response.Headers.TryAddWithoutValidation("Location", "https://management.azure.com" + id + "?api-version=2025-02-15");
                if (Barrier == "parser" || CreateFault == "dispose")
                {
                    response.Content.Dispose();
                    response.Content = new StreamContent(new OwnedNotificationBody(Encoding.UTF8.GetBytes(resource.ToJsonString()), this));
                    response.Content.Headers.ContentType = new("application/json");
                }
                return response;
            }
            if (request.Method == HttpMethod.Delete)
            {
                Resources.Remove(id);
                return Json(204, "");
            }
            await Pause(role == "notification-setup" ? "status" : "preflight");
            if (!Resources.TryGetValue(id, out var row))
            {
                var absent = Json(404, """{"error":{"code":"NotFound"}}""");
                if (Barrier == "read-body")
                {
                    absent.Content.Dispose();
                    absent.Content = new StreamContent(new OwnedNotificationBody(
                        Encoding.UTF8.GetBytes("""{"error":{"code":"NotFound"}}"""), this));
                    absent.Content.Headers.ContentType = new("application/json");
                }
                return absent;
            }
            if (ReadFault == "invalid-json") return Json(200, "{");
            var copy = row.DeepClone().AsObject();
            if (ReadFault == "foreign-topic") copy["properties"]!["topic"] = parent.VaultId + "-foreign";
            if (ReadFault == "foreign-label") copy["properties"]!["labels"] = new JsonArray("foreign-source-label");
            if (ReadFault == "missing-label") copy["properties"]!.AsObject().Remove("labels");
            if (ReadFault == "hidden-configuration")
                copy["properties"]!["destination"]!["properties"]!.AsObject().Remove("deliveryAttributeMappings");
            var read = Json(200, copy.ToJsonString());
            if (Barrier == "read-body" || ReadFault == "read-dispose")
            {
                read.Content.Dispose();
                read.Content = new StreamContent(new OwnedNotificationBody(Encoding.UTF8.GetBytes(copy.ToJsonString()), this));
                read.Content.Headers.ContentType = new("application/json");
            }
            return read;
        }

        internal async Task Pause(string point)
        {
            if (Barrier != point) return;
            Entered!.TrySetResult();
            await Resume!.Task;
        }

        public async ValueTask DisposeAsync()
        {
            Resume?.TrySetResult();
            try { await Source.DisposeAsync(); }
            finally
            {
                configuration.Dispose();
                foreach (var client in clients) client.Dispose();
            }
        }

        private static HttpResponseMessage Json(int status, string body) => new((HttpStatusCode)status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

        private sealed class OwnedNotificationBackend(OwnedNotifications fixture, string role) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                fixture.Respond(request, role, cancellationToken);
        }

        private sealed class OwnedNotificationBody(byte[] bytes, OwnedNotifications fixture) : MemoryStream(bytes)
        {
            private bool entered;
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (!entered)
                {
                    entered = true;
                    await fixture.Pause(fixture.Barrier == "read-body" ? "read-body" : "parser");
                }
                return base.Read(buffer.Span);
            }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
                ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
                if (disposing && (fixture.CreateFault == "dispose" || fixture.ReadFault == "read-dispose"))
                    throw new IOException("controlled-native-response-disposal");
            }
        }

        private sealed class OwnedNotificationCredential(OwnedNotifications fixture, string role) : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
                throw new InvalidOperationException("async-credential-required");
            public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
            {
                if (requestContext.Scopes.Length != 1 || requestContext.Scopes[0] != "https://management.azure.com/.default")
                    throw new InvalidOperationException("owned-notification-audience");
                await fixture.Pause("credential");
                return new(role, DateTimeOffset.MaxValue);
            }
        }
    }

    private sealed class OwnedNotificationClock : TimeProvider
    {
        internal bool ThrowOnCreate;
        private DateTimeOffset now = new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero);
        private readonly List<OwnedTimer> timers = [];
        public override DateTimeOffset GetUtcNow() => now;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            if (ThrowOnCreate) throw new InvalidOperationException("controlled-timer-failure");
            var timer = new OwnedTimer(callback, state, now + dueTime);
            timers.Add(timer);
            return timer;
        }
        internal void Advance(TimeSpan amount)
        {
            now += amount;
            foreach (var timer in timers.ToArray())
                if (!timer.Disposed && timer.Due <= now) { timer.Disposed = true; timer.Callback(timer.State); }
        }
        private sealed class OwnedTimer(TimerCallback callback, object? state, DateTimeOffset due) : ITimer
        {
            internal readonly TimerCallback Callback = callback;
            internal readonly object? State = state;
            internal readonly DateTimeOffset Due = due;
            internal bool Disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period) => throw new InvalidOperationException("one-shot-timer");
            public void Dispose() => Disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
