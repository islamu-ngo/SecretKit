using System.Reflection;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using Provisioner = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    private static string DeclaredSubnet => "/subscriptions/" + Subscription.ToString("D") +
        "/resourceGroups/network-group/providers/Microsoft.Network/virtualNetworks/borrowed-network/subnets/borrowed-subnet";

    [Test]
    public async Task EndpointSlotAndBorrowedSubnetAreDeclaredBeforeAnyNativeSetup()
    {
        using var f = new Fixture(allowPurge: true);
        var plan = f.Plan(seedCanary: false, privateEndpoint: new(DeclaredSubnet));
        var root = f.Read();
        var declaration = root.PrivateEndpoint?.Declaration ?? throw new InvalidOperationException("missing-endpoint-declaration");
        await Assert.That(declaration.VaultId).IsEqualTo(plan.VaultId);
        await Assert.That(declaration.BorrowedSubnetId).IsEqualTo(DeclaredSubnet);
        await Assert.That(root.Resources.Count(r => !r.Borrowed)).IsEqualTo(4);
        await Assert.That(root.Resources.Count(r => r.Borrowed)).IsEqualTo(1);
        await Assert.That(root.Resources.Single(r => r.Id == declaration.EndpointId).Borrowed).IsFalse();
        await Assert.That(root.Resources.Single(r => r.Id == DeclaredSubnet).Borrowed).IsTrue();
        await Assert.That(root.Resources.Any(r => r.Id == declaration.ExpectedNicId)).IsFalse();
        await Assert.That(root.Resources.Single(r => r.Id == plan.SecretId).CleanupOnly).IsTrue();
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(0);
        await Assert.That(f.Source.OwnsPreparedPlan(plan)).IsFalse();
    }

    [Test]
    public async Task PreparedEndpointParentRequiresOriginalActualVaultSetupNotCopiedPlanFields()
    {
        using var f = new Fixture(allowPurge: true);
        var plan = f.Plan(seedCanary: false, privateEndpoint: new(DeclaredSubnet));
        await Assert.That(f.Source.OwnsPreparedPlan(plan)).IsFalse();
        var prepared = await f.Source.ProvisionAsync(plan);
        await Assert.That(prepared.State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Source.OwnsPreparedPlan(plan)).IsTrue();
        var copy = (Provisioner.Plan)typeof(object).GetMethod("MemberwiseClone", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(plan, null)!;
        await Assert.That(f.Source.OwnsPreparedPlan(copy)).IsFalse();
        await using var other = f.Reopen();
        await Assert.That(other.OwnsPreparedPlan(plan)).IsFalse();
        var root = f.Read();
        await Assert.That(root.Resources.Single(r => r.Id == root.PrivateEndpoint!.Declaration.EndpointId).CreateAttempted).IsFalse();
    }

    [Test]
    [Arguments("Absent", false)]
    [Arguments("Deleted", false)]
    [Arguments("Active", true)]
    public async Task DeclaredEndpointTopologyRejectsUnadmittedParentPreparations(string preparation, bool seed)
    {
        using var f = new Fixture(allowPurge: true);
        await Assert.That(() => f.Source.PlanFixture(Owner, f.Selector, Enum.Parse<Provisioner.Preparation>(preparation),
            [], seedCanary: seed, privateEndpoint: new(DeclaredSubnet))).Throws<InvalidOperationException>();
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(0);
    }

    [Test]
    [Arguments("url")]
    [Arguments("subscription")]
    [Arguments("kind")]
    [Arguments("empty")]
    [Arguments("encoded")]
    [Arguments("non-guid")]
    public async Task BorrowedEndpointSubnetMustBeAnExplicitSafeHostCoordinate(string fault)
    {
        using var f = new Fixture(allowPurge: true);
        string subnet = fault switch
        {
            "url" => "https://management.azure.com" + DeclaredSubnet,
            "subscription" => DeclaredSubnet.Replace(Subscription.ToString("D"), Tenant.ToString("D"), StringComparison.Ordinal),
            "kind" => DeclaredSubnet.Replace("virtualNetworks", "networkInterfaces", StringComparison.Ordinal),
            "empty" => "",
            "encoded" => DeclaredSubnet.Replace("borrowed-subnet", "borrowed%2Fsubnet", StringComparison.Ordinal),
            _ => DeclaredSubnet.Replace(Subscription.ToString("D"), "not-a-guid", StringComparison.Ordinal)
        };
        await Assert.That(() => f.Source.PlanFixture(Owner, f.Selector, Provisioner.Preparation.Active, [], seedCanary: false,
            privateEndpoint: new(subnet))).Throws<InvalidOperationException>();
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(0);
    }

    [Test]
    public async Task ConsumedPlanMetadataCannotCreateOriginalPreparedParentAuthority()
    {
        using var f = new Fixture(allowPurge: true);
        var plan = f.Plan(seedCanary: false, privateEndpoint: new(DeclaredSubnet));
        plan.Consumed = 1;
        await Assert.That(f.Source.OwnsPreparedPlan(plan)).IsFalse();
        await Assert.That(f.Backends.Sum(b => b.Requests.Count)).IsEqualTo(0);
    }

    [Test]
    public async Task ClosingOriginalPreparedParentRevokesEndpointSetupReadiness()
    {
        using var f = new Fixture(allowPurge: true);
        var plan = f.Plan(seedCanary: false, privateEndpoint: new(DeclaredSubnet));
        await Assert.That((await f.Source.ProvisionAsync(plan)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Source.OwnsPreparedPlan(plan)).IsTrue();
        f.Journal.Close(Owner, f.Selector);
        await Assert.That(f.Source.OwnsPreparedPlan(plan)).IsFalse();
    }
}
