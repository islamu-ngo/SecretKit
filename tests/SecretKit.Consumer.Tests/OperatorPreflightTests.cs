using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;
using SecretKit.Samples.OperatorWorkflow;

namespace SecretKit.Consumer.Tests;

public sealed class OperatorPreflightTests
{
    [Test]
    [Arguments("unknown-policy", false, false)]
    [Arguments("null-policy", true, true)]
    [Arguments("", true, false)]
    [Arguments("lowercase-policy", true, false)]
    public async Task ManagementKeepsPolicyPresenceDistinctFromItsValue(string fault, bool present, bool nil)
    {
        using var provider = new OfflineProvider { Fault = fault };
        using var material = SecretMaterial.FromText("operator-admin");
        using var source = new InfisicalSuppliedTokenSource(material);
        using var transport = new ManagementTransport(OperatorWorkflow.Origin, OperatorWorkflow.Network(provider));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, source, OperatorWorkflow.Organization, "project");
        using var request = ProjectOperations.GetProject(OperatorWorkflow.Organization, "project");

        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(OperatorWorkflow.Organization, "project")));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.AutoCapitalization.IsPresent).IsEqualTo(present);
        await Assert.That(result.Value.AutoCapitalization.IsNull).IsEqualTo(nil);
        if (present && !nil)
            await Assert.That(result.Value.AutoCapitalization.Value).IsEqualTo(fault != "lowercase-policy");
    }

    [Test]
    [Arguments("managed", true)]
    [Arguments("unknown-rotation", null)]
    [Arguments("", false)]
    public async Task NativeInventoryPreservesRotationStateWithoutReadingValues(string fault, bool? expected)
    {
        using var provider = new OfflineProvider { Fault = fault };
        using var material = SecretMaterial.FromText("operator-runtime");
        using var source = new InfisicalSuppliedTokenSource(material);
        await using var client = new InfisicalClient(OperatorWorkflow.Origin, source, OperatorWorkflow.Network(provider));

        var result = await client.InspectNativeAsync(new(client.Authority, "project", "dev", "/"));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Entries[0].IsRotatedSecret).IsEqualTo(expected);
        await Assert.That(provider.RuntimeReads).IsEqualTo(0);
        await Assert.That(result.Value.Entries[0].Revision is not null).IsTrue();
    }

    [Test]
    public async Task ImportCandidatesHaveNoWritableReferenceAndDescribeAccessDoesNotProveDelivery()
    {
        using var provider = new OfflineProvider { Fault = "imported" };
        using var describeMaterial = SecretMaterial.FromText("describe-only");
        using var describe = new InfisicalSuppliedTokenSource(describeMaterial);
        await using var client = new InfisicalClient(OperatorWorkflow.Origin, describe, OperatorWorkflow.Network(provider));

        var inventory = await client.InspectNativeAsync(new(client.Authority, "project", "dev", "/", includeImports: true));
        var read = await client.ReadAsync(inventory.Value.Entries[0].Reference!);

        await Assert.That(inventory.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(inventory.Value.IsComplete).IsTrue();
        var imported = inventory.Value.Entries.Single(entry => entry.Origin == InfisicalInventoryOrigin.Imported);
        await Assert.That(imported.Reference is null).IsTrue();
        await Assert.That(imported.Revision is null).IsTrue();
        await Assert.That(imported.SourcePath).IsEqualTo("/source");
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(provider.ApplyAttempts).IsEqualTo(0);
    }
}
