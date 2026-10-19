using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthTemplatePermissionScopeTests
{
    public static IEnumerable<(string Operation, bool Attach)> Cases() =>
        from op in AuthTemplatePermissionContract.Operations from attach in new[] { false, true } select (op, attach);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ListAndAttachRemainIndependentAndSdkOrganizationDoesNotSelectRemoteScope(string operation, bool attach)
    {
        var action = attach ? AuthTemplatePermissionAction.Attach : AuthTemplatePermissionAction.List;
        await using var fixture = new InfisicalAuthTemplatePermissionFixture();
        using var env = fixture.Environment(operation, action);
        var root = fixture.Root(operation, action, "independent-effect");
        using var capability = SecretMaterial.FromText("auth-template-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        AuthTemplatePermissionTrial? retained = null;
        try
        {
            var trial = await AuthTemplatePermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
            await AuthTemplatePermissionEffects.WitnessAsync(env, trial, false, deadline.Token);
            await trial.ArmAsync(deadline.Token);
            await trial.SettleAsync(await AuthTemplatePermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token), deadline.Token);
            await AuthTemplatePermissionEffects.ActivateAsync(env, trial, deadline.Token);
            await AuthTemplatePermissionEffects.WitnessAsync(env, trial, true, deadline.Token);
            var client = env.CreateManagementClient();
            using (var tokens = new MemberPermissionTokens(trial.Issued.Actors[0].Credential))
            using (var get = IdentityTemplateOperations.GetIdentityTemplate(root.Organization, trial.Issued.Id("selected")))
            {
                var authority = new ManagementAuthority(client.Authority, tokens, root.Organization);
                var result = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: deadline.Token);
                await Assert.That(result.Status).IsEqualTo(attach ? SecretStatus.Denied : SecretStatus.Success);
                if (!attach) await Assert.That(result.Value.Id).IsEqualTo(trial.Issued.Id("selected"));
            }
            using (var tokens = new MemberPermissionTokens(trial.Issued.Actors[0].Credential))
            using (var usage = IdentityTemplateOperations.GetIdentityTemplateUsage(root.Organization, trial.Issued.Id("selected")))
            {
                var authority = new ManagementAuthority(client.Authority, tokens, root.Organization);
                var result = await client.ExecuteAsync(usage, authority, authority.IssueGrant(usage.OperationId, usage.Target), cancellationToken: deadline.Token);
                await Assert.That(result.Status).IsEqualTo(attach ? SecretStatus.Denied : SecretStatus.Success);
                if (!attach) await Assert.That(result.Value.IsComplete && result.Value.Items.Count == 0).IsTrue();
            }
            string foreign = trial.Issued.Id(AuthTemplatePermissionPlan.OtherOrganization);
            using (var tokens = new MemberPermissionTokens(trial.Issued.Actors[0].Credential))
            using (var misleading = attach ? IdentityTemplateOperations.ListIdentityTemplates(foreign, IdentityTemplateAuthMethod.Kubernetes) :
                IdentityTemplateOperations.SearchIdentityTemplates(foreign, limit: 100))
            {
                var authority = new ManagementAuthority(client.Authority, tokens, foreign);
                var result = await client.ExecuteAsync(misleading, authority, authority.IssueGrant(misleading.OperationId, misleading.Target), cancellationToken: deadline.Token);
                // The provider still returns the actor's organization; SDK response
                // validation rejects the foreign organization assertion.
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
            }
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        var packet = fixture.ClosedPacket!;
        var last = packet.Values<AuthTemplatePermissionRequest>(AuthTemplatePermissionJournal.Ingress, "request").Last();
        await Assert.That(last.Organization).IsEqualTo(root.Organization);
        var capture = packet.Values<AuthTemplatePermissionCollection>(AuthTemplatePermissionJournal.Collection, "read").Last();
        await Assert.That(capture.Rows.Length == 2 && capture.Rows.All(s => s.Organization == root.Organization)).IsTrue();
        var policies = packet.Values<AuthTemplatePermissionPolicyChange>(AuthTemplatePermissionJournal.Policy, "change");
        await Assert.That(policies.Where(p => p.After is not null).All(p => p.After!.Actions.Length <= 1)).IsTrue();
        await InfisicalAuthTemplatePermissionEffectTests.Clean(fixture);
    }
}
