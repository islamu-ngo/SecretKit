using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Direct typed SDK and source, deliberately bypassing Effects, Client and Trial.
public sealed class InfisicalGatewayPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary, bool Retain)> Cases() =>
        from row in InfisicalGatewayPermissionGateTests.SupportedCases()
        from retain in new[] { true, false }
        select (row.Operation, row.Variant, row.Boundary, retain);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public Task DirectSdkCalibratesBothObservedConfigIdHistories(string operation, string variant, string boundary, bool retain) =>
        Calibrate(operation, variant, boundary, retain);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalGatewayPermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task ConfiguredGenericCalibrationRetainsFactoryLabel(string operation, string boundary, int action)
    {
        await Assert.That(InfisicalGovernanceFamilies.Bindings[InfisicalGatewayPermissionGateTests.Execute].Variants.Contains("factory." + operation)).IsTrue();
        await Calibrate(operation, GatewayPermissionContract.Variant((GatewayPermissionAction)action), boundary, true);
    }
    private static async Task Calibrate(string operation, string variant, string boundary, bool retain)
    {
        var action = InfisicalGatewayPermissionGateTests.Action(variant);
        await using var provider = new InfisicalGatewayPermissionFixture(retainConfigId: retain); using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45)); using var cap = SecretMaterial.FromText("gateway-capability");
        var root = provider.Root(operation, action, boundary); var plan = new GatewayPermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new GatewayPermissionVerifier(root); var ownership = new GatewayPermissionOwnership(root, plan);
        GatewayPermissionIssued? issued = null;
        bool create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal), applied = boundary is not ("denied-authority" or "cancellation-boundary");
        var expected = new Dictionary<string, GatewayPermissionState>();
        try
        {
            Check(await source.StepAsync(root, GatewayPermissionStep.Reserve, cap, deadline.Token), GatewayPermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, GatewayPermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings); Check(opened, GatewayPermissionStep.Open);
            foreach (var state in opened.Storage.Payload.Content.Inventory) expected.Add(state.Row, state);
            await Witness(false);
            Check(await source.StepAsync(root, GatewayPermissionStep.Arm, null, deadline.Token), GatewayPermissionStep.Arm);
            var change = new OrganizationRoleChange(plan.Slug, plan.Slug, permissions: [new(OrganizationRoleSubject.Gateway,
                action == GatewayPermissionAction.Create ? OrganizationRoleAction.CreateGateways : OrganizationRoleAction.EditGateways)]);
            var original = await Original(create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change));
            var settled = await source.StepAsync(root, GatewayPermissionStep.Settle, null, deadline.Token); Check(settled, GatewayPermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var commit = settled.Policy.Payload.Content.Commits.Single(); var policy = commit.Policy;
                await Assert.That(commit.Request).IsEqualTo(settled.Ingress.Payload.Content.Single().Request);
                await Assert.That(policy.Actor).IsEqualTo(issued.Actors[0].Principal);
                await Assert.That(policy.Kind).IsEqualTo(MemberPermissionActorKind.User);
                await Assert.That(policy.Subject).IsEqualTo("gateway");
                await Assert.That(policy.Actions.SequenceEqual([GatewayPermissionContract.Wire(action)])).IsTrue();
                await Assert.That(policy.Names.Length).IsEqualTo(0); await Assert.That(policy.Role).IsEqualTo(plan.Slug);
                await Assert.That(policy.Resource).IsEqualTo(issued.Id(plan.PolicyKey)); await Assert.That(policy.Organization).IsEqualTo(root.Organization);
                if (create) _ = await Original(OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                    issued.Id(plan.ActorMembership(0)), role: plan.Slug), true);
            }
            var evidence = original.Native.Evidence;
            await Assert.That(evidence).IsEqualTo(boundary switch
            {
                "denied-authority" => DispatchEvidence.Rejected,
                "cancellation-boundary" => DispatchEvidence.NotDispatched,
                "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                _ => DispatchEvidence.Applied
            });
            await Witness(true); await Assert.That(original.Native.Evidence).IsEqualTo(evidence);
            await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        }
        finally
        {
            try { Check(await source.StepAsync(root, GatewayPermissionStep.Close, null, CancellationToken.None), GatewayPermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalGatewayPermissionEffectTests.Clean(provider);
        void Check(GatewayPermissionPacket packet, GatewayPermissionStep step)
        {
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
        }
        async Task<GatewayPermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
        {
            using (request)
            {
                var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
                var identity = setup ? NativeIdentityRole.Setup : boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = !setup && boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(identity)) : null;
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                using var loss = !setup && boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
                using var scope = loss?.Enter(); Task? signal = barrier?.Entered;
                var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(identity), root.Organization, request.Target.ProjectId);
                var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, cancellation.Token).AsTask();
                SecretOutcome<T>? result = null; bool cancelled = false;
                try
                {
                    if (signal is not null) { await signal.WaitAsync(deadline.Token); cancellation.Cancel(); barrier!.Release(); }
                    try { result = await execution; }
                    catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !deadline.IsCancellationRequested) { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue();
                    if (setup) await Assert.That(result is { IsSuccess: true }).IsTrue();
                    return new(receipt, result?.Status, cancelled, request.Target.SecondaryId ?? "");
                }
                finally
                {
                    cancellation.Cancel(); barrier?.Release();
                    try { result ??= await execution; } catch (OperationCanceledException) { }
                    if (result is { IsSuccess: true } completed && completed.Value is IDisposable owned) owned.Dispose();
                }
            }
        }
        async Task Witness(bool after)
        {
            var step = after ? GatewayPermissionStep.After : GatewayPermissionStep.Before;
            Check(await source.StepAsync(root, step, null, deadline.Token), step);
            var rows = plan.Rows.Where(r => r.Window == (after ? "after" : "before")).ToArray();
            var returned = new Dictionary<string, GatewaySummary>(); var submitted = new Dictionary<string, string>();
            foreach (var row in rows)
            {
                var actor = issued!.Actors[row.Actor]; string organization = issued.Id(row.Organization), target = issued.Id(row.Target);
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(NativeIdentityRole.Runtime));
                int version = row.Action == GatewayPermissionAction.Edit ? 2 : 1;
                string accounts = version == 1 ? "111111111111" : "222222222222";
                using var auth = GatewayAuthenticationInput.Aws(accounts, "arn:aws:iam::" + accounts + ":role/closed-witness-v" + version);
                using var request = version == 1 ? GatewayAdministrationOperations.Create(organization, new(row.Name, auth)) :
                    GatewayAdministrationOperations.Update(organization, target, new(row.Name + "-edited", auth));
                submitted.Add(row.Key, request.Target.SecondaryId!);
                var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
                var authority = new ManagementAuthority(client.Authority, tokens, organization);
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                bool allowed = row.Control == "selected" && (after && applied ? row.Action == action : !create && row.Action != action);
                await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                if (allowed) returned.Add(row.Key, result.Value);
            }
            var end = after ? GatewayPermissionStep.ObserveAfter : GatewayPermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            await Assert.That(packet.Access.Payload.Content.Length).IsEqualTo(rows.Length);
            for (int index = 0; index < rows.Length; index++)
            {
                var row = rows[index]; var actor = issued!.Actors[row.Actor]; var decision = packet.Access.Payload.Content[index];
                var ingress = packet.Ingress.Payload.Content.Single(e => e.Request == decision.Request);
                await Assert.That(ingress.BodyHash).IsEqualTo(submitted[row.Key]);
                await Assert.That(decision.Actor).IsEqualTo(actor.Principal); await Assert.That(decision.Kind).IsEqualTo(actor.Kind);
                await Assert.That(decision.CredentialId).IsEqualTo(actor.CredentialId); await Assert.That(decision.CredentialHash).IsEqualTo(actor.CredentialHash);
                await Assert.That(decision.Organization).IsEqualTo(issued.Id(row.Organization)); await Assert.That(decision.Target).IsEqualTo(issued.Id(row.Target));
                await Assert.That(packet.Issuer.Payload.Content.Credentials.Contains(new(actor.CredentialId, actor.Principal, actor.Kind, actor.Organization, actor.CredentialHash, actor.Owned))).IsTrue();
                var before = expected.GetValueOrDefault(row.Key); var transition = packet.Storage.Payload.Content.Changes.Single(c => c.Request == decision.Request);
                await Assert.That(transition.Before).IsEqualTo(before);
                if (returned.TryGetValue(row.Key, out var value))
                {
                    var next = transition.After!; int version = row.Action == GatewayPermissionAction.Edit ? 2 : 1;
                    await Assert.That(next.Target).IsEqualTo(issued.Id(row.Target)); await Assert.That(next.Organization).IsEqualTo(issued.Id(row.Organization));
                    await Assert.That(next.Name).IsEqualTo(row.Name + (version == 2 ? "-edited" : ""));
                    await Assert.That(next.Accounts).IsEqualTo(version == 1 ? "111111111111" : "222222222222");
                    await Assert.That(next.Principals).IsEqualTo("arn:aws:iam::" + next.Accounts + ":role/closed-witness-v" + version);
                    await Assert.That(value.Id).IsEqualTo(next.Target); await Assert.That(value.Name).IsEqualTo(next.Name);
                    await Assert.That(value.Authentication.Method).IsEqualTo(GatewayAuthenticationMethod.Aws);
                    await Assert.That(value.Authentication.Id).IsEqualTo(next.ConfigId);
                    await Assert.That(value.Authentication.AllowedAccountIds).IsEqualTo(next.Accounts);
                    await Assert.That(value.Authentication.AllowedPrincipalArns).IsEqualTo(next.Principals);
                    if (before is not null)
                    {
                        await Assert.That(next.ConfigId == before.ConfigId).IsEqualTo(retain);
                        await Assert.That(next.ConfigRevision != before.ConfigRevision).IsTrue();
                        await Assert.That(packet.Configuration.Payload.Content.Retired.Any(r => r.Gateway == next.Target && r.Revision == before.ConfigRevision && r.Request == decision.Request)).IsTrue();
                    }
                    expected[row.Key] = next;
                }
                else await Assert.That(transition.After).IsEqualTo(before);
            }
            await Assert.That(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(expected.Values.OrderBy(s => s.Row))).IsTrue();
            // Complete inventory is independently signed. Get only calibrates each fresh projection.
            foreach (var state in expected.Values)
            {
                var client = env.CreateManagementClient(); using var get = GatewayAdministrationOperations.Get(state.Organization, state.Target);
                var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), state.Organization);
                var read = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: deadline.Token);
                await Assert.That(read.IsSuccess).IsTrue(); await Assert.That(read.Value.Id).IsEqualTo(state.Target);
                await Assert.That(read.Value.Name).IsEqualTo(state.Name); await Assert.That(read.Value.Authentication.Id).IsEqualTo(state.ConfigId);
                await Assert.That(read.Value.Authentication.AllowedAccountIds).IsEqualTo(state.Accounts);
                await Assert.That(read.Value.Authentication.AllowedPrincipalArns).IsEqualTo(state.Principals);
            }
        }
    }
}
