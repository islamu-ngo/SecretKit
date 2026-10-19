using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProjectFamilyTests
{
    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Admin = "00000000-0000-0000-0000-000000000002";
    private const string Observer = "00000000-0000-0000-0000-000000000003";
    private const string Runtime = "00000000-0000-0000-0000-000000000004";
    private const string User = "00000000-0000-0000-0000-000000000005";
    private const string SecondUser = "00000000-0000-0000-0000-000000000006";
    private const string OwnerOrg = "00000000-0000-0000-0000-000000000010";
    private const string OwnerSetup = "00000000-0000-0000-0000-000000000011";
    private const string OwnerObserver = "00000000-0000-0000-0000-000000000012";
    private const string Setup = "00000000-0000-0000-0000-000000000013";
    private const string Denied = "00000000-0000-0000-0000-000000000014";
    private const string Date = "2026-10-12T00:00:00.000Z";

    [Test]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "good")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "good")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "good")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "good")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "early-activation")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "early-activation")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "early-activation")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "early-activation")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "delayed-activation")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "delayed-activation")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "delayed-activation")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "delayed-activation")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "ignored-expiry")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "ignored-expiry")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "ignored-expiry")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "ignored-expiry")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "expired-token")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "expired-token")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "expired-token")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "expired-token")]
    public async Task OrganizationGroupTemporalFixtureClockUsesActualSdkAuthorization(string method, string policy, string fault)
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("ownership-temporal-" + fault, clock);
        var source = new ControlledOrganizationExpiryObserver(backend, clock, fault);
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true, organizationTemporalPolicy: policy);
        ManagementClient client = environment.CreateManagementClient();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        CancellationToken token = deadline.Token;
        async ValueTask<T> Need<T>(ManagementRequest<T> request, string credential, string organization) where T : notnull
        {
            var result = await OwnershipExecute(client, request, credential, organization, token, request.Target.ProjectId);
            await Assert.That(result.IsSuccess).IsTrue();
            return result.Value;
        }
        GroupMetadata group = await Need(ScopedAccessOperations.CreateGroup(OwnerOrg, "temporal-parent",
            "temporal-parent", "no-access"), "owner-setup", OwnerOrg);
        MembershipIdentifier link = await Need(ScopedAccessOperations.AddGroupIdentity(OwnerOrg, group.Id, Runtime),
            "owner-setup", OwnerOrg);
        MembershipSummary owner = await Need(MembershipOperations.GetOrganizationGroup(OwnerOrg, group.Id),
            "owner-observer", OwnerOrg);
        string ownerRoleId = owner.Roles.Value.Single().Id;
        RoleSummary role = await Need(RoleChangeOperations.CreateOrganizationRole(Org,
            new("temporary-reader", "temporary-reader",
                permissions: [new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)])), "setup", Org);
        MembershipSummary? before = method == "UpdateOrganizationGroupRoles" ?
            await Need(MembershipOperations.AddOrganizationGroup(Org, group.Id, [new("no-access")]), "setup", Org) : null;
        // A separate owned project viewer grant verifies the same runtime token
        // without supplying another organization Groups.read permission.
        string control = (await Need(ProjectOperations.CreateProject(Org, "control", "control",
            createDefaultEnvironments: false), "setup", Org)).Id;
        await Need(MembershipOperations.AddProjectIdentity(Org, control, Runtime,
            new MembershipRoleSelection(roles: [new("viewer")])), "setup", Org);
        await using InfisicalClient setup = environment.CreateClient(NativeIdentityRole.Setup);
        using SecretMaterial material = SecretMaterial.FromText("offline-org-temporal-control");
        var address = new InfisicalSecretAddress(control, "witness", "/", "org-temporal-control");
        var reference = new SecretReference(setup.Authority, address);
        await Assert.That((await setup.CreateAsync(reference, material, new MutationReceipt(reference), token)).IsSuccess).IsTrue();
        var attempt = new OrganizationGroupExpiryAttempt(Guid.NewGuid().ToString(), "fixture-" + method, method,
            "fixture-v1", Backend.AuthenticatedOrganizationScopes(), group.Id, owner.Id, link.Id, role.Id, role.Slug,
            before?.Id, MembershipExpirySource.ControlledFixture, Enum.Parse<OrganizationGroupExpiredMetadata>(policy));
        OrganizationGroupExpiryArm arm = await source.ArmAsync(new(attempt, "1m", 5), token);
        Task<OrganizationGroupExpiryFence> terminal = source.CompleteAsync(arm, token).AsTask();
        await Assert.That(terminal.IsCompleted).IsFalse();
        MembershipRole[] roles = [new("no-access"), new(role.Slug, arm.StartsAt, "1m")];
        MembershipSummary accepted = await Need(method == "AddOrganizationGroup" ?
            MembershipOperations.AddOrganizationGroup(Org, group.Id, roles) :
            MembershipOperations.UpdateOrganizationGroupRoles(Org, group.Id, roles), "administrative", Org);
        OrganizationGroupExpiryFence fence = await terminal;
        await Assert.That(fence.Disposition).IsEqualTo(MembershipExpiryDisposition.Applied);
        await Assert.That(fence.MutationOrganizationId).IsEqualTo(Org);
        await Assert.That(fence.MutationIdentityId).IsEqualTo(Admin);
        await Assert.That(fence.TargetMembershipId).IsEqualTo(accepted.Id);
        // PATCH recreates role assignment IDs. Pin the accepted baseline rather
        // than the obsolete before-update assignment.
        string baselineId = accepted.Roles.Value.Single(r => r.IsTemporary != true).Id;
        if (before is not null)
            await Assert.That(baselineId == before.Roles.Value.Single().Id).IsFalse();
        JsonNode sent = backend.OrganizationTemporalRequests.Single()["roles"]!.AsArray()
            .Single(r => r!["isTemporary"]?.GetValue<bool>() == true)!;
        await Assert.That(sent["temporaryAccessStartTime"]!.GetValue<string>().EndsWith('Z')).IsTrue();
        foreach (MembershipExpiryPhase phase in Enum.GetValues<MembershipExpiryPhase>())
        {
            int callbacks = 0;
            var observation = await source.ObserveAsync(fence, phase, async ct =>
            {
                callbacks++;
                bool active = phase == MembershipExpiryPhase.Active && fault != "delayed-activation" ||
                    phase == MembershipExpiryPhase.BeforeActivation && fault == "early-activation" ||
                    phase == MembershipExpiryPhase.Expired && fault == "ignored-expiry";
                var runtime = await OwnershipExecute(client, ScopedAccessOperations.GetGroup(OwnerOrg, group.Id),
                    "runtime", OwnerOrg, ct);
                await Assert.That(runtime.Status).IsEqualTo(active ? SecretStatus.Success : SecretStatus.Denied);
                if (active) await Assert.That(runtime.Value.Id).IsEqualTo(group.Id);
                await Assert.That((await OwnershipExecute(client, ScopedAccessOperations.GetGroup(OwnerOrg, group.Id),
                    "denied", OwnerOrg, ct)).Status).IsEqualTo(SecretStatus.Denied);
                await Need(ScopedAccessOperations.GetGroup(OwnerOrg, group.Id), "owner-observer", OwnerOrg);
                await Need(ScopedAccessOperations.GetGroup(OwnerOrg, group.Id), "observer", OwnerOrg);
                MembershipSummary metadata = await Need(MembershipOperations.GetOrganizationGroup(Org, group.Id), "observer", Org);
                await Assert.That(metadata.Id).IsEqualTo(fence.TargetMembershipId);
                await Assert.That(metadata.Group!.OrganizationId.Value).IsEqualTo(OwnerOrg);
                await Assert.That(metadata.Roles.Value.Single(r => r.IsTemporary != true).Id).IsEqualTo(baselineId);
                bool removed = phase == MembershipExpiryPhase.Expired && policy == "RemovedAssignment" && fault != "ignored-expiry";
                await Assert.That(metadata.Roles.Value.Count).IsEqualTo(removed ? 1 : 2);
                if (!removed)
                {
                    ProjectMembershipRole temporary = metadata.Roles.Value.Single(r => r.IsTemporary == true);
                    await Assert.That(temporary.Id).IsEqualTo(fence.TemporaryAssignmentId);
                    await Assert.That(temporary.Role).IsEqualTo("custom");
                    await Assert.That(temporary.CustomRoleId).IsEqualTo(role.Id);
                    await Assert.That(temporary.CustomRoleSlug).IsEqualTo(role.Slug);
                    await Assert.That(temporary.Mode).IsEqualTo("relative");
                    await Assert.That(temporary.Range).IsEqualTo("1m");
                    await Assert.That(DateTimeOffset.Parse(temporary.StartsAt!)).IsEqualTo(arm.StartsAt);
                    await Assert.That(DateTimeOffset.Parse(temporary.EndsAt!)).IsEqualTo(arm.EndsAt);
                }
                MembershipSummary unchanged = await Need(MembershipOperations.GetOrganizationGroup(OwnerOrg, group.Id),
                    "owner-observer", OwnerOrg);
                await Assert.That(unchanged.Id).IsEqualTo(owner.Id);
                await Assert.That(unchanged.Roles.Value.Single().Id).IsEqualTo(ownerRoleId);
                await Assert.That(unchanged.Roles.Value.Single().Role).IsEqualTo("no-access");
                var links = await Need(ScopedAccessOperations.ListGroupMembers(OwnerOrg, group.Id), "owner-observer", OwnerOrg);
                await Assert.That(links.IsComplete && links.Items.Count == 1 &&
                    links.Items.Single().Id == link.Id && links.Items.Single().PrincipalId == Runtime).IsTrue();
                await using InfisicalClient reader = environment.CreateRuntimeClient();
                var controlRead = await reader.ReadAsync(new(reader.Authority, address), ct);
                bool expiredToken = phase == MembershipExpiryPhase.Expired && fault == "expired-token";
                await Assert.That(controlRead.IsSuccess).IsEqualTo(!expiredToken);
                if (controlRead.IsSuccess)
                {
                    using SecretRead value = controlRead.Value;
                    await Assert.That(value.Material.ExportCharacters().AsSpan().SequenceEqual("offline-org-temporal-control")).IsTrue();
                }
                return metadata.Id;
            }, token);
            await Assert.That(callbacks).IsEqualTo(1);
            await Assert.That(observation.Window.EventObserved && observation.Window.Authoritative).IsTrue();
            await Assert.That(observation.Window.OpenedAt).IsEqualTo(clock.GetUtcNow());
            await Assert.That(observation.Window.RuntimeOrganizationId).IsEqualTo(Org);
            await Assert.That(observation.Window.RuntimeIdentityId).IsEqualTo(Runtime);
            await Assert.That(observation.Sample).IsEqualTo(accepted.Id);
        }
        var cleanup = await source.CloseAsync(attempt, token);
        await Assert.That(cleanup.Closed && cleanup.LateCreationFenced && cleanup.MutationSettled &&
            cleanup.InventoryComplete && cleanup.RemainingRegistrations == 0 && cleanup.PendingDeliveries == 0).IsTrue();
        await Need(MembershipOperations.RemoveOrganizationGroup(Org, group.Id), "setup", Org);
        await Need(ScopedAccessOperations.DeleteGroup(OwnerOrg, group.Id), "owner-setup", OwnerOrg);
        await Need(ScopedAccessOperations.DeleteOrganizationRole(Org, role.Id), "setup", Org);
        await Need(ProjectOperations.DeleteProject(Org, control), "setup", Org);
        await Assert.That(backend.GroupCount + backend.OwnerAssignmentCount + backend.OwnerRuntimeLinkCount +
            backend.TargetLinkCount + backend.OrganizationRoleCount + backend.ProjectCount).IsEqualTo(0);
        await Assert.That(backend.OwnerUnlinkDispatches).IsEqualTo(0);
    }

    [Test]
    public async Task OrganizationGroupTemporalFixtureLostArmClosesOriginalAttemptWithoutCompletion()
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("ownership-temporal-good", clock);
        var source = new ControlledOrganizationExpiryObserver(backend, clock, "lost-arm");
        using NativeEnvironment environment = Environment(backend.Origin);
        ManagementClient management = environment.CreateManagementClient();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        CancellationToken token = deadline.Token;
        GroupMetadata group = (await OwnershipExecute(management,
            ScopedAccessOperations.CreateGroup(OwnerOrg, "lost-arm", "lost-arm", "no-access"),
            "owner-setup", OwnerOrg, token)).Value;
        MembershipIdentifier link = (await OwnershipExecute(management,
            ScopedAccessOperations.AddGroupIdentity(OwnerOrg, group.Id, Runtime), "owner-setup", OwnerOrg, token)).Value;
        MembershipSummary owner = (await OwnershipExecute(management,
            MembershipOperations.GetOrganizationGroup(OwnerOrg, group.Id), "owner-observer", OwnerOrg, token)).Value;
        RoleSummary role = (await OwnershipExecute(management, RoleChangeOperations.CreateOrganizationRole(Org,
            new("lost-arm-reader", "lost-arm-reader",
                permissions: [new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)])),
            "setup", Org, token)).Value;
        var attempt = new OrganizationGroupExpiryAttempt(Guid.NewGuid().ToString(), "lost-arm", "AddOrganizationGroup",
            "fixture-v1", Backend.AuthenticatedOrganizationScopes(), group.Id, owner.Id,
            link.Id, role.Id, role.Slug, null, MembershipExpirySource.ControlledFixture,
            OrganizationGroupExpiredMetadata.RetainedInactive);
        bool lost = false;
        try { await source.ArmAsync(new(attempt, "1m", 5), CancellationToken.None); }
        catch (IOException) { lost = true; }
        await Assert.That(lost).IsTrue();
        await Assert.That(source.Registrations).IsEqualTo(1);
        var closed = await source.CloseAsync(attempt, CancellationToken.None);
        await Assert.That(closed.Attempt).IsEqualTo(attempt);
        await Assert.That(closed.Closed && closed.LateCreationFenced && closed.MutationSettled &&
            closed.InventoryComplete && closed.RemainingRegistrations == 0 && closed.PendingDeliveries == 0).IsTrue();
        using var client = new HttpClient { BaseAddress = backend.Origin };
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/organizations/memberships/groups/" + attempt.GroupId);
        request.Headers.Authorization = new("Bearer", "administrative");
        request.Content = new StringContent(new JsonObject
        {
            ["roles"] = new JsonArray(new JsonObject
            {
                ["role"] = "reader",
                ["isTemporary"] = true,
                ["temporaryMode"] = "relative",
                ["temporaryRange"] = "1m",
                ["temporaryAccessStartTime"] = source.Arm!.StartsAt.ToString("O")
            })
        }.ToJsonString(), Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, deadline.Token);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
        await Assert.That(source.CompleteCalls + source.AppliedMutations).IsEqualTo(0);
        await Assert.That(backend.TargetLinkCount).IsEqualTo(0);
        await OwnershipExecute(management, ScopedAccessOperations.DeleteGroup(OwnerOrg, group.Id), "owner-setup", OwnerOrg, token);
        await OwnershipExecute(management, ScopedAccessOperations.DeleteOrganizationRole(Org, role.Id), "setup", Org, token);
        await Assert.That(backend.GroupCount + backend.OrganizationRoleCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("AddOrganizationGroup", "selected-contract")]
    [Arguments("AddOrganizationGroup", "independent-effect")]
    [Arguments("AddOrganizationGroup", "denied-authority")]
    [Arguments("AddOrganizationGroup", "cancellation-boundary")]
    [Arguments("AddOrganizationGroup", "lost-response-no-replay")]
    [Arguments("UpdateOrganizationGroupRoles", "selected-contract")]
    [Arguments("UpdateOrganizationGroupRoles", "independent-effect")]
    [Arguments("UpdateOrganizationGroupRoles", "denied-authority")]
    [Arguments("UpdateOrganizationGroupRoles", "cancellation-boundary")]
    [Arguments("UpdateOrganizationGroupRoles", "lost-response-no-replay")]
    [Arguments("GetOrganizationGroup", "selected-contract")]
    [Arguments("ListOrganizationGroups", "selected-contract")]
    [Arguments("RemoveOrganizationGroup", "independent-effect")]
    public async Task OrganizationGroupOwnershipRequiresParentTopology(string method, string caseName)
    {
        await using var backend = new Backend("ownership-good");
        using NativeEnvironment environment = Environment(backend.Origin);
        string variant = method switch
        {
            "GetOrganizationGroup" => "selector.exact",
            "ListOrganizationGroups" => "orderBy.Name",
            "RemoveOrganizationGroup" => "input.organizationId-groupId",
            _ => "roles.permanent"
        };
        NativeCaseResult result = await RunAsync(environment, Definition("MembershipOperations." + method, variant, caseName));
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(backend.OwnerGroupCreates).IsGreaterThan(0);
        await Assert.That(backend.OwnerUnlinkDispatches).IsEqualTo(0);
        await Assert.That(backend.GroupCount + backend.TargetLinkCount + backend.OrganizationRoleCount).IsEqualTo(0);
        await Assert.That(backend.OwnerAssignmentCount + backend.OwnerRuntimeLinkCount).IsEqualTo(0);
        if (method is not ("AddOrganizationGroup" or "UpdateOrganizationGroupRoles") ||
            caseName is not ("denied-authority" or "cancellation-boundary"))
            await Assert.That(backend.RuntimeGroupAllowed).IsGreaterThan(0);
        if (method is "AddOrganizationGroup" or "UpdateOrganizationGroupRoles")
        {
            await Assert.That(backend.RuntimeGroupDenied).IsGreaterThan(0);
            await Assert.That(backend.TargetGroupMutations).IsEqualTo(
                caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        }
        await Assert.That(backend.OrganizationDispatches.Where(d => d.Method is "POST" or "PATCH" &&
            d.Path.StartsWith("/api/v1/organizations/", StringComparison.Ordinal))
            .All(d => d.Credential is "setup" or "administrative")).IsTrue();
    }

    [Test]
    [Arguments("missing-profile")]
    [Arguments("missing-organizationId")]
    [Arguments("missing-setupIdentityId")]
    [Arguments("missing-observerIdentityId")]
    [Arguments("missing-setupToken")]
    [Arguments("missing-observerToken")]
    [Arguments("blank-setupToken")]
    [Arguments("blank-observerToken")]
    [Arguments("blank-organizationId")]
    [Arguments("blank-setupIdentityId")]
    [Arguments("blank-observerIdentityId")]
    [Arguments("same-organization")]
    [Arguments("same-principal")]
    [Arguments("same-token")]
    [Arguments("setup-admin-principal")]
    [Arguments("observer-runtime-principal")]
    [Arguments("setup-observer-principal")]
    [Arguments("setup-runtime-principal")]
    [Arguments("observer-admin-principal")]
    [Arguments("observer-observer-principal")]
    [Arguments("setup-target-token")]
    [Arguments("observer-target-token")]
    [Arguments("setup-alias-setup")]
    [Arguments("setup-alias-administrative")]
    [Arguments("setup-alias-observer")]
    [Arguments("setup-alias-runtime")]
    [Arguments("setup-alias-denied")]
    [Arguments("observer-alias-setup")]
    [Arguments("observer-alias-administrative")]
    [Arguments("observer-alias-observer")]
    [Arguments("observer-alias-runtime")]
    [Arguments("observer-alias-denied")]
    [Arguments("nonobject-profile")]
    [Arguments("nonstring-organizationId")]
    [Arguments("nonstring-setupIdentityId")]
    [Arguments("nonstring-observerIdentityId")]
    [Arguments("nonstring-setupToken")]
    [Arguments("nonstring-observerToken")]
    [Arguments("invalid-organizationId")]
    [Arguments("invalid-setupIdentityId")]
    [Arguments("invalid-observerIdentityId")]
    public async Task OrganizationGroupOwnershipRejectsInvalidProfileBeforeOwnership(string fault)
    {
        await using var backend = new Backend("ownership-good");
        using NativeEnvironment environment = Environment(backend.Origin, ownerFault: fault);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipOperations.AddOrganizationGroup", "roles.permanent"));
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.OwnerGroupCreates).IsEqualTo(0);
        await Assert.That(backend.OrganizationDispatches.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("wrong-owner")]
    [Arguments("wrong-context")]
    [Arguments("owner-resource-substitution")]
    [Arguments("target-assignment-substitution")]
    [Arguments("group-cleanup")]
    [Arguments("role-cleanup")]
    [Arguments("unlink-cleanup")]
    [Arguments("link-drift")]
    public async Task OrganizationGroupOwnershipFaultsCannotCertifyEarlyFailure(string fault)
    {
        await using var backend = new Backend("ownership-" + fault);
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipOperations.UpdateOrganizationGroupRoles", "roles.permanent", "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        // An unrelated setup failure is not evidence that the observer caught this fault.
        await Assert.That(backend.OwnerGroupCreates).IsGreaterThan(0);
        await Assert.That(backend.FaultApplied).IsTrue();
        await Assert.That(backend.OwnerUnlinkDispatches).IsEqualTo(0);
        if (fault.EndsWith("cleanup", StringComparison.Ordinal))
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }

    [Test]
    [Arguments("AddOrganizationGroup")]
    [Arguments("UpdateOrganizationGroupRoles")]
    public async Task OrganizationGroupOwnershipTemporalProfileMustBeExplicit(string method)
    {
        await using var backend = new Backend("ownership-good");
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipOperations." + method, "roles.relative-time"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.OrganizationDispatches.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OrganizationGroupOwnershipNativeShapeUsesBearerContextAndScopedCleanup()
    {
        await using var backend = new Backend("ownership-good");
        using NativeEnvironment environment = Environment(backend.Origin);
        ManagementClient client = environment.CreateManagementClient();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        CancellationToken token = deadline.Token;
        async ValueTask<SecretOutcome<T>> Call<T>(ManagementRequest<T> request, string credential,
            string organization) where T : notnull =>
            await OwnershipExecute(client, request, credential, organization, token);
        GroupMetadata group = (await Call(ScopedAccessOperations.CreateGroup(OwnerOrg, "parent", "parent", "no-access"),
            "owner-setup", OwnerOrg)).Value;
        await Assert.That(group.OrganizationId).IsEqualTo(OwnerOrg);
        MembershipIdentifier runtimeLink = (await Call(ScopedAccessOperations.AddGroupIdentity(OwnerOrg, group.Id, Runtime),
            "owner-setup", OwnerOrg)).Value;
        var ownerMembership = (await Call(MembershipOperations.GetOrganizationGroup(OwnerOrg, group.Id),
            "owner-observer", OwnerOrg)).Value;
        await Assert.That(ownerMembership.Group!.OrganizationId.Value).IsEqualTo(OwnerOrg);
        await Assert.That((await Call(MembershipOperations.GetOrganizationGroup(Org, group.Id),
            "observer", Org)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That((await Call(ScopedAccessOperations.GetGroup(OwnerOrg, group.Id),
            "runtime", OwnerOrg)).Status).IsEqualTo(SecretStatus.Denied);
        RoleSummary custom = (await Call(RoleChangeOperations.CreateOrganizationRole(Org,
            new("target-reader", "target-reader", permissions: [new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)])),
            "setup", Org)).Value;
        var added = (await Call(MembershipOperations.AddOrganizationGroup(Org, group.Id, [new("no-access")]),
            "administrative", Org)).Value;
        await Assert.That(added.Id == ownerMembership.Id).IsFalse();
        await Assert.That(added.Group!.OrganizationId.Value).IsEqualTo(OwnerOrg);
        await Assert.That((await Call(ScopedAccessOperations.GetGroup(OwnerOrg, group.Id),
            "runtime", OwnerOrg)).Status).IsEqualTo(SecretStatus.Denied);
        var updated = (await Call(MembershipOperations.UpdateOrganizationGroupRoles(Org, group.Id, [new(custom.Slug)]),
            "administrative", Org)).Value;
        await Assert.That(updated.Id).IsEqualTo(added.Id);
        await Assert.That(updated.Roles.Value.Single().Role).IsEqualTo("custom");
        await Assert.That(updated.Roles.Value.Single().CustomRoleId).IsEqualTo(custom.Id);
        await Assert.That(updated.Roles.Value.Single().CustomRoleSlug).IsEqualTo(custom.Slug);
        await Assert.That((await Call(ScopedAccessOperations.GetGroup(OwnerOrg, group.Id),
            "runtime", OwnerOrg)).Value.Id).IsEqualTo(group.Id);
        var target = (await Call(MembershipOperations.GetOrganizationGroup(Org, group.Id), "observer", Org)).Value;
        await Assert.That(target.Id).IsEqualTo(added.Id);
        var inventory = (await Call(MembershipOperations.ListOrganizationGroups(Org), "observer", Org)).Value;
        await Assert.That(inventory.IsComplete && inventory.Items.Single().Id == added.Id).IsTrue();
        var links = (await Call(ScopedAccessOperations.ListGroupMembers(OwnerOrg, group.Id), "owner-observer", OwnerOrg)).Value;
        await Assert.That(links.IsComplete && links.Items.Count == 1 &&
            links.Items.Single().Kind == GroupMemberKind.MachineIdentity &&
            links.Items.Single().PrincipalId == Runtime && links.Items.Single().Id == runtimeLink.Id).IsTrue();
        await Assert.That(runtimeLink.Id == group.Id).IsFalse();

        // These grants are valid host intent. The provider still sees only the
        // bearer context, so a target token cannot acquire root write authority.
        await Assert.That((await Call(ScopedAccessOperations.DeleteGroup(OwnerOrg, group.Id),
            "administrative", OwnerOrg)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((await Call(RoleChangeOperations.CreateOrganizationRole(Org,
            new("wrong", "wrong", permissions: [new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)])),
            "owner-setup", Org)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((await Call(MembershipOperations.AddOrganizationGroup(Org, group.Id, [new("viewer")]),
            "owner-setup", Org)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((await Call(ScopedAccessOperations.DeleteGroup(OwnerOrg, group.Id),
            "owner-observer", OwnerOrg)).Status).IsEqualTo(SecretStatus.Denied);
        // A different host OrganizationId cannot alter the authenticated context.
        var hostOwnerIntent = (await Call(MembershipOperations.GetOrganizationGroup(OwnerOrg, group.Id),
            "observer", OwnerOrg)).Value;
        await Assert.That(hostOwnerIntent.Id).IsEqualTo(added.Id);
        await Assert.That((await Call(MembershipOperations.RemoveOrganizationGroup(Org, group.Id),
            "setup", Org)).Value.Id).IsEqualTo(added.Id);
        await Assert.That((await Call(ScopedAccessOperations.GetGroup(OwnerOrg, group.Id),
            "runtime", OwnerOrg)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((await Call(MembershipOperations.GetOrganizationGroup(OwnerOrg, group.Id),
            "owner-observer", OwnerOrg)).Value.Id).IsEqualTo(ownerMembership.Id);
        await Assert.That((await Call(ScopedAccessOperations.DeleteGroup(OwnerOrg, group.Id),
            "owner-setup", OwnerOrg)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That((await Call(ScopedAccessOperations.GetGroup(OwnerOrg, group.Id),
            "owner-observer", OwnerOrg)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That((await Call(ScopedAccessOperations.DeleteOrganizationRole(Org, custom.Id),
            "setup", Org)).IsSuccess).IsTrue();
        await Assert.That(backend.OwnerUnlinkDispatches).IsEqualTo(0);
        await Assert.That(backend.GroupCount + backend.OrganizationRoleCount + backend.TargetLinkCount).IsEqualTo(0);
        await Assert.That(backend.OwnerAssignmentCount + backend.OwnerRuntimeLinkCount).IsEqualTo(0);
    }

    [Test]
    public async Task OrganizationGroupOwnershipNativeOwnerAssignmentCannotBeUnlinked()
    {
        await using var backend = new Backend("ownership-good");
        using NativeEnvironment environment = Environment(backend.Origin);
        ManagementClient client = environment.CreateManagementClient();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        GroupMetadata group = (await OwnershipExecute(client,
            ScopedAccessOperations.CreateGroup(OwnerOrg, "root-owned", "root-owned", "no-access"),
            "owner-setup", OwnerOrg, deadline.Token)).Value;
        var remove = await OwnershipExecute(client, MembershipOperations.RemoveOrganizationGroup(OwnerOrg, group.Id),
            "owner-setup", OwnerOrg, deadline.Token);
        await Assert.That(remove.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((await OwnershipExecute(client, MembershipOperations.GetOrganizationGroup(OwnerOrg, group.Id),
            "owner-observer", OwnerOrg, deadline.Token)).IsSuccess).IsTrue();
        await Assert.That(backend.OwnerUnlinkDispatches).IsEqualTo(1);
        await Assert.That((await OwnershipExecute(client, ScopedAccessOperations.DeleteGroup(OwnerOrg, group.Id),
            "owner-setup", OwnerOrg, deadline.Token)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(backend.GroupCount).IsEqualTo(0);
    }

    private static async ValueTask<SecretOutcome<T>> OwnershipExecute<T>(ManagementClient client,
        ManagementRequest<T> request, string credential, string organization, CancellationToken token,
        string? projectId = null) where T : notnull
    {
        using (request)
        {
            var authority = new ManagementAuthority(client.Authority, new OwnershipTokens(credential), organization, projectId);
            return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                request.IsMutation ? client.CreateReceipt(request) : null, token);
        }
    }

    private sealed class OwnershipTokens(string credential) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText(credential))));
        }
        public override string ToString() => "[OwnershipTokens]";
    }

    [Test]
    public async Task EveryCompilerRowBindsExactMemberVariantAndCase()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        NativeCaseDefinition[] expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => InfisicalProjectFamilies.Owns(o.GetProperty("id").GetString()!))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        await Assert.That(expected.Length).IsEqualTo(3823);
        await Assert.That(expected.All(InfisicalProjectFamilies.Valid)).IsTrue();
        await Assert.That(expected.Select(d => d.Key.Operation).Distinct().Count()).IsEqualTo(51);
        await Assert.That(expected.Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(775);
        await Assert.That(expected.Count(d => InfisicalProjectFamilies.UnavailableReason(d) is null)).IsEqualTo(1103);
        await Assert.That(expected.Where(d => InfisicalProjectFamilies.UnavailableReason(d) is null)
            .Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(229);
        using NativeEnvironment environment = Environment(new Uri("http://127.0.0.1:1/"), false);
        var registry = new NativeCaseRegistry();
        InfisicalProjectFamilies.Register(registry, environment, expected);
        IReadOnlyList<NativeCaseResult> results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode is "missing-input" or "observer-unavailable")).IsTrue();
        await Assert.That(results.Count(r => r.ReasonCode == "observer-unavailable")).IsEqualTo(
            expected.Count(d => InfisicalProjectFamilies.UnavailableReason(d) is not null));
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("scope")]
    public async Task InvalidBindingCannotReachSetup(string corruption)
    {
        NativeCaseDefinition definition = Definition("ProjectOperations.CreateTag",
            "input.organizationId-projectId-slug-color", "selected-contract");
        definition = corruption switch
        {
            "member" => definition with { Member = definition.Member + ".wrong" },
            "variant" => definition with { Key = definition.Key with { Variant = "unknown" } },
            "case" => definition with { Key = definition.Key with { Case = "unknown" } },
            _ => definition with { Key = definition.Key with { Scope = "unselected" } }
        };
        using NativeEnvironment environment = Environment(new Uri("http://127.0.0.1:1/"));
        NativeCaseResult result = await RunAsync(environment, definition);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(corruption == "scope" ? "missing-input" : "contract-mismatch");
    }

    [Test]
    [Arguments("selected-contract", "good", "observed")]
    [Arguments("independent-effect", "good", "observed")]
    [Arguments("denied-authority", "good", "observed")]
    [Arguments("cancellation-boundary", "good", "observed")]
    [Arguments("lost-response-no-replay", "good", "observed")]
    [Arguments("independent-effect", "drift", "effect-mismatch")]
    [Arguments("independent-effect", "cleanup", "cleanup-incomplete")]
    [Arguments("independent-effect", "wrong-coordinate", "contract-mismatch")]
    public async Task TagCreationUsesMeasuredStateAndNeverReplays(string caseName, string mode, string reason)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition("ProjectOperations.CreateTag",
            "input.organizationId-projectId-slug-color", caseName));
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsEqualTo(reason == "observed");
        await Assert.That(backend.AdministrativeTagCreates).IsEqualTo(caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        if (mode != "cleanup") await Assert.That(backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("GetProject", "selector.exact")]
    [Arguments("GetProjectBySlug", "selector.slug")]
    [Arguments("DeleteProject", "input.organizationId-projectId")]
    [Arguments("UpdateProject", "name.omitted")]
    [Arguments("UpdateProject", "slug.value")]
    [Arguments("UpdateProject", "deleteProtection.true")]
    [Arguments("UpdateProject", "auditRetentionDays.value")]
    [Arguments("UpdateProject", "secretDetectionIgnoreValues.value")]
    [Arguments("GetTag", "selector.exact")]
    [Arguments("GetTagBySlug", "selector.slug")]
    [Arguments("UpdateTag", "input.organizationId-projectId-tagId-slug-color")]
    [Arguments("DeleteTag", "input.organizationId-projectId-tagId")]
    [Arguments("ListTags", "collection.bounded")]
    [Arguments("CreateEnvironment", "position.value")]
    [Arguments("GetEnvironment", "selector.exact")]
    [Arguments("UpdateEnvironment", "name.omitted")]
    [Arguments("DeleteEnvironment", "permanently.false")]
    [Arguments("DeleteEnvironment", "permanently.true")]
    [Arguments("RestoreEnvironment", "input.organizationId-projectId-environmentId")]
    public async Task ProjectScenariosRoundTripOwnedState(string method, string variant)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition("ProjectOperations." + method, variant));
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("AddProjectIdentity.Selection", "roles.permanent")]
    [Arguments("AddProjectIdentity.Selection", "role.scalar")]
    [Arguments("AddProjectIdentity.Selection", "roles.empty")]
    [Arguments("AddProjectIdentity.Roles", "roles.permanent-discriminator-omitted")]
    [Arguments("UpdateProjectIdentityRoles", "roles.permanent")]
    [Arguments("GetProjectIdentityMembership", "selector.exact")]
    [Arguments("RemoveProjectIdentity", "input.organizationId-projectId-identityId")]
    public async Task IdentityMembershipRequiresActualRuntimeAccess(string method, string variant)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition("MembershipOperations." + method, variant));
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.RuntimeReads).IsGreaterThan(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("AddProjectGroup.Selection", "role-and-roles.supplied")]
    [Arguments("AddProjectGroup.Roles", "roles.value")]
    [Arguments("UpdateProjectGroupRoles", "roles.permanent")]
    [Arguments("GetProjectGroup", "selector.exact")]
    [Arguments("ListProjectGroups", "collection.bounded")]
    [Arguments("RemoveProjectGroup", "input.organizationId-projectId-groupId")]
    [Arguments("AddOrganizationGroup", "roles.permanent")]
    [Arguments("UpdateOrganizationGroupRoles", "roles.permanent-discriminator-omitted")]
    [Arguments("GetOrganizationGroup", "selector.exact")]
    [Arguments("ListOrganizationGroups", "orderBy.Name")]
    [Arguments("RemoveOrganizationGroup", "input.organizationId-groupId")]
    public async Task GroupMembershipScenariosUseIndependentGroupAndPrincipalState(string method, string variant)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition("MembershipOperations." + method, variant));
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("MembershipMutationOperations.InviteProjectMembers", "principals.usernames")]
    [Arguments("MembershipMutationOperations.RemoveProjectMembers", "principals.emails")]
    [Arguments("ProjectMembershipOperations.InspectProjectMembershipByUsername", "selector.exact")]
    [Arguments("ProjectMembershipOperations.ListProjectMemberships", "collection.bounded")]
    [Arguments("ProjectMembershipOperations.UpdateProjectMembershipRoles", "roles.permanent-discriminator-omitted")]
    public async Task UserMembershipBindsSelectedPrincipalAndDownstreamRead(string operation, string variant)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition(operation, variant));
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.RuntimeReads).IsGreaterThan(0);
    }

    [Test]
    [Arguments("InviteProjectMembers", "selected-contract")]
    [Arguments("InviteProjectMembers", "independent-effect")]
    [Arguments("InviteProjectMembers", "denied-authority")]
    [Arguments("InviteProjectMembers", "cancellation-boundary")]
    [Arguments("InviteProjectMembers", "lost-response-no-replay")]
    [Arguments("RemoveProjectMembers", "selected-contract")]
    [Arguments("RemoveProjectMembers", "independent-effect")]
    [Arguments("RemoveProjectMembers", "denied-authority")]
    [Arguments("RemoveProjectMembers", "cancellation-boundary")]
    [Arguments("RemoveProjectMembers", "lost-response-no-replay")]
    public async Task MixedPrincipalsMeasureBothMembershipsAndFreshAccess(string method, string caseName)
    {
        await using var backend = new Backend("mixed-good");
        using NativeEnvironment environment = Environment(backend.Origin, mixed: true);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipMutationOperations." + method, "principals.emails-and-usernames", caseName));
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(backend.AdministrativeMemberMutations).IsEqualTo(
            caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        await Assert.That(backend.FirstAllowedReads).IsGreaterThan(0);
        await Assert.That(backend.FirstDeniedReads).IsGreaterThan(0);
        await Assert.That(backend.SecondAllowedReads).IsGreaterThan(0);
        await Assert.That(backend.SecondDeniedReads).IsGreaterThan(0);
        await Assert.That(backend.FirstMembershipReads).IsGreaterThan(0);
        await Assert.That(backend.SecondMembershipReads).IsGreaterThan(0);
        await Assert.That(backend.DeniedCanaryReads).IsGreaterThan(0);
        await Assert.That(backend.CanaryCount).IsGreaterThan(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
        await Assert.That(backend.OwnedProjectDeletes).IsEqualTo(1);
        await Assert.That(backend.UnrelatedStatePreserved).IsTrue();
    }

    [Test]
    [Arguments("InviteProjectMembers", "mixed-missing-second-membership", "effect-mismatch")]
    [Arguments("RemoveProjectMembers", "mixed-missing-second-membership", "effect-mismatch")]
    [Arguments("InviteProjectMembers", "mixed-missing-second-access", "effect-mismatch")]
    [Arguments("RemoveProjectMembers", "mixed-missing-second-access", "missing-prerequisite")]
    [Arguments("InviteProjectMembers", "mixed-wrong-second-username", "effect-mismatch")]
    [Arguments("RemoveProjectMembers", "mixed-wrong-second-username", "missing-prerequisite")]
    [Arguments("InviteProjectMembers", "mixed-wrong-second-user-id", "contract-mismatch")]
    [Arguments("RemoveProjectMembers", "mixed-wrong-second-user-id", "contract-mismatch")]
    [Arguments("InviteProjectMembers", "mixed-duplicate-results", "contract-mismatch")]
    [Arguments("RemoveProjectMembers", "mixed-duplicate-results", "contract-mismatch")]
    [Arguments("InviteProjectMembers", "mixed-extra-results", "contract-mismatch")]
    [Arguments("RemoveProjectMembers", "mixed-extra-results", "contract-mismatch")]
    public async Task MixedPrincipalsRejectIndependentStateAndResponseCorruption(
        string method, string mode, string reason)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin, mixed: true);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipMutationOperations." + method, "principals.emails-and-usernames"));
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.FaultApplied).IsTrue();
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
        await Assert.That(backend.OwnedProjectDeletes).IsEqualTo(1);
        await Assert.That(backend.UnrelatedStatePreserved).IsTrue();
    }

    [Test]
    [Arguments("InviteProjectMembers")]
    [Arguments("RemoveProjectMembers")]
    public async Task MixedPrincipalsRejectAliasedSecondaryCredentialBeforeMutation(string method)
    {
        await using var backend = new Backend("mixed-aliased-secondary-credential");
        using NativeEnvironment environment = Environment(backend.Origin, mixed: true);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipMutationOperations." + method, "principals.emails-and-usernames"));
        await Assert.That(result.ReasonCode).IsEqualTo("missing-prerequisite");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.AdministrativeMemberMutations).IsEqualTo(0);
        await Assert.That(backend.SecondAllowedReads).IsGreaterThan(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
        await Assert.That(backend.OwnedProjectDeletes).IsEqualTo(1);
        await Assert.That(backend.UnrelatedStatePreserved).IsTrue();
    }

    [Test]
    [Arguments("InviteProjectMembers", "missing-username")]
    [Arguments("InviteProjectMembers", "missing-user-id")]
    [Arguments("InviteProjectMembers", "missing-email")]
    [Arguments("InviteProjectMembers", "missing-token")]
    [Arguments("InviteProjectMembers", "colliding-username")]
    [Arguments("InviteProjectMembers", "colliding-user-id")]
    [Arguments("InviteProjectMembers", "colliding-email")]
    [Arguments("InviteProjectMembers", "colliding-token")]
    [Arguments("RemoveProjectMembers", "missing-username")]
    [Arguments("RemoveProjectMembers", "missing-user-id")]
    [Arguments("RemoveProjectMembers", "missing-email")]
    [Arguments("RemoveProjectMembers", "missing-token")]
    [Arguments("RemoveProjectMembers", "colliding-username")]
    [Arguments("RemoveProjectMembers", "colliding-user-id")]
    [Arguments("RemoveProjectMembers", "colliding-email")]
    [Arguments("RemoveProjectMembers", "colliding-token")]
    public async Task MixedPrincipalsRequireSeparateSecondaryInputs(string method, string fault)
    {
        await using var backend = new Backend("mixed-good");
        using NativeEnvironment environment = Environment(backend.Origin, mixed: true, secondaryFault: fault);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipMutationOperations." + method, "principals.emails-and-usernames"));
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.AdministrativeMemberMutations).IsEqualTo(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
        await Assert.That(backend.UnrelatedStatePreserved).IsTrue();
    }

    [Test]
    [Arguments("mixed-good")]
    [Arguments("mixed-aliased-secondary-credential")]
    public async Task MixedPrincipalsBackendCredentialsFollowOnlyActualMembership(string mode)
    {
        await using var backend = new Backend(mode);
        using var client = new HttpClient { BaseAddress = backend.Origin };
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string credential,
            JsonObject? body = null)
        {
            using var request = new HttpRequestMessage(method, path);
            request.Headers.Authorization = new("Bearer", credential);
            if (body is not null) request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            return await client.SendAsync(request, deadline.Token);
        }
        using HttpResponseMessage created = await SendAsync(HttpMethod.Post, "/api/v1/projects", "setup",
            new JsonObject { ["projectName"] = "credential-witness", ["slug"] = "credential-witness", ["hasDeleteProtection"] = false });
        JsonObject project = JsonNode.Parse(await created.Content.ReadAsStringAsync(deadline.Token))!["project"]!.AsObject();
        string id = project["id"]!.GetValue<string>();
        string membershipPath = "/api/v1/projects/" + id + "/memberships";
        string canaryPath = "/api/v4/secrets/credential-witness";
        using HttpResponseMessage canary = await SendAsync(HttpMethod.Post, canaryPath, "setup",
            new JsonObject { ["projectId"] = id, ["environment"] = "witness", ["secretValue"] = "offline-canary" });
        await Assert.That(canary.StatusCode).IsEqualTo(HttpStatusCode.OK);
        string readPath = canaryPath + "?projectId=" + id + "&environment=witness";
        foreach (bool firstOnly in new[] { true, false })
        {
            var selection = firstOnly ?
                new JsonObject { ["usernames"] = new JsonArray("fixture-user"), ["emails"] = new JsonArray() } :
                new JsonObject { ["usernames"] = new JsonArray(), ["emails"] = new JsonArray("fixture-second@example.invalid") };
            using HttpResponseMessage added = await SendAsync(HttpMethod.Post, membershipPath, "setup", selection);
            await Assert.That(added.StatusCode).IsEqualTo(HttpStatusCode.OK);
            using HttpResponseMessage first = await SendAsync(HttpMethod.Get, readPath, "runtime");
            using HttpResponseMessage second = await SendAsync(HttpMethod.Get, readPath, "second-runtime");
            using HttpResponseMessage denied = await SendAsync(HttpMethod.Get, readPath, "denied");
            await Assert.That(first.StatusCode).IsEqualTo(firstOnly ? HttpStatusCode.OK : HttpStatusCode.Forbidden);
            await Assert.That(second.StatusCode).IsEqualTo(
                firstOnly == (mode == "mixed-aliased-secondary-credential") ? HttpStatusCode.OK : HttpStatusCode.Forbidden);
            await Assert.That(denied.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
            using HttpResponseMessage removed = await SendAsync(HttpMethod.Delete, membershipPath, "setup", selection);
            await Assert.That(removed.StatusCode).IsEqualTo(HttpStatusCode.OK);
        }
        using HttpResponseMessage forbiddenRead = await SendAsync(HttpMethod.Get, "/api/v1/projects/" + id, "second-runtime");
        using HttpResponseMessage forbiddenWrite = await SendAsync(HttpMethod.Post, membershipPath, "second-runtime",
            new JsonObject { ["usernames"] = new JsonArray("fixture-second-user"), ["emails"] = new JsonArray() });
        await Assert.That(forbiddenRead.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(forbiddenWrite.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        using HttpResponseMessage deleted = await SendAsync(HttpMethod.Delete, "/api/v1/projects/" + id, "setup");
        await Assert.That(deleted.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
        await Assert.That(backend.UnrelatedStatePreserved).IsTrue();
    }

    [Test]
    public async Task MetadataMembershipWithoutAccessCannotPass()
    {
        await using var backend = new Backend("access-denied");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipOperations.AddProjectIdentity.Selection", "roles.permanent"));
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
    }

    [Test]
    public async Task OnlyMeasuredPrerequisitesAreConfirmed()
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("ProjectTemplateOperations.CreateProjectTemplate", "permissions.literal"));
        await Assert.That(result.Passed).IsTrue();
        string[] measured = ["selected-administrative-identity", "scoped-administrative-rights",
            "selected-runtime-identity", "permission-policy-entitlement",
            "intended-principal-permission-observer", "approved-sandbox-cleanup"];
        await Assert.That(environment.PrerequisiteResults(measured.Select(p =>
            new NativePrerequisiteKey("Infisical", "local", p)).ToArray()).All(p => p.Confirmed)).IsTrue();
        await Assert.That(environment.PrerequisiteResults([
            new("Infisical", "local", "separate-observer-identity"),
            new("Infisical", "local", "primary-permission-response-shapes"),
            new("Infisical", "local", "owned-origin-api-revision")]).All(p => !p.Confirmed)).IsTrue();
    }

    [Test]
    [Arguments("CreateProjectTemplate", "permissions.literal")]
    [Arguments("CreateProjectTemplate", "permissions.action.array")]
    [Arguments("CreateProjectTemplate", "permissions.in.empty")]
    [Arguments("CreateProjectTemplate", "roles.empty")]
    [Arguments("CreateProjectTemplate", "environments.empty")]
    [Arguments("CreateProjectTemplate", "permission.Secrets.describeSecret")]
    [Arguments("CreateProjectTemplate", "permission.Secrets.create")]
    [Arguments("CreateProjectTemplate", "permission.Secrets.edit")]
    [Arguments("CreateProjectTemplate", "permission.Secrets.delete")]
    [Arguments("CreateProjectTemplate", "permissions.metadata.elemMatch")]
    [Arguments("CreateProjectTemplate", "permissions.secretTags.in")]
    [Arguments("CreateProjectTemplate", "permissions.secretTags.all")]
    [Arguments("GetProjectTemplate", "selector.exact")]
    [Arguments("ListProjectTemplates", "type.omitted")]
    [Arguments("UpdateProjectTemplate", "name.omitted")]
    [Arguments("UpdateProjectTemplate", "users.null")]
    [Arguments("UpdateProjectTemplate", "identities.null")]
    [Arguments("DeleteProjectTemplate", "response.conditions-unprojected")]
    public async Task TemplatePoliciesRequireSupportedIndependentEffects(string method, string variant)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment, Definition("ProjectTemplateOperations." + method, variant));
        await Assert.That(result.ReasonCode).IsEqualTo(
            variant == "permissions.metadata.elemMatch" ? "observer-unavailable" : "observed");
        await Assert.That(backend.ProjectCount).IsEqualTo(0);
        await Assert.That(backend.TemplateCount).IsEqualTo(0);
    }

    [Test]
    public async Task UnsupportedObserversRemainExplicitFailures()
    {
        using NativeEnvironment environment = Environment(new Uri("http://127.0.0.1:1/"));
        foreach (NativeCaseDefinition definition in new[]
        {
            Definition("ProjectTemplateOperations.CreateProjectTemplate", "permission.AppConnections.read-app-connections"),
            Definition("ProjectTemplateOperations.UpdateProjectTemplate", "permission.Insights.read"),
            Definition("ProjectTemplateOperations.CreateProjectTemplate", "permission.Webhooks.read"),
            Definition("ProjectTemplateOperations.CreateProjectTemplate", "permission.SecretApproval.read"),
            Definition("MembershipOperations.UpdateProjectIdentityRoles", "roles.relative-time"),
            Definition("MembershipMutationOperations.DeleteOrganizationMemberships", "input.organizationId-membershipIds")
        })
        {
            NativeCaseResult result = await RunAsync(environment, definition);
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(result.EffectObserved).IsFalse();
        }
    }

    [Test]
    public async Task CleanupRejectsAProjectIdSubstitutedUnderTheOwnedSlug()
    {
        await using var backend = new Backend("cleanup-substitution");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("ProjectOperations.CreateTag",
            "input.organizationId-projectId-slug-color"));
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(backend.ForeignProjectProtected).IsTrue();
        await Assert.That(backend.ProjectCount).IsEqualTo(2);
    }

    [Test]
    public async Task DuplicateProjectMembershipsCannotCertifyInventory()
    {
        await using var backend = new Backend("duplicate-memberships");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition(
            "ProjectMembershipOperations.ListProjectMemberships", "collection.bounded"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CertificateManager")]
    [Arguments("Kms")]
    [Arguments("SecretScanning")]
    [Arguments("Pam")]
    [Arguments("AgentVault")]
    public async Task EmptyNonsecretInventoryCannotCertifyTypeFiltering(string type)
    {
        await using var backend = new Backend("empty-project-list");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("ProjectOperations.ListProjects", "type." + type));
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
    }

    [Test]
    [Arguments("permissions.literal")]
    [Arguments("roles.empty")]
    [Arguments("environments.empty")]
    [Arguments("identities.null")]
    public async Task TemplateMetadataCannotHideAnIgnoredConfigurationUpdate(string variant)
    {
        await using var backend = new Backend("ignore-template-configuration");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("ProjectTemplateOperations.UpdateProjectTemplate",
            variant));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.ProjectCount).IsEqualTo(0);
        await Assert.That(backend.TemplateCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("permissions.literal")]
    [Arguments("permissions.in.empty")]
    [Arguments("permissions.conditions.empty")]
    [Arguments("permission.Secrets.create")]
    [Arguments("roles.empty")]
    [Arguments("environments.empty")]
    [Arguments("environments.null")]
    [Arguments("ProjectTemplateConfiguration.identities.omitted")]
    [Arguments("identities.null")]
    public async Task TemplateConfigurationTransitionsPreserveDeniedAndInterruptedBaselines(string variant)
    {
        foreach (string caseName in new[] { "independent-effect", "denied-authority",
            "cancellation-boundary", "lost-response-no-replay" })
        {
            await using var backend = new Backend("good");
            using NativeEnvironment environment = Environment(backend.Origin);
            var result = await RunAsync(environment, Definition("ProjectTemplateOperations.UpdateProjectTemplate",
                variant, caseName));
            await Assert.That(result.ReasonCode).IsEqualTo("observed").Because(variant + "/" + caseName);
            await Assert.That(backend.ProjectCount).IsEqualTo(0);
            await Assert.That(backend.TemplateCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("orderBy.Name")]
    [Arguments("orderBy.Slug")]
    [Arguments("orderBy.Role")]
    [Arguments("orderBy.omitted")]
    [Arguments("order.Ascending")]
    [Arguments("order.Descending")]
    [Arguments("order.omitted")]
    [Arguments("search.omitted")]
    [Arguments("search.value")]
    public async Task OrganizationGroupInventoryMeasuresItsSelectedOrderAndSearch(string variant)
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("MembershipOperations.ListOrganizationGroups", variant));
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
    }

    [Test]
    public async Task FixedGroupInsertionOrderCannotCertifyDescendingOrder()
    {
        await using var backend = new Backend("ignore-group-order");
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("MembershipOperations.ListOrganizationGroups",
            "order.Descending"));
        await Assert.That(result.Passed).IsFalse();
    }

    [Test]
    public async Task ResponseBoundaryCancelsBeforeBodyReceiptAndDoesNotReplay()
    {
        await using var backend = new Backend("good");
        using NativeEnvironment environment = Environment(backend.Origin);
        ManagementClient client = environment.CreateManagementClient();
        ManagementAuthority authority = environment.CreateManagementAuthority(client, NativeIdentityRole.Administrative, Org);
        using var request = ProjectOperations.CreateProject(Org, "boundary", "boundary", createDefaultEnvironments: false);
        ManagementReceipt receipt = client.CreateReceipt(request);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var boundary = new ProjectResponseBoundary(backend.Origin, cancellation);
        bool cancelled = false;
        using (boundary.Enter())
        {
            try
            {
                await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
                    ProjectOperations.ProjectCreateTarget(Org, "boundary", "boundary", createDefaultEnvironments: false)),
                    receipt, cancellation.Token);
            }
            catch (OperationCanceledException) { cancelled = true; }
        }
        await Assert.That(boundary.Reached).IsTrue();
        await Assert.That(cancelled).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
    }

    [Test]
    [Arguments("AddProjectIdentity.Selection", "selected-contract")]
    [Arguments("AddProjectIdentity.Selection", "independent-effect")]
    [Arguments("AddProjectIdentity.Selection", "denied-authority")]
    [Arguments("AddProjectIdentity.Selection", "cancellation-boundary")]
    [Arguments("AddProjectIdentity.Selection", "lost-response-no-replay")]
    [Arguments("AddProjectIdentity.Roles", "selected-contract")]
    [Arguments("AddProjectIdentity.Roles", "independent-effect")]
    [Arguments("AddProjectIdentity.Roles", "denied-authority")]
    [Arguments("AddProjectIdentity.Roles", "cancellation-boundary")]
    [Arguments("AddProjectIdentity.Roles", "lost-response-no-replay")]
    [Arguments("UpdateProjectIdentityRoles", "selected-contract")]
    [Arguments("UpdateProjectIdentityRoles", "independent-effect")]
    [Arguments("UpdateProjectIdentityRoles", "denied-authority")]
    [Arguments("UpdateProjectIdentityRoles", "cancellation-boundary")]
    [Arguments("UpdateProjectIdentityRoles", "lost-response-no-replay")]
    [Arguments("AddProjectGroup.Selection", "selected-contract")]
    [Arguments("AddProjectGroup.Selection", "independent-effect")]
    [Arguments("AddProjectGroup.Selection", "denied-authority")]
    [Arguments("AddProjectGroup.Selection", "cancellation-boundary")]
    [Arguments("AddProjectGroup.Selection", "lost-response-no-replay")]
    [Arguments("AddProjectGroup.Roles", "selected-contract")]
    [Arguments("AddProjectGroup.Roles", "independent-effect")]
    [Arguments("AddProjectGroup.Roles", "denied-authority")]
    [Arguments("AddProjectGroup.Roles", "cancellation-boundary")]
    [Arguments("AddProjectGroup.Roles", "lost-response-no-replay")]
    [Arguments("UpdateProjectGroupRoles", "selected-contract")]
    [Arguments("UpdateProjectGroupRoles", "independent-effect")]
    [Arguments("UpdateProjectGroupRoles", "denied-authority")]
    [Arguments("UpdateProjectGroupRoles", "cancellation-boundary")]
    [Arguments("UpdateProjectGroupRoles", "lost-response-no-replay")]
    [Arguments("ProjectMembershipOperations.UpdateProjectMembershipRoles", "selected-contract")]
    [Arguments("ProjectMembershipOperations.UpdateProjectMembershipRoles", "independent-effect")]
    [Arguments("ProjectMembershipOperations.UpdateProjectMembershipRoles", "denied-authority")]
    [Arguments("ProjectMembershipOperations.UpdateProjectMembershipRoles", "cancellation-boundary")]
    [Arguments("ProjectMembershipOperations.UpdateProjectMembershipRoles", "lost-response-no-replay")]
    public async Task TemporaryMembershipRequiresBoundProviderExpiryAndFreshControl(string method, string caseName)
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("temporal-good", clock);
        var expiry = new ControlledExpiryObserver(backend, clock);
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true);
        string operation = method.StartsWith("ProjectMembershipOperations.", StringComparison.Ordinal) ?
            method : "MembershipOperations." + method;
        NativeCaseResult result = await RunAsync(environment, Definition(operation, "roles.relative-time", caseName), expiry);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(expiry.Samples.SequenceEqual(new[] { MembershipExpiryPhase.BeforeActivation,
            MembershipExpiryPhase.Active, MembershipExpiryPhase.Expired })).IsTrue();
        await Assert.That(expiry.CompleteCalls).IsEqualTo(caseName == "cancellation-boundary" ? 0 : 1);
        await Assert.That(expiry.AppliedMutations).IsEqualTo(
            caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        if (caseName != "cancellation-boundary")
            await Assert.That(expiry.Completions.Single().Disposition).IsEqualTo(
                caseName == "denied-authority" ? MembershipExpiryDisposition.Rejected : MembershipExpiryDisposition.Applied);
        await Assert.That(expiry.CloseCalls).IsEqualTo(1);
        await Assert.That(expiry.Registrations).IsEqualTo(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
        await Assert.That(backend.UnrelatedStatePreserved).IsTrue();
        await Assert.That(backend.DeniedCanaryReads).IsGreaterThan(2);
        await Assert.That(backend.FirstDeniedReads).IsGreaterThan(1);
        await Assert.That(backend.FirstAllowedReads).IsGreaterThan(2);
        MembershipExpiryAttempt attempt = expiry.LastAttempt!;
        await Assert.That(expiry.Arm!.Intent.Attempt).IsEqualTo(attempt);
        foreach (MembershipExpiryPhase phase in Enum.GetValues<MembershipExpiryPhase>())
        {
            DateTimeOffset time = phase == MembershipExpiryPhase.BeforeActivation ? expiry.Arm.ArmedAt :
                phase == MembershipExpiryPhase.Active ? expiry.Arm.StartsAt : expiry.Arm.EndsAt;
            int expected = phase == MembershipExpiryPhase.Active &&
                caseName is not ("denied-authority" or "cancellation-boundary") ? 200 : 403;
            await Assert.That(backend.Accesses.Any(a => a.Project == attempt.ProjectId &&
                a.Credential == "runtime" && a.Time == time && a.Status == expected)).IsTrue();
            await Assert.That(backend.Accesses.Any(a => a.Project != attempt.ProjectId &&
                a.Project != Backend.ForeignProjectId && a.Credential == "runtime" &&
                a.Time == time && a.Status == 200)).IsTrue();
            await Assert.That(backend.Accesses.Any(a => a.Project == attempt.ProjectId &&
                a.Credential == "denied" && a.Time == time && a.Status == 403)).IsTrue();
        }
        if (expiry.AppliedMutations == 1)
        {
            JsonObject captured = expiry.CapturedMembership!;
            await Assert.That(captured["roles"]!.AsArray().Count).IsEqualTo(2);
            await Assert.That(captured["roles"]!.AsArray().Count(r => r!["role"]!.GetValue<string>() == "no-access" &&
                r["isTemporary"]!.GetValue<bool>() == false)).IsEqualTo(1);
            JsonNode temporary = captured["roles"]!.AsArray().Single(r => r!["isTemporary"]!.GetValue<bool>())!;
            await Assert.That(temporary["role"]!.GetValue<string>()).IsEqualTo("viewer");
            await Assert.That(temporary["id"]!.GetValue<string>()).IsEqualTo(expiry.Completions.Single().AssignmentId);
            await Assert.That(captured["id"]!.GetValue<string>()).IsEqualTo(expiry.Completions.Single().MembershipId);
        }
    }

    [Test]
    [Arguments("unbound-attempt")]
    [Arguments("bad-phase")]
    [Arguments("bad-phase-time")]
    [Arguments("bad-window-time")]
    [Arguments("bad-window-close")]
    [Arguments("bad-clock-epoch")]
    [Arguments("different-window-epoch")]
    [Arguments("bad-sequence")]
    [Arguments("bad-window-sequence")]
    [Arguments("unobserved-event")]
    [Arguments("different-assignment-id")]
    [Arguments("different-member-id")]
    [Arguments("missing-permanent-baseline")]
    [Arguments("unexpected-expired-grant")]
    [Arguments("expired-credential")]
    [Arguments("missing-completion-fence")]
    [Arguments("lost-arm")]
    [Arguments("cleanup-leftovers")]
    [Arguments("cleanup-pending")]
    [Arguments("cleanup-inventory")]
    [Arguments("late-mutation")]
    [Arguments("alias-observer")]
    public async Task TemporaryMembershipCannotCertifyCorruptEvidence(string fault)
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("temporal-good", clock);
        var expiry = new ControlledExpiryObserver(backend, clock, fault);
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipOperations.AddProjectIdentity.Selection", "roles.relative-time"), expiry);
        await Assert.That(result.Passed).IsFalse();
        // An unavailable handler never exercises the counterexample.
        await Assert.That(result.ReasonCode == "observer-unavailable").IsFalse();
        await Assert.That(expiry.LastAttempt is not null).IsTrue();
        await Assert.That(expiry.CloseCalls).IsEqualTo(1);
        await Assert.That(expiry.Registrations).IsEqualTo(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
        await Assert.That(backend.UnrelatedStatePreserved).IsTrue();
        if (fault == "lost-arm") await Assert.That(expiry.CompleteCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("absent-temporal")]
    [Arguments("absent-duration")]
    [Arguments("absent-lead")]
    [Arguments("absent-source")]
    [Arguments("colliding-window")]
    [Arguments("colliding-duration")]
    public async Task TemporaryMembershipRequiresExplicitNonCollidingTemporalInputs(string fault)
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("temporal-good", clock);
        var expiry = new ControlledExpiryObserver(backend, clock);
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true, temporalFault: fault);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipOperations.AddProjectIdentity.Selection", "roles.relative-time"), expiry);
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(expiry.LastAttempt is null).IsTrue();
        await Assert.That(expiry.AppliedMutations).IsEqualTo(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
    }

    [Test]
    public async Task TemporaryMembershipNativeFactoryRejectsUninjectedControlledSource()
    {
        await using var backend = new Backend("temporal-good");
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "MembershipOperations.AddProjectIdentity.Selection", "roles.relative-time"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
    }

    [Test]
    [Arguments("retained-inactive")]
    [Arguments("removed-expired-assignment")]
    [Arguments("expired-credential")]
    public async Task TemporaryMembershipFixtureAccessUsesActualRoleTimeAndCredentialValidity(string expiryMode)
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("temporal-good", clock);
        var expiry = new ControlledExpiryObserver(backend, clock, expiryMode);
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        CancellationToken token = deadline.Token;
        ManagementClient management = environment.CreateManagementClient();
        async ValueTask<T> Execute<T>(ManagementRequest<T> request) where T : notnull
        {
            using (request)
            {
                ManagementAuthority authority = environment.CreateManagementAuthority(management,
                    NativeIdentityRole.Setup, request.Target.OrganizationId, request.Target.ProjectId);
                SecretOutcome<T> outcome = await management.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, request.Target),
                    request.IsMutation ? management.CreateReceipt(request) : null, token);
                await Assert.That(outcome.IsSuccess).IsTrue();
                return outcome.Value;
            }
        }
        string project = (await Execute(ProjectOperations.CreateProject(Org, "temporal", "temporal",
            createDefaultEnvironments: false))).Id;
        string control = (await Execute(ProjectOperations.CreateProject(Org, "control", "control",
            createDefaultEnvironments: false))).Id;
        await Execute(MembershipOperations.AddProjectIdentity(Org, project, Runtime,
            new MembershipRoleSelection(roles: [new("no-access")])));
        await Execute(MembershipOperations.AddProjectIdentity(Org, control, Runtime,
            new MembershipRoleSelection(roles: [new("viewer")])));
        await using InfisicalClient setup = environment.CreateClient(NativeIdentityRole.Setup);
        using SecretMaterial material = SecretMaterial.FromText("offline-temporal-canary");
        foreach (string id in new[] { project, control })
        {
            var reference = new SecretReference(setup.Authority, new InfisicalSecretAddress(id, "witness", "/", "temporal-canary"));
            SecretOutcome<InfisicalStaticChange> created = await setup.CreateAsync(reference, material,
                new MutationReceipt(reference), token);
            await Assert.That(created.IsSuccess).IsTrue();
        }
        var attempt = new MembershipExpiryAttempt(Guid.NewGuid().ToString(), "fixture-characterization", Org,
            project, MembershipExpiryPrincipal.Identity, Runtime, Runtime,
            backend.MembershipSnapshot(project, Runtime)!["id"]!.GetValue<string>(), MembershipExpirySource.ControlledFixture);
        MembershipExpiryArm arm = await expiry.ArmAsync(new(attempt, "1m", 5), token);
        // Complete waits on the already-armed request capture. Start it before
        // dispatch to characterize synchronous event delivery without polling.
        Task<MembershipExpiryFence> completed = expiry.CompleteAsync(arm, token).AsTask();
        await Assert.That(completed.IsCompleted).IsFalse();
        await Execute(MembershipOperations.UpdateProjectIdentityRoles(Org, project, Runtime,
            [new("no-access"), new("viewer", arm.StartsAt, "1m")]));
        MembershipExpiryFence fence = await completed;
        await Assert.That(fence.Disposition).IsEqualTo(MembershipExpiryDisposition.Applied);
        string assignmentId = fence.AssignmentId!;
        foreach (MembershipExpiryPhase phase in Enum.GetValues<MembershipExpiryPhase>())
        {
            int callbacks = 0;
            MembershipExpiryObservation<bool> measured = await expiry.ObserveAsync(fence, phase, async ct =>
            {
                callbacks++;
                await using InfisicalClient runtime = environment.CreateRuntimeClient();
                await using InfisicalClient denied = environment.CreateClient(NativeIdentityRole.Denied);
                async ValueTask<SecretStatus> Read(InfisicalClient reader, string id)
                {
                    SecretOutcome<SecretRead> read = await reader.ReadAsync(new(reader.Authority,
                        new InfisicalSecretAddress(id, "witness", "/", "temporal-canary")), ct);
                    if (read.IsSuccess)
                    {
                        using SecretRead value = read.Value;
                        await Assert.That(value.Material.ExportCharacters().AsSpan()
                            .SequenceEqual("offline-temporal-canary")).IsTrue();
                    }
                    return read.Status;
                }
                SecretStatus target = await Read(runtime, project), unaffected = await Read(runtime, control);
                await Assert.That(await Read(denied, project)).IsEqualTo(SecretStatus.Denied);
                bool credentialExpired = expiryMode == "expired-credential" && phase == MembershipExpiryPhase.Expired;
                await Assert.That(unaffected == SecretStatus.Success).IsEqualTo(!credentialExpired);
                await Assert.That(target == SecretStatus.Success).IsEqualTo(phase == MembershipExpiryPhase.Active);
                ProjectIdentityMembershipSummary metadata = await Execute(
                    MembershipOperations.GetProjectIdentityMembership(Org, project, Runtime));
                await Assert.That(metadata.Id).IsEqualTo(fence.MembershipId);
                await Assert.That(metadata.Roles.Count(r => r.Role == "no-access" && r.IsTemporary != true)).IsEqualTo(1);
                bool removed = expiryMode == "removed-expired-assignment" && phase == MembershipExpiryPhase.Expired;
                await Assert.That(metadata.Roles.Count).IsEqualTo(removed ? 1 : 2);
                if (!removed)
                {
                    var temporary = metadata.Roles.Single(r => r.IsTemporary == true);
                    await Assert.That(temporary.Id).IsEqualTo(assignmentId);
                    await Assert.That(temporary.Role).IsEqualTo("viewer");
                }
                // A denied target plus an expired credential is not expiry proof.
                return target != SecretStatus.Success && unaffected == SecretStatus.Success;
            }, token);
            await Assert.That(callbacks).IsEqualTo(1);
            await Assert.That(measured.Window.EventObserved).IsTrue();
            await Assert.That(measured.Window.OpenedAt).IsEqualTo(clock.GetUtcNow());
            await Assert.That(measured.Sample).IsEqualTo(phase != MembershipExpiryPhase.Active &&
                !(expiryMode == "expired-credential" && phase == MembershipExpiryPhase.Expired));
        }
        MembershipExpiryCleanup cleanup = await expiry.CloseAsync(attempt, token);
        await Assert.That(cleanup.Closed && cleanup.LateCreationFenced && cleanup.MutationSettled &&
            cleanup.InventoryComplete && cleanup.RemainingRegistrations == 0 && cleanup.PendingDeliveries == 0).IsTrue();
        await Execute(ProjectOperations.DeleteProject(Org, project));
        await Execute(ProjectOperations.DeleteProject(Org, control));
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
        await Assert.That(backend.UnrelatedStatePreserved).IsTrue();
    }

    [Test]
    public async Task TemporaryMembershipLostArmClosesClientKnownAttemptAndFencesLateDispatch()
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("temporal-good", clock);
        var expiry = new ControlledExpiryObserver(backend, clock, "lost-arm");
        var attempt = new MembershipExpiryAttempt(Guid.NewGuid().ToString(), "lost-arm-characterization",
            Org, Guid.NewGuid().ToString(), MembershipExpiryPrincipal.Identity, Runtime, Runtime, null,
            MembershipExpirySource.ControlledFixture);
        bool lost = false;
        try { await expiry.ArmAsync(new(attempt, "1m", 5), CancellationToken.None); }
        catch (IOException) { lost = true; }
        await Assert.That(lost).IsTrue();
        await Assert.That(expiry.Registrations).IsEqualTo(1);
        MembershipExpiryCleanup cleanup = await expiry.CloseAsync(attempt, CancellationToken.None);
        await Assert.That(cleanup.Attempt).IsEqualTo(attempt);
        await Assert.That(cleanup.RemainingRegistrations).IsEqualTo(0);
        await Assert.That(cleanup.PendingDeliveries).IsEqualTo(0);
        await Assert.That(cleanup.LateCreationFenced && cleanup.MutationSettled && cleanup.InventoryComplete).IsTrue();
        using var client = new HttpClient { BaseAddress = backend.Origin };
        using var request = new HttpRequestMessage(HttpMethod.Post,
            "/api/v1/projects/" + attempt.ProjectId + "/memberships/identities/" + Runtime);
        request.Headers.Authorization = new("Bearer", "administrative");
        request.Content = new StringContent(new JsonObject
        {
            ["roles"] = new JsonArray(new JsonObject
            {
                ["role"] = "viewer",
                ["isTemporary"] = true,
                ["temporaryMode"] = "relative",
                ["temporaryRange"] = "1m",
                ["temporaryAccessStartTime"] = clock.GetUtcNow().AddSeconds(5).ToString("O")
            })
        }.ToJsonString(), Encoding.UTF8, "application/json");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using HttpResponseMessage response = await client.SendAsync(request, deadline.Token);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
        await Assert.That(expiry.AppliedMutations).IsEqualTo(0);
        await Assert.That(expiry.CompleteCalls).IsEqualTo(0);
        await Assert.That(backend.ProjectCount).IsEqualTo(1);
    }

    [Test]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-profile")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-profile")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-profile")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-profile")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "nonobject-profile")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "nonobject-profile")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "nonobject-profile")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "nonobject-profile")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-nativeDuration")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-nativeDuration")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-nativeDuration")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-nativeDuration")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "blank-nativeDuration")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "blank-nativeDuration")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "blank-nativeDuration")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "blank-nativeDuration")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "nonstring-nativeDuration")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "nonstring-nativeDuration")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "nonstring-nativeDuration")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "nonstring-nativeDuration")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "zero-duration")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "zero-duration")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "zero-duration")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "zero-duration")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "invalid-duration")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "invalid-duration")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "invalid-duration")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "invalid-duration")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-activationLeadSeconds")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-activationLeadSeconds")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-activationLeadSeconds")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-activationLeadSeconds")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "zero-lead")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "zero-lead")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "zero-lead")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "zero-lead")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "negative-lead")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "negative-lead")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "negative-lead")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "negative-lead")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "noninteger-lead")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "noninteger-lead")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "noninteger-lead")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "noninteger-lead")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-sourceProfile")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-sourceProfile")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-sourceProfile")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-sourceProfile")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "blank-sourceProfile")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "blank-sourceProfile")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "blank-sourceProfile")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "blank-sourceProfile")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "invalid-source")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "invalid-source")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "invalid-source")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "invalid-source")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-expiredMetadata")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-expiredMetadata")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-expiredMetadata")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-expiredMetadata")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "blank-expiredMetadata")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "blank-expiredMetadata")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "blank-expiredMetadata")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "blank-expiredMetadata")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "nonstring-expiredMetadata")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "nonstring-expiredMetadata")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "nonstring-expiredMetadata")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "nonstring-expiredMetadata")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "invalid-policy")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "invalid-policy")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "invalid-policy")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "invalid-policy")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-setup")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-setup")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-setup")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-setup")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-denied")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-denied")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-denied")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-denied")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "alias-setup")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "alias-setup")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "alias-setup")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "alias-setup")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "alias-denied")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "alias-denied")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "alias-denied")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "alias-denied")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "owner-alias-setup")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "owner-alias-setup")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "owner-alias-setup")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "owner-alias-setup")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "owner-alias-denied")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "owner-alias-denied")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "owner-alias-denied")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "owner-alias-denied")]
    public async Task OrganizationGroupTemporalInvalidProfileFailsBeforeArmAndOwnership(string method, string policy, string fault)
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("ownership-temporal-good", clock);
        var source = new ControlledOrganizationExpiryObserver(backend, clock);
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true,
            organizationTemporalPolicy: policy, organizationTemporalFault: fault);
        var result = await RunAsync(environment, Definition("MembershipOperations." + method, "roles.relative-time"),
            organizationExpiryObserver: source);
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(source.ArmCalls + source.CompleteCalls + source.CloseCalls).IsEqualTo(0);
        await Assert.That(backend.OrganizationDispatches.Count + backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("AddOrganizationGroup")]
    [Arguments("UpdateOrganizationGroupRoles")]
    public async Task OrganizationGroupTemporalNativeProfileRequiresInjectedSourceBeforeOwnership(string method)
    {
        await using var backend = new Backend("ownership-temporal-good");
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true,
            organizationTemporalPolicy: "RetainedInactive", organizationTemporalFault: "native-without-source");
        var result = await RunAsync(environment, Definition("MembershipOperations." + method, "roles.relative-time"));
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.OrganizationDispatches.Count + backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "selected-contract")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "selected-contract")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "selected-contract")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "selected-contract")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "independent-effect")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "independent-effect")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "independent-effect")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "independent-effect")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "denied-authority")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "denied-authority")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "denied-authority")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "denied-authority")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "cancellation-boundary")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "cancellation-boundary")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "cancellation-boundary")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "cancellation-boundary")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "lost-response-no-replay")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "lost-response-no-replay")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "lost-response-no-replay")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "lost-response-no-replay")]
    public async Task OrganizationGroupTemporalRequiresScopedNativeExpiryEvidence(string method, string policy, string caseName)
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("ownership-temporal-good", clock);
        var source = new ControlledOrganizationExpiryObserver(backend, clock);
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true, organizationTemporalPolicy: policy);
        var result = await RunAsync(environment, Definition("MembershipOperations." + method, "roles.relative-time", caseName),
            organizationExpiryObserver: source);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(source.ArmCalls).IsEqualTo(1);
        await Assert.That(source.CompleteCalls).IsEqualTo(caseName == "cancellation-boundary" ? 0 : 1);
        await Assert.That(source.AppliedMutations).IsEqualTo(caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        await Assert.That(backend.TargetGroupMutations).IsEqualTo(caseName is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        if (caseName != "cancellation-boundary")
        {
            var fence = source.Completions.Single();
            await Assert.That(fence.Disposition).IsEqualTo(caseName == "denied-authority" ?
                MembershipExpiryDisposition.Rejected : MembershipExpiryDisposition.Applied);
            await Assert.That(fence.MutationOrganizationId).IsEqualTo(Org);
            await Assert.That(fence.MutationIdentityId).IsEqualTo(caseName == "denied-authority" ? Denied : Admin);
        }
        await Assert.That(source.Samples.SequenceEqual(Enum.GetValues<MembershipExpiryPhase>())).IsTrue();
        await Assert.That(source.CloseCalls).IsEqualTo(1);
        await Assert.That(source.Registrations).IsEqualTo(0);
        var arm = source.Arm!;
        await Assert.That(arm.ObservedScopes).IsEqualTo(Backend.AuthenticatedOrganizationScopes());
        await Assert.That(new[] { OwnerSetup, OwnerObserver, Setup, Admin, Observer, Runtime, Denied }.Distinct().Count()).IsEqualTo(7);
        await Assert.That(arm.Intent.Attempt.ExpiredMetadata).IsEqualTo(Enum.Parse<OrganizationGroupExpiredMetadata>(policy));
        foreach (var phase in Enum.GetValues<MembershipExpiryPhase>())
        {
            DateTimeOffset time = phase == MembershipExpiryPhase.BeforeActivation ? arm.ArmedAt :
                phase == MembershipExpiryPhase.Active ? arm.StartsAt : arm.EndsAt;
            int expected = phase == MembershipExpiryPhase.Active && caseName is not ("denied-authority" or "cancellation-boundary") ? 200 : 403;
            await Assert.That(backend.GroupAccesses.Any(a => a.Group == arm.Intent.Attempt.GroupId &&
                a.Credential == "runtime" && a.Time == time && a.Status == expected)).IsTrue();
            foreach (string credential in new[] { "owner-observer", "observer", "denied" })
                await Assert.That(backend.GroupAccesses.Any(a => a.Group == arm.Intent.Attempt.GroupId &&
                    a.Credential == credential && a.Time == time && a.Status == (credential == "denied" ? 403 : 200))).IsTrue();
            await Assert.That(backend.Accesses.Any(a => a.Credential == "runtime" && a.Time == time && a.Status == 200)).IsTrue();
        }
        await Assert.That(backend.OwnerUnlinkDispatches).IsEqualTo(0);
        await Assert.That(backend.GroupCount + backend.TargetLinkCount + backend.OrganizationRoleCount +
            backend.OwnerAssignmentCount + backend.OwnerRuntimeLinkCount + backend.ProjectCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "unbound-attempt")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "unbound-attempt")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "unbound-attempt")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "unbound-attempt")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-source")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-source")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-source")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-source")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-policy")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-policy")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-policy")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-policy")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-auth-context")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-auth-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-auth-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-auth-context")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-auth-context")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-auth-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-auth-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-auth-context")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-owner-context")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-owner-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-owner-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-owner-context")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-source")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-source")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-source")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-source")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "alias-source")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "alias-source")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "alias-source")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "alias-source")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-clock")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-clock")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-clock")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-clock")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-epoch")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-epoch")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-epoch")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-epoch")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "not-armed")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "not-armed")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "not-armed")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "not-armed")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-arm-time")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-arm-time")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-arm-time")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-arm-time")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-end-time")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-end-time")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-end-time")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-end-time")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-fence")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-fence")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-fence")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-fence")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-request")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-request")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-request")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-request")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-fence-sequence")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-fence-sequence")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-fence-sequence")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-fence-sequence")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-membership-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-membership-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-membership-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-membership-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-assignment-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-assignment-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-assignment-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-assignment-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-actor")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-actor")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-actor")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-actor")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-mutation-context")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-mutation-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-mutation-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-mutation-context")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "service-not-dispatched")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "service-not-dispatched")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "service-not-dispatched")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "service-not-dispatched")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-phase")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-phase")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-phase")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-phase")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-window-time")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-window-time")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-window-time")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-window-time")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-window-close")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-window-close")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-window-close")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-window-close")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-window-sequence")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-window-sequence")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-window-sequence")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-window-sequence")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-event")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-event")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-event")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-event")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "unauthoritative-window")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "unauthoritative-window")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "unauthoritative-window")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "unauthoritative-window")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-window-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-window-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-window-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-window-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-event-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-event-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-event-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-event-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-runtime-context")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-runtime-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-runtime-context")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-runtime-context")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-runtime-principal")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-runtime-principal")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-runtime-principal")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-runtime-principal")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "foreign-window-epoch")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "foreign-window-epoch")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "foreign-window-epoch")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "foreign-window-epoch")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "baseline-loss")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "baseline-loss")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "baseline-loss")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "baseline-loss")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "baseline-id-drift")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "baseline-id-drift")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "baseline-id-drift")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "baseline-id-drift")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "extra-role")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "extra-role")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "extra-role")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "extra-role")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "metadata-role-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "metadata-role-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "metadata-role-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "metadata-role-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "metadata-role-slug")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "metadata-role-slug")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "metadata-role-slug")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "metadata-role-slug")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "metadata-assignment-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "metadata-assignment-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "metadata-assignment-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "metadata-assignment-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "metadata-mode")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "metadata-mode")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "metadata-mode")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "metadata-mode")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "metadata-range")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "metadata-range")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "metadata-range")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "metadata-range")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "metadata-start")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "metadata-start")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "metadata-start")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "metadata-start")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "metadata-end")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "metadata-end")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "metadata-end")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "metadata-end")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "owner-link-drift")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "owner-link-drift")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "owner-link-drift")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "owner-link-drift")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "owner-assignment-drift")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "owner-assignment-drift")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "owner-assignment-drift")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "owner-assignment-drift")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "expired-token")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "expired-token")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "expired-token")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "expired-token")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "early-activation")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "early-activation")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "early-activation")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "early-activation")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "delayed-activation")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "delayed-activation")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "delayed-activation")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "delayed-activation")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "ignored-expiry")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "ignored-expiry")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "ignored-expiry")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "ignored-expiry")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "denied-commit")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "denied-commit")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "denied-commit")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "denied-commit")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "lost-arm")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "lost-arm")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "lost-arm")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "lost-arm")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "cleanup-open")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "cleanup-open")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "cleanup-open")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "cleanup-open")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "cleanup-late")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "cleanup-late")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "cleanup-late")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "cleanup-late")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "cleanup-unsettled")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "cleanup-unsettled")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "cleanup-unsettled")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "cleanup-unsettled")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "cleanup-inventory")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "cleanup-inventory")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "cleanup-inventory")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "cleanup-inventory")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "cleanup-registration")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "cleanup-registration")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "cleanup-registration")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "cleanup-registration")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "cleanup-pending")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "cleanup-pending")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "cleanup-pending")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "cleanup-pending")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "removed-against-policy")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "removed-against-policy")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "retained-against-policy")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "retained-against-policy")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-group-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-group-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-group-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-group-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-owner-membership-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-owner-membership-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-owner-membership-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-owner-membership-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-runtime-link-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-runtime-link-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-runtime-link-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-runtime-link-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-role-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-role-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-role-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-role-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "wrong-role-slug")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "wrong-role-slug")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "wrong-role-slug")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "wrong-role-slug")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-membership-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-membership-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-membership-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-membership-id")]
    [Arguments("AddOrganizationGroup", "RetainedInactive", "missing-assignment-id")]
    [Arguments("AddOrganizationGroup", "RemovedAssignment", "missing-assignment-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RetainedInactive", "missing-assignment-id")]
    [Arguments("UpdateOrganizationGroupRoles", "RemovedAssignment", "missing-assignment-id")]
    public async Task OrganizationGroupTemporalFaultMustBeReachedAndCannotCertify(string method, string policy, string fault)
    {
        var clock = new AuthorizationClock();
        await using var backend = new Backend("ownership-temporal-" + fault, clock);
        var source = new ControlledOrganizationExpiryObserver(backend, clock, fault);
        using NativeEnvironment environment = Environment(backend.Origin, temporal: true, organizationTemporalPolicy: policy);
        var result = await RunAsync(environment, Definition("MembershipOperations." + method, "roles.relative-time",
            fault == "denied-commit" ? "denied-authority" : "independent-effect"), organizationExpiryObserver: source);
        await Assert.That(result.Passed).IsFalse();
        // The old unavailable gate must not make an adversarial test pass.
        await Assert.That(source.ArmCalls).IsEqualTo(1);
        await Assert.That(source.FaultApplied).IsTrue();
        await Assert.That(source.CloseCalls).IsEqualTo(1);
        if (fault.StartsWith("cleanup-", StringComparison.Ordinal))
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        if (fault == "denied-commit")
        {
            await Assert.That(source.Completions.Single().Disposition).IsEqualTo(MembershipExpiryDisposition.Applied);
            await Assert.That(source.Completions.Single().MutationIdentityId).IsEqualTo(Denied);
        }
        if (fault == "lost-arm") await Assert.That(source.CompleteCalls).IsEqualTo(0);
        await Assert.That(backend.OwnerUnlinkDispatches).IsEqualTo(0);
    }

    private static NativeCaseDefinition Definition(string operation, string variant, string caseName = "independent-effect")
    {
        string id = "i.management." + operation;
        return new(new("Infisical", id, variant, "local", caseName), InfisicalProjectFamilies.Bindings[id].Member);
    }

    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment environment, NativeCaseDefinition definition,
        IMembershipExpiryObserver? expiryObserver = null, IOrganizationGroupExpiryObserver? organizationExpiryObserver = null)
    {
        var registry = new NativeCaseRegistry();
        InfisicalProjectFamilies.Register(registry, environment, [definition], expiryObserver, organizationExpiryObserver);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(
            expiryObserver is null && organizationExpiryObserver is null ? 15 : 120));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }

    private static NativeEnvironment Environment(Uri origin, bool inputs = true,
        bool mixed = false, string? secondaryFault = null, bool temporal = false, string? temporalFault = null,
        string? ownerFault = null, string? organizationTemporalPolicy = null, string? organizationTemporalFault = null)
    {
        var families = new Dictionary<string, object>();
        if (inputs)
            foreach (string family in new[] { "Projects", "ProjectTemplates", "ProjectMemberships", "MembershipMutations", "Memberships" })
                families.Add("C08-IM-" + family, new
                {
                    scopes = new Dictionary<string, object>
                    {
                        ["local"] = new
                        {
                            organizationId = Org,
                            setupIdentityId = Setup,
                            deniedIdentityId = Denied,
                            administrativeIdentityId = Admin,
                            observerIdentityId = Observer,
                            runtimeIdentityId = Runtime,
                            runtimeUsername = "fixture-user",
                            runtimeUserId = User,
                            runtimeEmail = "fixture@example.invalid"
                        }
                    }
                });
        JsonObject settings = JsonSerializer.SerializeToNode(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            administrative = "administrative",
            observer = "observer",
            runtime = "runtime",
            denied = "denied",
            families
        })!.AsObject();
        if (inputs)
        {
            JsonObject scope = settings["families"]!["C08-IM-Memberships"]!["scopes"]!["local"]!.AsObject();
            var owner = new JsonObject
            {
                ["organizationId"] = OwnerOrg,
                ["setupIdentityId"] = OwnerSetup,
                ["observerIdentityId"] = OwnerObserver,
                ["setupToken"] = "owner-setup",
                ["observerToken"] = "owner-observer"
            };
            scope["groupOwner"] = owner;
            if (ownerFault == "missing-profile") scope.Remove("groupOwner");
            else if (ownerFault == "nonobject-profile") scope["groupOwner"] = "invalid";
            else if (ownerFault is not null)
            {
                string[] parts = ownerFault.Split('-', 2);
                if (parts[0] == "missing") owner.Remove(parts[1]);
                if (parts[0] == "blank") owner[parts[1]] = " ";
                if (parts[0] == "nonstring") owner[parts[1]] = 42;
                if (parts[0] == "invalid") owner[parts[1]] = "not-a-uuid";
                if (ownerFault == "same-organization") owner["organizationId"] = Org;
                if (ownerFault == "same-principal") owner["observerIdentityId"] = OwnerSetup;
                if (ownerFault == "same-token") owner["observerToken"] = "owner-setup";
                if (ownerFault == "setup-admin-principal") owner["setupIdentityId"] = Admin;
                if (ownerFault == "observer-runtime-principal") owner["observerIdentityId"] = Runtime;
                if (ownerFault == "setup-observer-principal") owner["setupIdentityId"] = Observer;
                if (ownerFault == "setup-runtime-principal") owner["setupIdentityId"] = Runtime;
                if (ownerFault == "observer-admin-principal") owner["observerIdentityId"] = Admin;
                if (ownerFault == "observer-observer-principal") owner["observerIdentityId"] = Observer;
                if (ownerFault == "setup-target-token") owner["setupToken"] = "administrative";
                if (ownerFault == "observer-target-token") owner["observerToken"] = "observer";
                if (ownerFault.StartsWith("setup-alias-", StringComparison.Ordinal))
                    owner["setupToken"] = ownerFault["setup-alias-".Length..];
                if (ownerFault.StartsWith("observer-alias-", StringComparison.Ordinal))
                    owner["observerToken"] = ownerFault["observer-alias-".Length..];
            }
        }
        if (temporal)
        {
            foreach (string family in new[] { "Memberships", "ProjectMemberships" })
            {
                JsonObject scope = settings["families"]!["C08-IM-" + family]!["scopes"]!["local"]!.AsObject();
                scope["caseTimeoutSeconds"] = 120;
                scope["temporal"] = new JsonObject
                {
                    ["nativeDuration"] = "1m",
                    ["activationLeadSeconds"] = 5,
                    ["sourceProfile"] = "ControlledFixture"
                };
                if (family == "Memberships" && organizationTemporalPolicy is not null)
                    scope["temporal"]!["expiredMetadata"] = organizationTemporalPolicy;
                if (temporalFault == "absent-temporal") scope.Remove("temporal");
                if (temporalFault == "absent-duration") scope["temporal"]!.AsObject().Remove("nativeDuration");
                if (temporalFault == "absent-lead") scope["temporal"]!.AsObject().Remove("activationLeadSeconds");
                if (temporalFault == "absent-source") scope["temporal"]!.AsObject().Remove("sourceProfile");
                if (temporalFault == "colliding-window") scope["temporal"]!["activationLeadSeconds"] = 0;
                if (temporalFault == "colliding-duration") scope["temporal"]!["nativeDuration"] = "0m";
            }
        }
        if (mixed)
        {
            JsonObject scope = settings["families"]!["C08-IM-MembershipMutations"]!["scopes"]!["local"]!.AsObject();
            scope["secondRuntimeUsername"] = "fixture-second-user";
            scope["secondRuntimeUserId"] = SecondUser;
            scope["secondRuntimeEmail"] = "fixture-second@example.invalid";
            scope["secondRuntimeToken"] = "second-runtime";
            string? field = secondaryFault switch
            {
                "missing-username" or "colliding-username" => "secondRuntimeUsername",
                "missing-user-id" or "colliding-user-id" => "secondRuntimeUserId",
                "missing-email" or "colliding-email" => "secondRuntimeEmail",
                "missing-token" or "colliding-token" => "secondRuntimeToken",
                _ => null
            };
            if (field is not null)
            {
                if (secondaryFault!.StartsWith("missing-", StringComparison.Ordinal)) scope.Remove(field);
                else scope[field] = field switch
                {
                    "secondRuntimeUsername" => "fixture-user",
                    "secondRuntimeUserId" => User,
                    "secondRuntimeEmail" => "fixture@example.invalid",
                    _ => "runtime"
                };
            }
        }
        if (organizationTemporalFault is not null)
        {
            JsonObject scope = settings["families"]!["C08-IM-Memberships"]!["scopes"]!["local"]!.AsObject();
            JsonObject profile = scope["temporal"]!.AsObject();
            string[] parts = organizationTemporalFault.Split('-', 2);
            if (parts[0] == "missing") profile.Remove(parts[1]);
            if (parts[0] == "blank") profile[parts[1]] = " ";
            if (parts[0] == "nonstring") profile[parts[1]] = 42;
            if (organizationTemporalFault == "invalid-policy") profile["expiredMetadata"] = "InferredOrganizationDefault";
            if (organizationTemporalFault == "invalid-source") profile["sourceProfile"] = "inferred";
            if (organizationTemporalFault == "zero-lead") profile["activationLeadSeconds"] = 0;
            if (organizationTemporalFault == "negative-lead") profile["activationLeadSeconds"] = -1;
            if (organizationTemporalFault == "noninteger-lead") profile["activationLeadSeconds"] = "5";
            if (organizationTemporalFault == "zero-duration") profile["nativeDuration"] = "0m";
            if (organizationTemporalFault == "invalid-duration") profile["nativeDuration"] = "minute";
            if (organizationTemporalFault == "missing-profile") scope.Remove("temporal");
            if (organizationTemporalFault == "nonobject-profile") scope["temporal"] = "invalid";
            if (organizationTemporalFault == "missing-setup") scope.Remove("setupIdentityId");
            if (organizationTemporalFault == "missing-denied") scope.Remove("deniedIdentityId");
            if (organizationTemporalFault == "alias-setup") scope["setupIdentityId"] = Admin;
            if (organizationTemporalFault == "alias-denied") scope["deniedIdentityId"] = Runtime;
            if (organizationTemporalFault == "owner-alias-setup") scope["groupOwner"]!["setupIdentityId"] = Setup;
            if (organizationTemporalFault == "owner-alias-denied") scope["groupOwner"]!["observerIdentityId"] = Denied;
            if (organizationTemporalFault == "native-without-source") profile["sourceProfile"] = "NativeProvider";
        }
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(settings));
    }

    private sealed class AuthorizationClock : TimeProvider
    {
        private DateTimeOffset now = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => now;
        internal event Action? Changed;
        internal void AdvanceTo(DateTimeOffset value)
        {
            if (value < now) throw new InvalidOperationException("fixture-clock-regression");
            now = value;
            Changed?.Invoke();
        }
    }

    // The source reports clocks, contexts and terminal requests, never access
    // booleans. All permission samples go through the public SDK and bearer map.
    private sealed class ControlledOrganizationExpiryObserver : IOrganizationGroupExpiryObserver
    {
        private readonly Backend backend;
        private readonly AuthorizationClock clock;
        private readonly string fault;
        private readonly Dictionary<string, OrganizationGroupExpiryArm> registrations = [];
        private readonly Dictionary<string, TaskCompletionSource<OrganizationGroupExpiryFence>> terminals = [];
        private readonly Dictionary<string, string> closedGroups = [];
        private readonly HashSet<string> pendingDeliveries = [];
        private long sequence;
        internal int ArmCalls { get; private set; }
        internal int CompleteCalls { get; private set; }
        internal int CloseCalls { get; private set; }
        internal int AppliedMutations { get; private set; }
        internal int Registrations => registrations.Count;
        internal bool FaultApplied { get; private set; }
        internal OrganizationGroupExpiryArm? Arm { get; private set; }
        internal List<MembershipExpiryPhase> Samples { get; } = [];
        internal List<OrganizationGroupExpiryFence> Completions { get; } = [];

        internal ControlledOrganizationExpiryObserver(Backend backend, AuthorizationClock clock, string fault = "good")
        {
            this.backend = backend;
            this.clock = clock;
            this.fault = fault;
            backend.OrganizationExpiryObserver = this;
        }

        public ValueTask<OrganizationGroupExpiryArm> ArmAsync(OrganizationGroupExpiryIntent intent, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            ArmCalls++;
            var arm = new OrganizationGroupExpiryArm(intent, Guid.NewGuid().ToString(), "fixture-org-expiry-source",
                "fixture-org-authorization-clock", "fixture-org-epoch", clock.GetUtcNow(),
                clock.GetUtcNow().AddSeconds(intent.ActivationLeadSeconds),
                clock.GetUtcNow().AddSeconds(intent.ActivationLeadSeconds).AddMinutes(1), ++sequence, true,
                Backend.AuthenticatedOrganizationScopes(), true);
            registrations.Add(intent.Attempt.Id, arm);
            terminals.Add(intent.Attempt.Id, new(TaskCreationOptions.RunContinuationsAsynchronously));
            Arm = arm;
            if (fault == "lost-arm")
            {
                FaultApplied = true;
                throw new IOException("fixture-lost-org-arm-reply");
            }
            OrganizationGroupExpiryArm returned = fault switch
            {
                "unbound-attempt" => arm with { Intent = intent with { Attempt = intent.Attempt with { Id = Guid.NewGuid().ToString() } } },
                "wrong-source" => arm with { Intent = intent with { Attempt = intent.Attempt with { Source = MembershipExpirySource.NativeProvider } } },
                "wrong-policy" => arm with
                {
                    Intent = intent with
                    {
                        Attempt = intent.Attempt with
                        {
                            ExpiredMetadata = intent.Attempt.ExpiredMetadata == OrganizationGroupExpiredMetadata.RetainedInactive ?
                                OrganizationGroupExpiredMetadata.RemovedAssignment : OrganizationGroupExpiredMetadata.RetainedInactive
                        }
                    }
                },
                "missing-auth-context" => arm with { AuthenticatedScopesObserved = false },
                "wrong-auth-context" => arm with { ObservedScopes = arm.ObservedScopes with { TargetRuntimeIdentityId = User } },
                "wrong-owner-context" => arm with { ObservedScopes = arm.ObservedScopes with { OwnerOrganizationId = Org } },
                "missing-source" => arm with { SourceIdentity = "" },
                "alias-source" => arm with { SourceIdentity = "observer" },
                "missing-clock" => arm with { ClockAuthority = "" },
                "wrong-epoch" => arm with { ClockEpoch = "" },
                "not-armed" => arm with { CaptureArmed = false },
                "wrong-arm-time" => arm with { StartsAt = arm.ArmedAt },
                "wrong-end-time" => arm with { EndsAt = arm.StartsAt },
                "wrong-group-id" => arm with { Intent = intent with { Attempt = intent.Attempt with { GroupId = Guid.NewGuid().ToString() } } },
                "wrong-owner-membership-id" => arm with { Intent = intent with { Attempt = intent.Attempt with { OwnerMembershipId = Guid.NewGuid().ToString() } } },
                "wrong-runtime-link-id" => arm with { Intent = intent with { Attempt = intent.Attempt with { RuntimeLinkId = Guid.NewGuid().ToString() } } },
                "wrong-role-id" => arm with { Intent = intent with { Attempt = intent.Attempt with { RoleId = Guid.NewGuid().ToString() } } },
                "wrong-role-slug" => arm with { Intent = intent with { Attempt = intent.Attempt with { RoleSlug = "other" } } },
                _ => arm
            };
            FaultApplied |= returned != arm;
            return ValueTask.FromResult(returned);
        }

        internal bool IsClosedMutation(Uri uri, JsonObject body) =>
            body["roles"] is JsonArray roles && roles.Any(r => r!["isTemporary"]?.GetValue<bool>() == true) &&
            closedGroups.Values.Any(group => uri.AbsolutePath.EndsWith("/groups/" + group, StringComparison.Ordinal));

        internal void Capture(string method, Uri uri, string credential, JsonObject body, int status)
        {
            if (method is not ("POST" or "PATCH") ||
                !uri.AbsolutePath.StartsWith("/api/v1/organizations/", StringComparison.Ordinal) ||
                body["roles"] is not JsonArray roles || !roles.Any(r => r!["isTemporary"]?.GetValue<bool>() == true))
                return;
            foreach (OrganizationGroupExpiryArm arm in registrations.Values)
            {
                OrganizationGroupExpiryAttempt attempt = arm.Intent.Attempt;
                if (!uri.AbsolutePath.EndsWith("/groups/" + attempt.GroupId, StringComparison.Ordinal)) continue;
                JsonObject? member = backend.OrganizationMembershipSnapshot(attempt.GroupId);
                bool applied = status == 200 && member is not null &&
                    member["roles"]!.AsArray().Any(r => r!["isTemporary"]?.GetValue<bool>() == true);
                var actor = Backend.AuthenticatedActor(credential);
                string? assignment = applied ? member!["roles"]!.AsArray()
                    .Single(r => r!["isTemporary"]?.GetValue<bool>() == true)!["id"]!.GetValue<string>() : null;
                var fence = new OrganizationGroupExpiryFence(arm, Guid.NewGuid().ToString(),
                    applied ? MembershipExpiryDisposition.Applied : MembershipExpiryDisposition.Rejected,
                    member?["id"]?.GetValue<string>(), assignment, actor.Organization, actor.Principal, ++sequence, true);
                if (!terminals[attempt.Id].TrySetResult(fence)) throw new InvalidOperationException("fixture-org-replayed");
                pendingDeliveries.Add(attempt.Id);
                if (applied) AppliedMutations++;
                FaultApplied |= fault == "denied-commit" && applied && credential == "denied";
            }
        }

        public async ValueTask<OrganizationGroupExpiryFence> CompleteAsync(OrganizationGroupExpiryArm arm, CancellationToken token)
        {
            CompleteCalls++;
            OrganizationGroupExpiryFence fence = await terminals[arm.Intent.Attempt.Id].Task.WaitAsync(token);
            if (fault != "cleanup-pending") pendingDeliveries.Remove(arm.Intent.Attempt.Id);
            Completions.Add(fence);
            OrganizationGroupExpiryFence returned = fault switch
            {
                "missing-fence" => fence with { ExcludesLateCommit = false },
                "missing-request" => fence with { ProviderRequestId = null },
                "missing-membership-id" => fence with { TargetMembershipId = null },
                "missing-assignment-id" => fence with { TemporaryAssignmentId = null },
                "wrong-fence-sequence" => fence with { Sequence = arm.Cursor },
                "wrong-membership-id" => fence with { TargetMembershipId = Guid.NewGuid().ToString() },
                "wrong-assignment-id" => fence with { TemporaryAssignmentId = Guid.NewGuid().ToString() },
                "wrong-actor" => fence with { MutationIdentityId = Setup },
                "wrong-mutation-context" => fence with { MutationOrganizationId = OwnerOrg },
                "service-not-dispatched" => fence with { Disposition = MembershipExpiryDisposition.NotDispatched },
                _ => fence
            };
            FaultApplied |= returned != fence;
            return returned;
        }

        public async ValueTask<OrganizationGroupExpiryObservation<T>> ObserveAsync<T>(OrganizationGroupExpiryFence binding,
            MembershipExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token)
        {
            sequence = Math.Max(sequence, binding.Sequence);
            DateTimeOffset time = phase switch
            {
                MembershipExpiryPhase.BeforeActivation => binding.Arm.ArmedAt,
                MembershipExpiryPhase.Active => binding.Arm.StartsAt,
                _ => binding.Arm.EndsAt
            };
            var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            void Changed() => reached.TrySetResult();
            clock.Changed += Changed;
            try
            {
                clock.AdvanceTo(time);
                await reached.Task.WaitAsync(token);
            }
            finally { clock.Changed -= Changed; }
            FaultApplied |= backend.ApplyOrganizationTemporalPhase(binding.Arm.Intent.Attempt, phase, fault);
            var window = new OrganizationGroupExpiryWindow(binding, phase, Guid.NewGuid().ToString(),
                Guid.NewGuid().ToString(), ++sequence, clock.GetUtcNow(), clock.GetUtcNow(), true, true, Org, Runtime);
            Samples.Add(phase);
            T value = await sample(token);
            OrganizationGroupExpiryWindow returned = fault switch
            {
                "wrong-phase" => window with
                {
                    Phase = phase == MembershipExpiryPhase.Active ?
                        MembershipExpiryPhase.Expired : MembershipExpiryPhase.Active
                },
                "wrong-window-time" => window with { OpenedAt = binding.Arm.EndsAt.AddMinutes(1) },
                "wrong-window-close" => window with { ClosedAt = window.OpenedAt.AddSeconds(-1) },
                "wrong-window-sequence" => window with { Sequence = binding.Sequence },
                "missing-event" => window with { EventObserved = false },
                "unauthoritative-window" => window with { Authoritative = false },
                "missing-window-id" => window with { WindowId = "" },
                "missing-event-id" => window with { EventId = "" },
                "wrong-runtime-context" => window with { RuntimeOrganizationId = OwnerOrg },
                "wrong-runtime-principal" => window with { RuntimeIdentityId = User },
                "foreign-window-epoch" => window with { Binding = binding with { Arm = binding.Arm with { ClockEpoch = "foreign" } } },
                _ => window
            };
            FaultApplied |= returned != window;
            return new(returned, value);
        }

        public ValueTask<OrganizationGroupExpiryCleanup> CloseAsync(OrganizationGroupExpiryAttempt attempt, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            CloseCalls++;
            closedGroups[attempt.Id] = attempt.GroupId;
            if (fault != "cleanup-registration") registrations.Remove(attempt.Id);
            bool settled = !terminals.TryGetValue(attempt.Id, out var terminal) || terminal.Task.IsCompleted ||
                CompleteCalls == 0;
            terminals.Remove(attempt.Id);
            if (fault != "cleanup-pending") pendingDeliveries.Remove(attempt.Id);
            FaultApplied |= fault.StartsWith("cleanup-", StringComparison.Ordinal);
            return ValueTask.FromResult(new OrganizationGroupExpiryCleanup(attempt, fault != "cleanup-open",
                fault != "cleanup-late", settled && fault != "cleanup-unsettled", fault != "cleanup-inventory",
                registrations.Count, pendingDeliveries.Count));
        }
    }

    private sealed class ControlledExpiryObserver : IMembershipExpiryObserver
    {
        private readonly Backend backend;
        private readonly AuthorizationClock clock;
        private readonly string fault;
        private readonly Dictionary<string, MembershipExpiryArm> registrations = [];
        private readonly Dictionary<string, TaskCompletionSource<MembershipExpiryFence>> terminals = [];
        private readonly HashSet<string> closed = [];
        private readonly Dictionary<string, string> attemptProjects = [];
        private long sequence;
        internal int CompleteCalls { get; private set; }
        internal int AppliedMutations { get; private set; }
        internal int CloseCalls { get; private set; }
        internal int Registrations => registrations.Count;
        internal List<MembershipExpiryPhase> Samples { get; } = [];
        internal List<MembershipExpiryFence> Completions { get; } = [];
        internal MembershipExpiryAttempt? LastAttempt { get; private set; }
        internal MembershipExpiryArm? Arm { get; private set; }
        internal JsonObject? CapturedMembership { get; private set; }

        internal ControlledExpiryObserver(Backend backend, AuthorizationClock clock, string fault = "good")
        {
            this.backend = backend;
            this.clock = clock;
            this.fault = fault;
            backend.ExpiryObserver = this;
        }

        public ValueTask<MembershipExpiryArm> ArmAsync(MembershipExpiryIntent intent, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            LastAttempt = intent.Attempt;
            attemptProjects.Add(intent.Attempt.Id, intent.Attempt.ProjectId);
            var arm = new MembershipExpiryArm(intent, Guid.NewGuid().ToString(), "fixture-expiry-capture",
                "fixture-authorization-clock", "fixture-epoch", clock.GetUtcNow(),
                clock.GetUtcNow().AddSeconds(intent.ActivationLeadSeconds),
                clock.GetUtcNow().AddSeconds(intent.ActivationLeadSeconds).AddMinutes(1), ++sequence, true);
            registrations.Add(intent.Attempt.Id, arm);
            Arm = arm;
            terminals.Add(intent.Attempt.Id, new(TaskCreationOptions.RunContinuationsAsynchronously));
            if (fault == "lost-arm") throw new IOException("fixture-lost-arm-reply");
            return ValueTask.FromResult(fault switch
            {
                "unbound-attempt" => arm with { Intent = intent with { Attempt = intent.Attempt with { Id = "unbound" } } },
                "bad-clock-epoch" => arm with { ClockEpoch = "" },
                "alias-observer" => arm with { SourceIdentity = "observer" },
                "bad-window-time" => arm with { EndsAt = arm.StartsAt },
                _ => arm
            });
        }

        // Registered before dispatch. A real handled request, including denied or
        // applied-with-lost-response, supplies the terminal signal, never Complete.
        internal void Capture(string method, Uri uri, string credential, JsonObject body, int status)
        {
            if (method is not ("POST" or "PATCH") ||
                !uri.AbsolutePath.Contains("/memberships", StringComparison.Ordinal) ||
                body["roles"] is not JsonArray roles ||
                !roles.Any(r => r!["isTemporary"]?.GetValue<bool>() == true))
                return;
            foreach (MembershipExpiryArm arm in registrations.Values)
            {
                MembershipExpiryAttempt attempt = arm.Intent.Attempt;
                if (!uri.AbsolutePath.Contains("/" + attempt.ProjectId + "/", StringComparison.Ordinal)) continue;
                if (closed.Contains(attempt.Id)) throw new InvalidOperationException("fixture-late-mutation");
                var member = backend.MembershipSnapshot(attempt.ProjectId, attempt.PrincipalId);
                CapturedMembership = member;
                string? assignment = member?["roles"]?.AsArray()
                    .SingleOrDefault(r => r!["isTemporary"]?.GetValue<bool>() == true)?["id"]?.GetValue<string>();
                bool applied = status == 200;
                if (applied) AppliedMutations++;
                var fence = new MembershipExpiryFence(arm, Guid.NewGuid().ToString(),
                    applied ? MembershipExpiryDisposition.Applied : MembershipExpiryDisposition.Rejected,
                    member?["id"]?.GetValue<string>(), applied ? assignment : null, ++sequence, true);
                if (!terminals[attempt.Id].TrySetResult(fence))
                    throw new InvalidOperationException("fixture-mutation-replayed");
            }
        }

        internal bool IsClosedMutation(Uri uri, JsonObject body) =>
            body["roles"] is JsonArray roles && roles.Any(r => r!["isTemporary"]?.GetValue<bool>() == true) &&
            closed.Any(id => uri.AbsolutePath.Contains("/" + attemptProjects[id] + "/", StringComparison.Ordinal));

        public async ValueTask<MembershipExpiryFence> CompleteAsync(MembershipExpiryArm arm, CancellationToken token)
        {
            CompleteCalls++;
            MembershipExpiryFence fence = await terminals[arm.Intent.Attempt.Id].Task.WaitAsync(token);
            Completions.Add(fence);
            return fault switch
            {
                "missing-completion-fence" => fence with { ExcludesLateCommit = false },
                "different-assignment-id" => fence with { AssignmentId = Guid.NewGuid().ToString() },
                "different-member-id" => fence with { MembershipId = Guid.NewGuid().ToString() },
                "bad-sequence" => fence with { Sequence = arm.Cursor },
                _ => fence
            };
        }

        public async ValueTask<MembershipExpiryObservation<T>> ObserveAsync<T>(MembershipExpiryFence binding,
            MembershipExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token)
        {
            // A local before-send fence also advances the shared observation
            // cursor; the next captured event must follow that bound marker.
            sequence = Math.Max(sequence, binding.Sequence);
            DateTimeOffset time = phase switch
            {
                MembershipExpiryPhase.BeforeActivation => binding.Arm.ArmedAt,
                MembershipExpiryPhase.Active => binding.Arm.StartsAt,
                _ => binding.Arm.EndsAt
            };
            // Subscribe before advancing the actual authorization clock. This
            // event is delivered even though it fires synchronously in AdvanceTo.
            var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            void Changed() => reached.TrySetResult();
            clock.Changed += Changed;
            try
            {
                clock.AdvanceTo(time);
                await reached.Task.WaitAsync(token);
            }
            finally { clock.Changed -= Changed; }
            backend.CorruptTemporalState(binding.Arm.Intent.Attempt, phase, fault, time);
            var window = new MembershipExpiryWindow(binding, phase, Guid.NewGuid().ToString(),
                Guid.NewGuid().ToString(), ++sequence, clock.GetUtcNow(), clock.GetUtcNow(), true, true);
            Samples.Add(phase);
            T result = await sample(token);
            window = fault switch
            {
                "bad-phase" => window with
                {
                    Phase = phase == MembershipExpiryPhase.Active ?
                        MembershipExpiryPhase.Expired : MembershipExpiryPhase.Active
                },
                "bad-phase-time" => window with { OpenedAt = binding.Arm.EndsAt.AddMinutes(1) },
                "bad-window-close" => window with { ClosedAt = window.OpenedAt.AddSeconds(-1) },
                "unobserved-event" => window with { EventObserved = false },
                "bad-window-sequence" => window with { Sequence = binding.Sequence },
                "different-window-epoch" => window with
                {
                    Binding = binding with
                    {
                        Arm = binding.Arm with { ClockEpoch = "foreign-epoch" }
                    }
                },
                _ => window
            };
            return new(window, result);
        }

        public ValueTask<MembershipExpiryCleanup> CloseAsync(MembershipExpiryAttempt attempt, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            CloseCalls++;
            closed.Add(attempt.Id);
            registrations.Remove(attempt.Id);
            bool settled = !terminals.TryGetValue(attempt.Id, out var terminal) || terminal.Task.IsCompleted ||
                AppliedMutations == 0;
            terminals.Remove(attempt.Id);
            return ValueTask.FromResult(new MembershipExpiryCleanup(attempt, true,
                fault != "late-mutation", settled, fault != "cleanup-inventory",
                fault == "cleanup-leftovers" ? 1 : registrations.Count,
                fault == "cleanup-pending" ? 1 : 0));
        }
    }

    // Stateful loopback characterization through the same public package APIs.
    // This server cannot emit native evidence and has no path to a real provider.
    private sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, JsonObject> projects = [];
        private readonly Dictionary<string, JsonObject> tags = [];
        private readonly Dictionary<string, JsonObject> environments = [];
        private readonly Dictionary<string, JsonObject> templates = [];
        private readonly Dictionary<(string Project, string Role), JsonArray> permissions = [];
        private readonly Dictionary<string, JsonObject> groups = [];
        private readonly Dictionary<string, JsonObject> organizationRoles = [];
        private readonly Dictionary<string, JsonObject> organizationGroups = [];
        private readonly Dictionary<string, JsonObject> ownerAssignments = [];
        private readonly Dictionary<string, string> ownerIdentityLinks = [];
        private readonly Dictionary<string, string> groupPrincipals = [];
        private readonly Dictionary<(string Project, string Principal), JsonObject> members = [];
        private readonly Dictionary<(string Project, string Environment, string Key), string> secrets = [];
        private readonly Dictionary<(string Project, string Environment, string Key), JsonObject> attributes = [];
        private readonly Task accept;
        private readonly string mode;
        private readonly TimeProvider clock;
        private DateTimeOffset? credentialExpiresAt;
        internal ControlledExpiryObserver? ExpiryObserver { get; set; }
        internal ControlledOrganizationExpiryObserver? OrganizationExpiryObserver { get; set; }
        internal Uri Origin { get; }
        internal int AdministrativeTagCreates { get; private set; }
        internal int RuntimeReads { get; private set; }
        internal int AdministrativeMemberMutations { get; private set; }
        internal int FirstAllowedReads { get; private set; }
        internal int FirstDeniedReads { get; private set; }
        internal int SecondAllowedReads { get; private set; }
        internal int SecondDeniedReads { get; private set; }
        internal int FirstMembershipReads { get; private set; }
        internal int SecondMembershipReads { get; private set; }
        internal int DeniedCanaryReads { get; private set; }
        internal int OwnedProjectDeletes { get; private set; }
        internal int OwnerGroupCreates { get; private set; }
        internal int OwnerUnlinkDispatches { get; private set; }
        internal int TargetGroupMutations { get; private set; }
        internal int TargetUnlinks { get; private set; }
        internal int RuntimeGroupAllowed { get; private set; }
        internal int RuntimeGroupDenied { get; private set; }
        internal int GroupCount { get { lock (projects) return groups.Count; } }
        internal int OrganizationRoleCount { get { lock (projects) return organizationRoles.Count; } }
        internal int TargetLinkCount { get { lock (projects) return organizationGroups.Count; } }
        internal int OwnerAssignmentCount { get { lock (projects) return ownerAssignments.Count; } }
        internal int OwnerRuntimeLinkCount { get { lock (projects) return ownerIdentityLinks.Count; } }
        internal List<(string Method, string Path, string Credential)> OrganizationDispatches { get; } = [];
        internal List<(string Group, string Credential, DateTimeOffset Time, int Status)> GroupAccesses { get; } = [];
        internal List<JsonObject> OrganizationTemporalRequests { get; } = [];
        internal static (string Organization, string Principal) AuthenticatedActor(string credential) => credential switch
        {
            "owner-setup" => (OwnerOrg, OwnerSetup),
            "owner-observer" => (OwnerOrg, OwnerObserver),
            "setup" => (Org, Setup),
            "administrative" => (Org, Admin),
            "observer" => (Org, Observer),
            "runtime" => (Org, Runtime),
            "denied" => (Org, Denied),
            _ => throw new InvalidOperationException("fixture-unknown-bearer")
        };
        internal static OrganizationGroupExpiryScopes AuthenticatedOrganizationScopes()
        {
            var ownerSetup = AuthenticatedActor("owner-setup");
            var ownerObserver = AuthenticatedActor("owner-observer");
            var setup = AuthenticatedActor("setup");
            return new(ownerSetup.Organization, ownerSetup.Principal, ownerObserver.Principal,
                setup.Organization, setup.Principal, AuthenticatedActor("administrative").Principal,
                AuthenticatedActor("observer").Principal, AuthenticatedActor("runtime").Principal,
                AuthenticatedActor("denied").Principal);
        }
        internal JsonObject? OrganizationMembershipSnapshot(string group)
        {
            lock (projects) return organizationGroups.GetValueOrDefault(group)?.DeepClone().AsObject();
        }
        internal bool ApplyOrganizationTemporalPhase(OrganizationGroupExpiryAttempt attempt,
            MembershipExpiryPhase phase, string fault)
        {
            lock (projects)
            {
                bool changed = false;
                if (fault == "expired-token" && phase == MembershipExpiryPhase.Expired)
                {
                    credentialExpiresAt = clock.GetUtcNow();
                    changed = true;
                }
                if (fault == "owner-link-drift")
                {
                    changed |= ownerIdentityLinks.Remove(attempt.GroupId);
                    groupPrincipals.Remove(attempt.GroupId);
                }
                if (fault == "owner-assignment-drift" && ownerAssignments.TryGetValue(attempt.GroupId, out var owner))
                {
                    owner["roles"]![0]!["role"] = "viewer";
                    changed = true;
                }
                if (!organizationGroups.TryGetValue(attempt.GroupId, out var member)) return changed;
                JsonArray roles = member["roles"]!.AsArray();
                JsonNode? temporary = roles.SingleOrDefault(r => r!["isTemporary"]?.GetValue<bool>() == true);
                if (phase == MembershipExpiryPhase.Expired &&
                    attempt.ExpiredMetadata == OrganizationGroupExpiredMetadata.RemovedAssignment &&
                    fault is not ("retained-against-policy" or "ignored-expiry") && temporary is not null)
                {
                    roles.Remove(temporary);
                    temporary = null;
                }
                if (fault == "removed-against-policy" && phase == MembershipExpiryPhase.Expired && temporary is not null)
                {
                    roles.Remove(temporary);
                    changed = true;
                }
                if (fault == "retained-against-policy" && phase == MembershipExpiryPhase.Expired &&
                    attempt.ExpiredMetadata == OrganizationGroupExpiredMetadata.RemovedAssignment)
                    changed = true;
                if (fault == "baseline-loss")
                    foreach (var role in roles.Where(r => r!["isTemporary"]?.GetValue<bool>() != true).ToArray())
                    {
                        roles.Remove(role);
                        changed = true;
                    }
                if (fault == "baseline-id-drift")
                    foreach (var role in roles.Where(r => r!["isTemporary"]?.GetValue<bool>() != true))
                    {
                        role!["id"] = Guid.NewGuid().ToString();
                        changed = true;
                    }
                if (fault == "extra-role")
                {
                    roles.Add(new JsonObject { ["id"] = Guid.NewGuid().ToString(), ["role"] = "viewer", ["isTemporary"] = false });
                    changed = true;
                }
                if (temporary is not null)
                {
                    string? field = fault switch
                    {
                        "metadata-role-id" => "customRoleId",
                        "metadata-role-slug" => "customRoleSlug",
                        "metadata-assignment-id" => "id",
                        "metadata-mode" => "temporaryMode",
                        "metadata-range" => "temporaryRange",
                        "metadata-start" => "temporaryAccessStartTime",
                        "metadata-end" => "temporaryAccessEndTime",
                        _ => null
                    };
                    if (field is not null)
                    {
                        temporary[field] = field.EndsWith("Time", StringComparison.Ordinal) ?
                            clock.GetUtcNow().AddDays(1).ToString("O") : "wrong";
                        changed = true;
                    }
                    if (fault is "early-activation" or "delayed-activation" or "ignored-expiry")
                        changed = true;
                }
                return changed;
            }
        }
        internal int CanaryCount { get { lock (projects) return canaryKeys.Count; } }
        internal bool FaultApplied { get; private set; }
        private readonly HashSet<(string Project, string Environment, string Key)> canaryKeys = [];
        internal int ProjectCount { get { lock (projects) return projects.Count; } }
        internal int TemplateCount { get { lock (projects) return templates.Count; } }
        internal List<(string Project, string Credential, DateTimeOffset Time, int Status)> Accesses { get; } = [];
        internal JsonObject? MembershipSnapshot(string project, string principal)
        {
            lock (projects) return members.GetValueOrDefault((project, principal))?.DeepClone().AsObject();
        }
        internal void CorruptTemporalState(MembershipExpiryAttempt attempt, MembershipExpiryPhase phase,
            string fault, DateTimeOffset time)
        {
            lock (projects)
            {
                if (fault == "expired-credential" && phase == MembershipExpiryPhase.Expired)
                    credentialExpiresAt = time;
                if (!members.TryGetValue((attempt.ProjectId, attempt.PrincipalId), out var member)) return;
                JsonArray roles = member["roles"]!.AsArray();
                if (fault == "missing-permanent-baseline")
                    foreach (JsonNode? role in roles.Where(r => r!["isTemporary"]?.GetValue<bool>() != true).ToArray())
                        roles.Remove(role);
                if (fault == "unexpected-expired-grant" && phase == MembershipExpiryPhase.Expired)
                    roles.Add(new JsonObject { ["id"] = Guid.NewGuid().ToString(), ["role"] = "viewer", ["isTemporary"] = false });
                if (fault == "removed-expired-assignment" && phase == MembershipExpiryPhase.Expired)
                    foreach (JsonNode? role in roles.Where(r => r!["isTemporary"]?.GetValue<bool>() == true).ToArray())
                        roles.Remove(role);
            }
        }
        internal const string ForeignProjectId = "00000000-0000-0000-0000-000000000099";
        internal bool ForeignProjectProtected
        {
            get
            {
                lock (projects) return projects.TryGetValue(ForeignProjectId, out var project) &&
                    project["hasDeleteProtection"]!.GetValue<bool>();
            }
        }
        internal bool UnrelatedStatePreserved
        {
            get
            {
                lock (projects) return projects.TryGetValue(ForeignProjectId, out var project) &&
                    Text(project, "slug") == "unrelated" && project["hasDeleteProtection"]!.GetValue<bool>() &&
                    members.TryGetValue((ForeignProjectId, SecondUser), out var member) &&
                    Text(member, "id") == ForeignProjectId &&
                    member["roles"]!.AsArray().Count == 1 &&
                    member["roles"]![0]!["role"]!.GetValue<string>() == "viewer";
            }
        }

        internal Backend(string mode, TimeProvider? clock = null)
        {
            this.mode = mode;
            this.clock = clock ?? TimeProvider.System;
            if (mode.StartsWith("mixed-", StringComparison.Ordinal) || mode.StartsWith("temporal-", StringComparison.Ordinal))
            {
                projects.Add(ForeignProjectId, new JsonObject
                {
                    ["id"] = ForeignProjectId,
                    ["_id"] = ForeignProjectId,
                    ["orgId"] = Org,
                    ["slug"] = "unrelated",
                    ["name"] = "Unrelated",
                    ["hasDeleteProtection"] = true
                });
                members.Add((ForeignProjectId, SecondUser), new JsonObject
                {
                    ["id"] = ForeignProjectId,
                    ["roles"] = new JsonArray(new JsonObject { ["role"] = "viewer", ["isTemporary"] = false })
                });
            }
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }
        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                    connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }
        private async Task ServeAsync(TcpClient socket)
        {
            using (socket)
            {
                try
                {
                    NetworkStream stream = socket.GetStream();
                    var header = new List<byte>();
                    byte[] one = new byte[1];
                    while (header.Count < 32768)
                    {
                        if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                        header.Add(one[0]);
                        if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10 && header[^2] == 13 && header[^1] == 10) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    string role = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)).Split(' ').Last();
                    int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                    if (length is < 0 or > 65536) throw new InvalidOperationException("fixture-input");
                    byte[] bytes = new byte[length];
                    await stream.ReadExactlyAsync(bytes, shutdown.Token);
                    var body = length == 0 ? new JsonObject() : JsonNode.Parse(bytes)!.AsObject();
                    (int Status, JsonNode Payload) response;
                    lock (projects)
                    {
                        var uri = new Uri(Origin, request[1]);
                        response = Handle(request[0], uri, role, body);
                        ExpiryObserver?.Capture(request[0], uri, role, body, response.Status);
                        OrganizationExpiryObserver?.Capture(request[0], uri, role, body, response.Status);
                    }
                    byte[] payload = Encoding.UTF8.GetBytes(response.Payload.ToJsonString());
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                    await stream.WriteAsync(payload, shutdown.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }
        private (int, JsonNode) Handle(string method, Uri uri, string role, JsonObject body)
        {
            if (method is "POST" or "PATCH" && ExpiryObserver?.IsClosedMutation(uri, body) == true)
                return (409, new JsonObject());
            if (method is "POST" or "PATCH" && OrganizationExpiryObserver?.IsClosedMutation(uri, body) == true)
                return (409, new JsonObject());
            if (role == "denied" && !(mode == "ownership-temporal-denied-commit" &&
                method is "POST" or "PATCH" && body["roles"] is JsonArray deniedRoles &&
                deniedRoles.Any(r => r!["isTemporary"]?.GetValue<bool>() == true)))
            {
                if (uri.AbsolutePath.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
                {
                    DeniedCanaryReads++;
                    string? deniedProject = uri.Query.TrimStart('?').Split('&').Select(q => q.Split('=', 2))
                        .Where(q => q.Length == 2 && q[0] == "projectId").Select(q => q[1]).SingleOrDefault();
                    if (deniedProject is not null) Accesses.Add((deniedProject, role, clock.GetUtcNow(), 403));
                }
                if (uri.AbsolutePath.StartsWith("/api/v1/groups/", StringComparison.Ordinal) && method == "GET")
                    GroupAccesses.Add((uri.Segments.Last(), role, clock.GetUtcNow(), 403));
                return (403, new JsonObject());
            }
            if (role == "runtime" && credentialExpiresAt is { } expires && clock.GetUtcNow() >= expires)
                return (401, new JsonObject());
            string[] path = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            bool organizationEndpoint = path.Length >= 3 && (path[2] == "groups" ||
                path[2] == "organization" || path[2] == "organizations");
            if (organizationEndpoint && (mode.StartsWith("ownership-", StringComparison.Ordinal) ||
                role.StartsWith("owner-", StringComparison.Ordinal) || ownerAssignments.Count > 0))
            {
                OrganizationDispatches.Add((method, uri.AbsolutePath, role));
                var response = OwnedOrganizationResponse(method, path, role, body, uri);
                if (path[2] == "groups" && path.Length == 4 && method == "GET")
                    GroupAccesses.Add((path[3], role, clock.GetUtcNow(), response.Item1));
                return response;
            }
            if (role.StartsWith("owner-", StringComparison.Ordinal)) return (403, new JsonObject());
            // A second credential can only read its own user's actual canary access.
            // It cannot borrow administrative, observer, runtime-identity or group authority.
            if (role == "second-runtime" && (method != "GET" ||
                !uri.AbsolutePath.StartsWith("/api/v4/secrets/", StringComparison.Ordinal) || path.Length != 4))
                return (403, new JsonObject());
            if (uri.AbsolutePath == "/api/v4/secrets/batch")
            {
                string project = Text(body, "projectId"), environment = Text(body, "environment");
                var results = new JsonArray();
                foreach (JsonNode? input in body["secrets"]!.AsArray())
                {
                    string key = input!["secretKey"]!.GetValue<string>();
                    if (role == "runtime" && !CanSecret(project, environment, key,
                        method == "DELETE" ? "delete" : method == "POST" ? "create" : "edit"))
                        return (403, new JsonObject());
                    if (method == "DELETE") { secrets.Remove((project, environment, key)); attributes.Remove((project, environment, key)); }
                    else
                    {
                        secrets[(project, environment, key)] = input["secretValue"]!.GetValue<string>();
                        attributes[(project, environment, key)] = (JsonObject)input.DeepClone();
                    }
                    results.Add(new JsonObject
                    {
                        ["secretKey"] = key,
                        ["workspace"] = project,
                        ["environment"] = environment,
                        ["type"] = "shared",
                        ["version"] = 1
                    });
                }
                return (200, new JsonObject { ["secrets"] = results });
            }
            if (uri.AbsolutePath.StartsWith("/api/v4/secrets", StringComparison.Ordinal))
            {
                Dictionary<string, string> query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                    .Select(q => q.Split('=', 2)).ToDictionary(q => q[0], q => Uri.UnescapeDataString(q[1]));
                string project = method == "GET" ? query["projectId"] : Text(body, "projectId");
                string env = method == "GET" ? query["environment"] : Text(body, "environment");
                string key = Uri.UnescapeDataString(path[^1]);
                if (role is "runtime" or "second-runtime")
                {
                    RuntimeReads++;
                    bool inspect = path.Length == 3;
                    string action = method == "POST" ? "create" : method == "PATCH" ? "edit" :
                        inspect ? "describeSecret" : "readValue";
                    bool second = role == "second-runtime";
                    bool aliased = second && mode == "mixed-aliased-secondary-credential";
                    bool allowed = mode != "access-denied" &&
                        CanSecret(project, env, key, action, second ? aliased ? User : SecondUser : null);
                    Accesses.Add((project, role, clock.GetUtcNow(), allowed ? 200 : 403));
                    if (second && mode == "mixed-missing-second-access" &&
                        members.ContainsKey((project, User)) && members.ContainsKey((project, SecondUser)))
                    {
                        allowed = false;
                        FaultApplied = true;
                    }
                    if (second)
                    {
                        if (allowed) SecondAllowedReads++; else SecondDeniedReads++;
                    }
                    else
                    {
                        if (allowed) FirstAllowedReads++; else FirstDeniedReads++;
                    }
                    if (!allowed) return (403, new JsonObject());
                }
                if (path.Length == 3 && method == "GET")
                    return (200, new JsonObject
                    {
                        ["secrets"] = new JsonArray(secrets.Keys
                        .Where(s => s.Project == project && s.Environment == env)
                        .Select(s => new JsonObject { ["secretKey"] = s.Key, ["version"] = 1 }).ToArray())
                    });
                if (method == "POST")
                {
                    secrets.Add((project, env, key), Text(body, "secretValue"));
                    canaryKeys.Add((project, env, key));
                }
                if (method == "PATCH" && secrets.ContainsKey((project, env, key))) secrets[(project, env, key)] = Text(body, "secretValue");
                if (!secrets.TryGetValue((project, env, key), out string? value)) return (404, new JsonObject());
                return (200, new JsonObject
                {
                    ["secret"] = new JsonObject
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["secretKey"] = key,
                        ["secretValue"] = value,
                        ["workspace"] = project,
                        ["environment"] = env,
                        ["version"] = 1,
                        ["secretValueHidden"] = false
                    }
                });
            }
            if (path.Length >= 3 && path[2] == "project-templates")
                return TemplateResponse(method, path, body);
            if (path.Length >= 3 && path[2] == "groups")
                return GroupResponse(method, path, role, body);
            if (path.Length >= 4 && path[2] == "organization" && path[3] == "roles")
                return OrganizationRoleResponse(method, path, body);
            if (path.Length >= 5 && path[2] == "organizations" && path[3] == "memberships")
                return OrganizationGroupResponse(method, path, body, uri);
            if (path.Length < 3 || path[2] != "projects") return (404, new JsonObject());
            if (path.Length == 3)
            {
                if (method == "POST")
                {
                    JsonObject? template = null;
                    if (body["template"] is not null && !templates.TryGetValue(Text(body, "template"), out template))
                        return (404, new JsonObject());
                    string id = Guid.NewGuid().ToString();
                    var project = new JsonObject
                    {
                        ["id"] = id,
                        ["_id"] = id,
                        ["orgId"] = Org,
                        ["name"] = Text(body, "projectName"),
                        ["slug"] = Text(body, "slug"),
                        ["type"] = "secret-manager",
                        ["description"] = body["projectDescription"]?.DeepClone(),
                        ["hasDeleteProtection"] = body["hasDeleteProtection"]!.DeepClone(),
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date,
                        ["environments"] = new JsonArray(),
                        ["deletedEnvironments"] = new JsonArray(),
                        ["auditLogsRetentionDays"] = 30,
                        ["secretSharing"] = false,
                        ["autoCapitalization"] = false,
                        ["enforceEncryptedSecretManagerSecretMetadata"] = false,
                        ["pitVersionLimit"] = 10,
                        ["showSnapshotsLegacy"] = false,
                        ["secretDetectionIgnoreValues"] = new JsonArray()
                    };
                    projects.Add(id, project);
                    if (mode == "cleanup-substitution" && projects.Count == 1)
                    {
                        var foreign = project.DeepClone().AsObject();
                        foreign["id"] = ForeignProjectId; foreign["_id"] = ForeignProjectId;
                        foreign["slug"] = "unrelated"; foreign["hasDeleteProtection"] = true;
                        projects.Add(ForeignProjectId, foreign);
                    }
                    if (template is not null)
                    {
                        foreach (JsonNode? e in template["environments"]?.AsArray() ?? [])
                        {
                            string envId = Guid.NewGuid().ToString();
                            environments.Add(envId, new JsonObject
                            {
                                ["id"] = envId,
                                ["projectId"] = id,
                                ["name"] = e!["name"]!.DeepClone(),
                                ["slug"] = e["slug"]!.DeepClone(),
                                ["position"] = e["position"]!.DeepClone(),
                                ["createdAt"] = Date,
                                ["updatedAt"] = Date,
                                ["softDeletedAt"] = null,
                                ["deleteAfter"] = null
                            });
                            project["environments"]!.AsArray().Add(new JsonObject
                            {
                                ["id"] = envId,
                                ["name"] = e["name"]!.DeepClone(),
                                ["slug"] = e["slug"]!.DeepClone()
                            });
                        }
                        foreach (JsonNode? r in template["roles"]!.AsArray())
                            permissions.Add((id, r!["slug"]!.GetValue<string>()), (JsonArray)r["permissions"]!.DeepClone());
                        foreach (JsonNode? identity in template["identities"]?.AsArray() ?? [])
                            members.Add((id, identity!["identityId"]!.GetValue<string>()),
                                new JsonObject
                                {
                                    ["id"] = Guid.NewGuid().ToString(),
                                    ["roles"] = new JsonArray(identity["roles"]!.AsArray()
                                    .Select(r => new JsonObject
                                    {
                                        ["id"] = Guid.NewGuid().ToString(),
                                        ["role"] = r!.DeepClone(),
                                        ["isTemporary"] = false
                                    }).ToArray())
                                });
                    }
                    return (200, Wrap("project", project));
                }
                return (200, new JsonObject
                {
                    ["projects"] = mode == "empty-project-list" ? new JsonArray() :
                    new JsonArray(projects.Values.Select(p => p.DeepClone()).ToArray())
                });
            }
            if (path[3] == "slug")
            {
                JsonObject? project = projects.Values.SingleOrDefault(p => Text(p, "slug") == path[4]);
                if (project is not null && mode == "cleanup-substitution" && role == "observer")
                {
                    var substituted = projects[ForeignProjectId].DeepClone().AsObject();
                    substituted["slug"] = project["slug"]!.DeepClone();
                    return (200, substituted);
                }
                return project is null ? (404, new JsonObject()) : (200, project.DeepClone());
            }
            string projectId = path[3];
            if (!projects.TryGetValue(projectId, out JsonObject? owner)) return (404, new JsonObject());
            if (path.Length == 4)
            {
                if (method == "PATCH")
                    foreach ((string key, JsonNode? value) in body) owner[key] = value?.DeepClone();
                JsonObject result = (JsonObject)owner.DeepClone();
                if (method is "PATCH" or "DELETE")
                    foreach (string field in new[] { "_id", "environments", "deletedEnvironments" }) result.Remove(field);
                if (method == "DELETE")
                {
                    if (mode == "cleanup") return (403, new JsonObject());
                    projects.Remove(projectId);
                    if (projectId != ForeignProjectId) OwnedProjectDeletes++;
                    if (mode.StartsWith("mixed-", StringComparison.Ordinal) || mode.StartsWith("temporal-", StringComparison.Ordinal))
                    {
                        foreach (var coordinate in members.Keys.Where(k => k.Project == projectId).ToArray())
                            members.Remove(coordinate);
                        foreach (var coordinate in secrets.Keys.Where(k => k.Project == projectId).ToArray())
                        {
                            secrets.Remove(coordinate);
                            attributes.Remove(coordinate);
                        }
                    }
                }
                return (200, Wrap("project", result));
            }
            if (path[4] == "memberships") return Membership(method, path, projectId, body, role);
            if (path[4] == "tags")
            {
                string? id = path.Length == 5 ? null : path[5] == "slug" ?
                    tags.Keys.SingleOrDefault(k => Text(tags[k], "projectId") == projectId && Text(tags[k], "slug") == path[6]) : path[5];
                if (method == "POST")
                {
                    id = Guid.NewGuid().ToString();
                    var tag = new JsonObject
                    {
                        ["id"] = id,
                        ["projectId"] = projectId,
                        ["slug"] = body["slug"]!.DeepClone(),
                        ["color"] = body["color"]!.DeepClone(),
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    };
                    if (role == "administrative") AdministrativeTagCreates++;
                    if (mode != "drift" || role != "administrative") tags.Add(id, tag);
                    if (mode == "wrong-coordinate" && role == "administrative") tag["projectId"] = Runtime;
                    return (200, Wrap("tag", tag));
                }
                if (path.Length == 5)
                    return (200, new JsonObject
                    {
                        ["tags"] = new JsonArray(tags.Values.Where(t => Text(t, "projectId") == projectId)
                        .Select(t => t.DeepClone()).ToArray())
                    });
                if (id is null || !tags.TryGetValue(id, out JsonObject? found)) return (404, new JsonObject());
                if (method == "PATCH")
                    foreach ((string key, JsonNode? value) in body) found[key] = value?.DeepClone();
                JsonObject result = (JsonObject)found.DeepClone();
                if (method == "GET") result["name"] = result["slug"]!.DeepClone();
                if (method == "DELETE") tags.Remove(id);
                return (200, Wrap("tag", result));
            }
            if (path[4] == "environments") return EnvironmentResponse(method, uri, path, projectId, owner, body);
            return (404, new JsonObject());
        }
        private bool CanSecret(string project, string env, string key, string action, string? selectedUser = null)
        {
            IEnumerable<string> principals = selectedUser is not null ? [selectedUser] :
                new[] { Runtime, User }.Concat(groupPrincipals.Where(g => g.Value == Runtime).Select(g => g.Key));
            foreach (string principal in principals)
            {
                if (!members.TryGetValue((project, principal), out JsonObject? member)) continue;
                foreach (JsonNode? assigned in member["roles"]!.AsArray())
                {
                    if (assigned!["isTemporary"]?.GetValue<bool>() == true)
                    {
                        DateTimeOffset start = DateTimeOffset.Parse(assigned["temporaryAccessStartTime"]!.GetValue<string>());
                        if (assigned["temporaryMode"]?.GetValue<string>() != "relative" ||
                            assigned["temporaryRange"]?.GetValue<string>() != "1m" ||
                            clock.GetUtcNow() < start || clock.GetUtcNow() >= start.AddMinutes(1))
                            continue;
                    }
                    string role = assigned!["role"]!.GetValue<string>();
                    if (role == "viewer") return action is "readValue" or "describeSecret";
                    if (!permissions.TryGetValue((project, role), out JsonArray? rules)) continue;
                    foreach (JsonNode? rule in rules)
                    {
                        if (rule!["subject"]?.GetValue<string>() != "secrets") continue;
                        string[] actions = rule["action"] is JsonArray array ? array.Select(a => a!.GetValue<string>()).ToArray() :
                            [rule["action"]!.GetValue<string>()];
                        if (!actions.Contains(action) && !(action is "readValue" or "describeSecret" && actions.Contains("read"))) continue;
                        JsonNode? condition = rule["conditions"]?["environment"];
                        bool matches = condition switch
                        {
                            null => true,
                            JsonValue literal => literal.GetValue<string>() == env,
                            JsonObject comparison when comparison["$eq"] is not null => Text(comparison, "$eq") == env,
                            JsonObject comparison when comparison["$ne"] is not null => Text(comparison, "$ne") != env,
                            JsonObject comparison when comparison["$in"] is JsonArray included =>
                                included.Any(v => v!.GetValue<string>() == env),
                            JsonObject comparison when comparison["$glob"] is not null => env.StartsWith(Text(comparison, "$glob").TrimEnd('*'), StringComparison.Ordinal),
                            _ => false
                        };
                        if (!matches) continue;
                        JsonObject? secret = attributes.GetValueOrDefault((project, env, key));
                        if (rule["conditions"]?["secretTags"] is JsonObject tagRule)
                        {
                            string[] slugs = (secret?["tagIds"]?.AsArray() ?? []).Select(id =>
                                Text(tags[id!.GetValue<string>()], "slug")).ToArray();
                            if (tagRule["$in"] is JsonArray included && !included.Any(t => slugs.Contains(t!.GetValue<string>()))) continue;
                            if (tagRule["$all"] is JsonArray all && !all.All(t => slugs.Contains(t!.GetValue<string>()))) continue;
                        }
                        return true;
                    }
                }
            }
            return false;
        }
        private (int, JsonNode) TemplateResponse(string method, string[] path, JsonObject body)
        {
            string? id = path.Length == 3 ? null : path[3];
            if (method == "POST")
            {
                id = Guid.NewGuid().ToString();
                var template = new JsonObject
                {
                    ["id"] = id,
                    ["orgId"] = Org,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["roles"] = new JsonArray(),
                    ["environments"] = new JsonArray(),
                    ["users"] = new JsonArray(),
                    ["groups"] = new JsonArray(),
                    ["identities"] = new JsonArray(),
                    ["projectManagedIdentities"] = new JsonArray()
                };
                foreach ((string field, JsonNode? value) in body) template[field] = value?.DeepClone();
                templates.Add(id, template);
            }
            if (path.Length == 3 && method == "GET")
                return (200, new JsonObject { ["projectTemplates"] = new JsonArray(templates.Values.Select(t => t.DeepClone()).ToArray()) });
            if (id is null || !templates.TryGetValue(id, out JsonObject? found)) return (404, new JsonObject());
            if (method == "PATCH")
                foreach ((string field, JsonNode? value) in body)
                    if (mode != "ignore-template-configuration" || field is "name" or "description")
                        found[field] = value?.DeepClone();
            foreach (JsonNode? identity in found["identities"]?.AsArray() ?? [])
                identity!["identityName"] = "fixture";
            if (method == "DELETE") templates.Remove(id);
            return (200, Wrap("projectTemplate", found));
        }
        private (int, JsonNode) Membership(string method, string[] path, string project, JsonObject body, string credential)
        {
            bool identity = path.Length > 5 && path[5] == "identities";
            bool group = path.Length > 5 && path[5] == "groups";
            if (mode.StartsWith("mixed-", StringComparison.Ordinal) && !identity && !group)
            {
                if (path.Length > 5 && path[5] == "details")
                {
                    string username = Text(body, "username");
                    string? user = username switch
                    {
                        "fixture-user" => User,
                        "fixture-second-user" => SecondUser,
                        _ => null
                    };
                    if (user == User) FirstMembershipReads++;
                    if (user == SecondUser) SecondMembershipReads++;
                    if (user is null || !members.TryGetValue((project, user), out var selected))
                        return (404, new JsonObject());
                    JsonObject result = UserMembership(project, selected, false, user);
                    if (user == SecondUser && mode == "mixed-wrong-second-username" &&
                        (AdministrativeMemberMutations > 0 || members.ContainsKey((project, User))))
                    {
                        result["user"]!["username"] = "wrong-second-user";
                        FaultApplied = true;
                    }
                    return (200, Wrap("membership", result));
                }
                if (path.Length == 5 && method is "POST" or "DELETE")
                {
                    string[] usernames = (body["usernames"]?.AsArray() ?? [])
                        .Select(v => v!.GetValue<string>()).ToArray();
                    string[] emails = (body["emails"]?.AsArray() ?? [])
                        .Select(v => v!.GetValue<string>()).ToArray();
                    string[] selected = new[] { User, SecondUser }.Where(user =>
                        usernames.Contains(user == User ? "fixture-user" : "fixture-second-user") ||
                        emails.Contains(user == User ? "fixture@example.invalid" : "fixture-second@example.invalid")).ToArray();
                    if (selected.Length != usernames.Length + emails.Length) return (400, new JsonObject());
                    bool administrative = credential == "administrative";
                    if (administrative) AdministrativeMemberMutations++;
                    var results = new JsonArray();
                    foreach (string user in selected)
                    {
                        JsonObject? previous = members.GetValueOrDefault((project, user));
                        JsonObject changedMember = previous ?? NewMembership(new JsonArray(
                            new JsonObject { ["role"] = body["roleSlugs"]?[0]?.DeepClone() ?? JsonValue.Create("viewer") }));
                        bool ignore = administrative && user == SecondUser && mode == "mixed-missing-second-membership";
                        if (ignore) FaultApplied = true;
                        else if (method == "POST") members[(project, user)] = changedMember;
                        else members.Remove((project, user));
                        var row = new JsonObject
                        {
                            ["id"] = changedMember["id"]!.DeepClone(),
                            ["userId"] = user,
                            ["projectId"] = project,
                            ["createdAt"] = Date,
                            ["updatedAt"] = Date
                        };
                        if (administrative && user == SecondUser && mode == "mixed-wrong-second-user-id")
                        {
                            row["userId"] = Runtime;
                            FaultApplied = true;
                        }
                        results.Add(row);
                    }
                    if (administrative && mode is "mixed-duplicate-results" or "mixed-extra-results")
                    {
                        JsonObject extra = results[^1]!.DeepClone().AsObject();
                        if (mode == "mixed-extra-results")
                        {
                            extra["id"] = Guid.NewGuid().ToString();
                            extra["userId"] = Observer;
                        }
                        results.Add(extra);
                        FaultApplied = true;
                    }
                    return (200, new JsonObject { ["memberships"] = results });
                }
            }
            if (group && path.Length == 6 && method == "GET")
                return (200, new JsonObject
                {
                    ["groupMemberships"] = new JsonArray(members
                    .Where(m => m.Key.Project == project && groups.ContainsKey(m.Key.Principal))
                    .Select(m => GroupMembership(m.Key.Principal, m.Value, project)).ToArray())
                });
            string principal = identity || group ? path[^1] : User;
            if (!identity && path.Length == 5 && method == "GET")
                return (200, new JsonObject
                {
                    ["memberships"] = new JsonArray(members.Where(m => m.Key.Project == project && m.Key.Principal == User)
                    .SelectMany(m => mode == "duplicate-memberships" ?
                        new[] { UserMembership(project, m.Value, true), UserMembership(project, m.Value, true) } :
                        new[] { UserMembership(project, m.Value, true) }).ToArray())
                });
            if (!identity && path.Length > 5 && path[5] == "details")
                return members.TryGetValue((project, User), out JsonObject? selected) ?
                    (200, Wrap("membership", UserMembership(project, selected, false))) : (404, new JsonObject());
            if (method == "POST")
            {
                JsonArray roles = body["roles"] is JsonArray explicitRoles ? (JsonArray)explicitRoles.DeepClone() :
                    new JsonArray(new JsonObject { ["role"] = body["role"]?.DeepClone() ?? body["roleSlugs"]?[0]?.DeepClone() ?? JsonValue.Create("viewer") });
                foreach (JsonNode? r in roles)
                {
                    r!["id"] = Guid.NewGuid().ToString();
                    r["isTemporary"] ??= false;
                    if (r["isTemporary"]!.GetValue<bool>())
                        r["temporaryAccessEndTime"] = DateTimeOffset.Parse(r["temporaryAccessStartTime"]!.GetValue<string>())
                            .AddMinutes(1).ToString("O");
                }
                members.Add((project, principal), new JsonObject { ["id"] = Guid.NewGuid().ToString(), ["roles"] = roles });
            }
            if (!members.TryGetValue((project, principal), out JsonObject? member)) return (404, new JsonObject());
            if (method == "PATCH")
            {
                member["roles"] = body["roles"]!.DeepClone();
                foreach (JsonNode? r in member["roles"]!.AsArray())
                {
                    r!["id"] = Guid.NewGuid().ToString();
                    r["isTemporary"] ??= false;
                    if (r["isTemporary"]!.GetValue<bool>())
                        r["temporaryAccessEndTime"] = DateTimeOffset.Parse(r["temporaryAccessStartTime"]!.GetValue<string>())
                            .AddMinutes(1).ToString("O");
                }
            }
            string id = Text(member, "id");
            if (method == "DELETE") members.Remove((project, principal));
            if (group && method != "PATCH")
            {
                if (method == "DELETE")
                    return (200, new JsonObject
                    {
                        ["groupMembership"] = new JsonObject
                        {
                            ["id"] = id,
                            ["groupId"] = principal,
                            ["projectId"] = project,
                            ["createdAt"] = Date,
                            ["updatedAt"] = Date
                        }
                    });
                return (200, Wrap("groupMembership", GroupMembership(principal, member, project)));
            }
            if (identity && method == "GET")
                return (200, new JsonObject
                {
                    ["identityMembership"] = new JsonObject
                    {
                        ["id"] = id,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date,
                        ["roles"] = member["roles"]!.DeepClone(),
                        ["identity"] = new JsonObject
                        {
                            ["id"] = principal,
                            ["name"] = "fixture",
                            ["orgId"] = Org,
                            ["projectId"] = null,
                            ["authMethods"] = new JsonArray(),
                            ["metadata"] = new JsonArray()
                        }
                    }
                });
            if (identity)
                return (200, new JsonObject
                {
                    ["identityMembership"] = new JsonObject
                    {
                        ["id"] = id,
                        ["identityId"] = principal,
                        ["projectId"] = project,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    }
                });
            if (method == "PATCH")
            {
                JsonArray roles = (JsonArray)member["roles"]!.DeepClone();
                foreach (JsonNode? role in roles)
                {
                    role!["projectMembershipId"] = id;
                    role["createdAt"] = Date;
                    role["updatedAt"] = Date;
                }
                return (200, new JsonObject { ["roles"] = roles });
            }
            return (200, new JsonObject
            {
                ["memberships"] = new JsonArray(new JsonObject
                {
                    ["id"] = id,
                    ["userId"] = User,
                    ["projectId"] = project,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date
                })
            });
        }
        private (int, JsonNode) GroupResponse(string method, string[] path, string credential, JsonObject body)
        {
            if (credential == "runtime" && !groupPrincipals.Any(g => g.Value == Runtime &&
                organizationGroups.TryGetValue(g.Key, out JsonObject? membership) &&
                membership["roles"]!.AsArray().Any(r => organizationRoles.Values.Any(role =>
                    Text(role, "slug") == r!["role"]!.GetValue<string>()))))
                return (403, new JsonObject());
            if (path.Length == 3)
            {
                if (method == "GET") return (200, new JsonArray(groups.Values.Select(g => g.DeepClone()).ToArray()));
                string id = Guid.NewGuid().ToString();
                var group = new JsonObject
                {
                    ["id"] = id,
                    ["orgId"] = Org,
                    ["name"] = body["name"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date
                };
                groups.Add(id, group);
                organizationGroups.Add(id, NewMembership(new JsonArray(new JsonObject { ["role"] = "no-access" })));
                return (200, group.DeepClone());
            }
            string groupId = path[3];
            if (!groups.TryGetValue(groupId, out JsonObject? found)) return (404, new JsonObject());
            if (method == "GET" && path.Length == 5 && path[4] == "members")
            {
                var linked = groupPrincipals.TryGetValue(groupId, out string? identity) ?
                    new JsonArray(new JsonObject
                    {
                        ["id"] = groupId,
                        ["type"] = "machineIdentity",
                        ["joinedGroupAt"] = null,
                        ["machineIdentity"] = new JsonObject { ["id"] = identity, ["name"] = "fixture" }
                    }) : new JsonArray();
                return (200, new JsonObject { ["members"] = linked, ["totalCount"] = linked.Count });
            }
            if (path.Length > 4 && path[4] == "machine-identities")
            {
                groupPrincipals[groupId] = path[5];
                return (200, new JsonObject { ["id"] = Guid.NewGuid().ToString() });
            }
            JsonObject result = (JsonObject)found.DeepClone();
            if (method == "GET") result["customRoleSlug"] = null;
            if (method == "DELETE")
            {
                groups.Remove(groupId);
                organizationGroups.Remove(groupId);
                groupPrincipals.Remove(groupId);
            }
            return (200, result);
        }
        private (int, JsonNode) OrganizationRoleResponse(string method, string[] path, JsonObject body)
        {
            string? id = path.Length == 4 ? null : path[4] == "slug" ?
                organizationRoles.Keys.SingleOrDefault(k => Text(organizationRoles[k], "slug") == path[5]) : path[4];
            if (method == "POST")
            {
                id = Guid.NewGuid().ToString();
                JsonObject role = (JsonObject)body.DeepClone();
                role["id"] = id; role["orgId"] = Org; role["createdAt"] = Date; role["updatedAt"] = Date;
                organizationRoles.Add(id, role);
            }
            if (id is null || !organizationRoles.TryGetValue(id, out JsonObject? found)) return (404, new JsonObject());
            if (method == "DELETE") organizationRoles.Remove(id);
            return (200, Wrap("role", found));
        }
        private (int, JsonNode) OwnedOrganizationResponse(string method, string[] path,
            string credential, JsonObject body, Uri uri)
        {
            // OrganizationId is deliberately not consulted here: it is host grant
            // intent, not a wire field. Only the simulated authenticated bearer
            // selects owner or target context.
            bool owner = credential is "owner-setup" or "owner-observer";
            bool write = method != "GET";
            bool deniedCommit = credential == "denied" && mode == "ownership-temporal-denied-commit" &&
                body["roles"] is JsonArray deniedRoles && deniedRoles.Any(r => r!["isTemporary"]?.GetValue<bool>() == true);
            if (!deniedCommit && (write && credential is not ("owner-setup" or "setup" or "administrative") ||
                credential is not ("owner-setup" or "owner-observer" or "setup" or "administrative" or "observer" or "runtime")))
                return (403, new JsonObject());
            if (path[2] == "organization")
            {
                if (owner || credential == "runtime") return (403, new JsonObject());
                if (method == "DELETE" && mode == "ownership-role-cleanup")
                {
                    FaultApplied = true;
                    return (403, new JsonObject());
                }
                return OrganizationRoleResponse(method, path, body);
            }
            if (path[2] == "groups")
            {
                if (path.Length == 3)
                {
                    if (!owner) return (403, new JsonObject());
                    if (method == "GET")
                        return (200, new JsonArray(groups.Values.Where(g => Text(g, "orgId") == OwnerOrg)
                            .Select(g => g.DeepClone()).ToArray()));
                    if (method != "POST") return (403, new JsonObject());
                    string id = Guid.NewGuid().ToString();
                    var created = new JsonObject
                    {
                        ["id"] = id,
                        ["orgId"] = OwnerOrg,
                        ["name"] = body["name"]!.DeepClone(),
                        ["slug"] = body["slug"]!.DeepClone(),
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    };
                    groups.Add(id, created);
                    ownerAssignments.Add(id, NewMembership(new JsonArray(new JsonObject { ["role"] = "no-access" })));
                    OwnerGroupCreates++;
                    JsonObject returned = created.DeepClone().AsObject();
                    if (mode == "ownership-wrong-owner")
                    {
                        returned["orgId"] = Org;
                        FaultApplied = true;
                    }
                    return (200, returned);
                }
                string group = path[3];
                if (!groups.TryGetValue(group, out JsonObject? found)) return (404, new JsonObject());
                if (Text(found, "orgId") != OwnerOrg) return (403, new JsonObject());
                if (!owner)
                {
                    bool accessible = organizationGroups.ContainsKey(group) ||
                        mode.StartsWith("ownership-temporal-", StringComparison.Ordinal) && credential == "observer";
                    if (credential == "runtime")
                    {
                        accessible = organizationGroups.Any(link => groupPrincipals.GetValueOrDefault(link.Key) == Runtime &&
                            link.Value["roles"]!.AsArray().Any(r =>
                                OrganizationRoleActive(r!.AsObject()) &&
                                organizationRoles.Values.Any(custom => Text(custom, "slug") == r!["role"]!.GetValue<string>() &&
                                    custom["permissions"]!.AsArray().Any(p => p!["subject"]!.GetValue<string>() == "groups" &&
                                        (p["action"] is JsonArray actions ?
                                            actions.Any(a => a!.GetValue<string>() == "read") :
                                            p["action"]!.GetValue<string>() == "read")))));
                        if (accessible) RuntimeGroupAllowed++; else RuntimeGroupDenied++;
                    }
                    if (write || !accessible || path.Length != 4) return (403, new JsonObject());
                    JsonObject targetGroup = found.DeepClone().AsObject();
                    targetGroup["customRoleSlug"] = null;
                    return (200, targetGroup);
                }
                if (path.Length > 4 && path[4] == "machine-identities")
                {
                    if (path.Length != 6 || path[5] != Runtime || method is not ("POST" or "DELETE"))
                        return (403, new JsonObject());
                    string? linkId = ownerIdentityLinks.GetValueOrDefault(group);
                    if (method == "POST")
                    {
                        if (linkId is not null) return (409, new JsonObject());
                        linkId = Guid.NewGuid().ToString();
                        ownerIdentityLinks.Add(group, linkId);
                        groupPrincipals[group] = Runtime;
                    }
                    else
                    {
                        if (linkId is null) return (404, new JsonObject());
                        ownerIdentityLinks.Remove(group);
                        groupPrincipals.Remove(group);
                    }
                    return (200, new JsonObject { ["id"] = linkId });
                }
                if (path.Length == 5 && path[4] == "members" && method == "GET")
                {
                    var linked = ownerIdentityLinks.TryGetValue(group, out string? linkId) ?
                        new JsonArray(new JsonObject
                        {
                            ["id"] = linkId,
                            ["type"] = "machineIdentity",
                            ["joinedGroupAt"] = null,
                            ["machineIdentity"] = new JsonObject { ["id"] = Runtime, ["name"] = "fixture" }
                        }) : new JsonArray();
                    return (200, new JsonObject { ["members"] = linked, ["totalCount"] = linked.Count });
                }
                JsonObject result = found.DeepClone().AsObject();
                if (method == "GET") result["customRoleSlug"] = null;
                if (method == "GET" && mode == "ownership-owner-resource-substitution")
                {
                    result["id"] = Guid.NewGuid().ToString();
                    FaultApplied = true;
                }
                if (method == "DELETE")
                {
                    if (mode == "ownership-group-cleanup")
                    {
                        FaultApplied = true;
                        return (403, new JsonObject());
                    }
                    if (organizationGroups.ContainsKey(group)) return (409, new JsonObject());
                    groups.Remove(group);
                    ownerAssignments.Remove(group);
                    ownerIdentityLinks.Remove(group);
                    groupPrincipals.Remove(group);
                }
                return (200, result);
            }
            if (path[2] != "organizations" || path.Length < 5 || path[4] != "groups" ||
                credential == "runtime") return (403, new JsonObject());
            if (path.Length == 5)
            {
                if (method != "GET") return (403, new JsonObject());
                if (!owner) return OrganizationGroupResponse(method, path, body, uri);
                var rows = ownerAssignments;
                return (200, new JsonObject
                {
                    ["groupMemberships"] = new JsonArray(rows.Select(g => GroupMembership(g.Key, g.Value)).ToArray()),
                    ["totalCount"] = rows.Count
                });
            }
            string selectedGroup = path[5];
            if (!groups.ContainsKey(selectedGroup)) return (404, new JsonObject());
            if (owner)
            {
                if (method == "DELETE") OwnerUnlinkDispatches++;
                if (write) return (403, new JsonObject());
                return (200, Wrap("groupMembership", GroupMembership(selectedGroup, ownerAssignments[selectedGroup])));
            }
            if (method is "POST" or "PATCH" && body["roles"] is JsonArray temporalRoles &&
                temporalRoles.Any(r => r!["isTemporary"]?.GetValue<bool>() == true))
                OrganizationTemporalRequests.Add(body.DeepClone().AsObject());
            if (credential == "administrative" && method is "POST" or "PATCH")
            {
                TargetGroupMutations++;
                if (mode == "ownership-wrong-context")
                {
                    FaultApplied = true;
                    return (403, new JsonObject());
                }
            }
            if (method == "POST")
            {
                if (organizationGroups.ContainsKey(selectedGroup)) return (409, new JsonObject());
                organizationGroups.Add(selectedGroup, NewMembership(body["roles"]!.DeepClone().AsArray()));
            }
            if (!organizationGroups.TryGetValue(selectedGroup, out JsonObject? membership)) return (404, new JsonObject());
            if (method == "PATCH") membership["roles"] = NewMembership(body["roles"]!.DeepClone().AsArray())["roles"]!.DeepClone();
            if (credential == "administrative" && method is "POST" or "PATCH" && mode == "ownership-link-drift")
            {
                groupPrincipals.Remove(selectedGroup);
                ownerIdentityLinks.Remove(selectedGroup);
                FaultApplied = true;
            }
            JsonObject projected = GroupMembership(selectedGroup, membership);
            if (credential == "observer" && mode == "ownership-target-assignment-substitution")
            {
                projected["id"] = Guid.NewGuid().ToString();
                FaultApplied = true;
            }
            if (method == "DELETE")
            {
                TargetUnlinks++;
                if (mode == "ownership-unlink-cleanup")
                {
                    FaultApplied = true;
                    return (403, new JsonObject());
                }
                organizationGroups.Remove(selectedGroup);
                return (200, new JsonObject
                {
                    ["groupMembership"] = new JsonObject
                    {
                        ["id"] = membership["id"]!.DeepClone(),
                        ["groupId"] = selectedGroup,
                        ["orgId"] = Org,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    }
                });
            }
            return (200, Wrap("groupMembership", projected));
        }
        private (int, JsonNode) OrganizationGroupResponse(string method, string[] path, JsonObject body, Uri uri)
        {
            if (path.Length == 5)
            {
                var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                    .Select(q => q.Split('=', 2)).ToDictionary(q => q[0], q => Uri.UnescapeDataString(q[1]));
                IEnumerable<KeyValuePair<string, JsonObject>> rows = organizationGroups;
                if (query.TryGetValue("search", out string? search))
                    rows = rows.Where(g => Text(groups[g.Key], "name").Contains(search, StringComparison.Ordinal));
                if (mode != "ignore-group-order" && query.TryGetValue("orderBy", out string? column))
                {
                    string Key(KeyValuePair<string, JsonObject> g) => column == "role" ?
                        g.Value["roles"]![0]!["role"]!.GetValue<string>() : Text(groups[g.Key], column);
                    rows = query.TryGetValue("orderDirection", out string? order) && order == "desc" ?
                        rows.OrderByDescending(Key, StringComparer.Ordinal) : rows.OrderBy(Key, StringComparer.Ordinal);
                }
                var values = rows.Select(g => GroupMembership(g.Key, g.Value)).ToArray();
                return (200, new JsonObject
                {
                    ["groupMemberships"] = new JsonArray(values),
                    ["totalCount"] = values.Length
                });
            }
            string group = path[5];
            if (method == "POST") organizationGroups.Add(group, NewMembership((JsonArray)body["roles"]!.DeepClone()));
            if (!organizationGroups.TryGetValue(group, out JsonObject? found)) return (404, new JsonObject());
            if (method == "PATCH") found["roles"] = NewMembership((JsonArray)body["roles"]!.DeepClone())["roles"]!.DeepClone();
            if (method == "DELETE")
            {
                organizationGroups.Remove(group);
                return (200, new JsonObject
                {
                    ["groupMembership"] = new JsonObject
                    {
                        ["id"] = found["id"]!.DeepClone(),
                        ["groupId"] = group,
                        ["orgId"] = Org,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    }
                });
            }
            return (200, Wrap("groupMembership", GroupMembership(group, found)));
        }
        private static JsonObject NewMembership(JsonArray roles)
        {
            foreach (JsonNode? role in roles)
            {
                role!["id"] = Guid.NewGuid().ToString();
                role["isTemporary"] ??= false;
                if (role["isTemporary"]!.GetValue<bool>())
                    role["temporaryAccessEndTime"] = DateTimeOffset.Parse(role["temporaryAccessStartTime"]!.GetValue<string>())
                        .AddMinutes(1).ToString("O");
            }
            return new JsonObject { ["id"] = Guid.NewGuid().ToString(), ["roles"] = roles };
        }
        private bool OrganizationRoleActive(JsonObject role)
        {
            if (role["isTemporary"]?.GetValue<bool>() != true) return true;
            DateTimeOffset start = DateTimeOffset.Parse(Text(role, "temporaryAccessStartTime"));
            if (mode == "ownership-temporal-early-activation" && clock.GetUtcNow() < start) return true;
            if (mode == "ownership-temporal-delayed-activation" && clock.GetUtcNow() == start) return false;
            if (mode == "ownership-temporal-ignored-expiry" && clock.GetUtcNow() >= start.AddMinutes(1)) return true;
            return Text(role, "temporaryMode") == "relative" && Text(role, "temporaryRange") == "1m" &&
                clock.GetUtcNow() >= start && clock.GetUtcNow() < start.AddMinutes(1);
        }
        private JsonObject GroupMembership(string group, JsonObject member, string? project = null)
        {
            JsonObject source = groups[group];
            JsonArray returnedRoles = member["roles"]!.DeepClone().AsArray();
            if (ownerAssignments.ContainsKey(group))
                foreach (JsonNode? assignment in returnedRoles)
                {
                    JsonObject? custom = organizationRoles.Values.SingleOrDefault(r =>
                        Text(r, "slug") == assignment!["role"]!.GetValue<string>());
                    assignment!["customRoleId"] ??= custom?["id"]?.DeepClone();
                    assignment["customRoleSlug"] ??= custom?["slug"]?.DeepClone();
                    if (custom is not null) assignment["role"] = "custom";
                }
            var result = new JsonObject
            {
                ["id"] = member["id"]!.DeepClone(),
                ["groupId"] = group,
                ["createdAt"] = Date,
                ["updatedAt"] = Date,
                ["roles"] = returnedRoles,
                ["group"] = new JsonObject
                {
                    ["id"] = group,
                    ["orgId"] = source["orgId"]!.DeepClone(),
                    ["name"] = source["name"]!.DeepClone(),
                    ["slug"] = source["slug"]!.DeepClone()
                }
            };
            if (project is not null) result["projectId"] = project;
            return result;
        }
        private static JsonObject UserMembership(string project, JsonObject member, bool created, string user = User)
        {
            var result = new JsonObject
            {
                ["id"] = member["id"]!.DeepClone(),
                ["projectId"] = project,
                ["userId"] = user,
                ["user"] = new JsonObject
                {
                    ["id"] = user,
                    ["username"] = user == SecondUser ? "fixture-second-user" : "fixture-user"
                },
                ["roles"] = member["roles"]!.DeepClone()
            };
            if (created) result["createdAt"] = Date;
            return result;
        }
        private (int, JsonNode) EnvironmentResponse(string method, Uri uri, string[] path, string project,
            JsonObject owner, JsonObject body)
        {
            string? id = path.Length == 5 ? null : path[5] == "slug" ?
                environments.Keys.SingleOrDefault(k => Text(environments[k], "projectId") == project && Text(environments[k], "slug") == path[6]) : path[5];
            if (method == "POST" && path.Length == 5)
            {
                id = Guid.NewGuid().ToString();
                environments.Add(id, new JsonObject
                {
                    ["id"] = id,
                    ["projectId"] = project,
                    ["name"] = body["name"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["position"] = body["position"]?.DeepClone() ?? JsonValue.Create(1),
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["softDeletedAt"] = null,
                    ["deleteAfter"] = null
                });
            }
            if (id is null || !environments.TryGetValue(id, out JsonObject? env)) return (404, new JsonObject());
            if (method == "PATCH")
                foreach ((string key, JsonNode? value) in body) env[key] = value?.DeepClone();
            if (method == "DELETE")
            {
                if (uri.Query.Contains("hardDelete=true", StringComparison.Ordinal)) environments.Remove(id);
                else { env["softDeletedAt"] = Date; env["deleteAfter"] = Date; }
            }
            if (path[^1] == "restore") { env["softDeletedAt"] = null; env["deleteAfter"] = null; }
            owner["environments"] = new JsonArray(environments.Values.Where(e => Text(e, "projectId") == project && e["softDeletedAt"] is null)
                .Select(e => new JsonObject { ["id"] = e["id"]!.DeepClone(), ["name"] = e["name"]!.DeepClone(), ["slug"] = e["slug"]!.DeepClone() }).ToArray());
            owner["deletedEnvironments"] = new JsonArray(environments.Values.Where(e => Text(e, "projectId") == project && e["softDeletedAt"] is not null)
                .Select(e => new JsonObject
                {
                    ["id"] = e["id"]!.DeepClone(),
                    ["name"] = e["name"]!.DeepClone(),
                    ["slug"] = e["slug"]!.DeepClone(),
                    ["softDeletedAt"] = Date,
                    ["deleteAfter"] = Date,
                    ["deletedBy"] = null
                }).ToArray());
            return method == "GET" ? (200, Wrap("environment", env)) :
                (200, new JsonObject { ["environment"] = env.DeepClone(), ["projectId"] = project });
        }
        private static string Text(JsonObject value, string field) => value[field]!.GetValue<string>();
        private static JsonObject Wrap(string field, JsonNode value) => new() { [field] = value.DeepClone() };
        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }
    }
}
