using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class RoleChangeTests
{
    private const string Org = "c168ae21-77c8-467a-9a31-d471c8dc3d71";
    private const string Project = "project-private";
    private const string Role = "9fe7d5c2-a8d3-4b2d-a9f7-f3a6e8c87d14";
    private const string ForeignUuid = "502d6349-cc18-4283-b85b-bad8d03c6109";
    private const string Slug = "reader-private";

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task FixedRoutesApplyTypedNativeRoleState(int route)
    {
        using var request = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, route), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Id).IsEqualTo(Role);
        await Assert.That(result.Value.Slug).IsEqualTo(Slug);
        await Assert.That(result.Value.IncludesPermissions).IsTrue();
        await Assert.That(result.Value.Permissions![0].Action.IsScalar).IsFalse();
        await Assert.That(result.Value.Permissions[0].Action.Values.Count).IsEqualTo(2);
        await Assert.That(result.Value.Permissions[0].Subject!.Values[0])
            .IsEqualTo(route < 2 ? "app-connections" : "secrets");
        await Assert.That(result.Value.Permissions[0].Inverted).IsTrue();
        await Assert.That(result.Value.Permissions[0].HasConditions).IsTrue();
        await Assert.That(result.Value.Permissions[0].IncludesConditionValues).IsFalse();
        await Assert.That(wire.State["name"]!.GetValue<string>()).IsEqualTo("Reviewed role");
        await Assert.That(wire.State["slug"]!.GetValue<string>()).IsEqualTo(Slug);
        await Assert.That(wire.State["description"]!.GetValue<string>()).IsEqualTo("Reviewed description");
        JsonObject permission = wire.State["permissions"]![0]!.AsObject();
        await Assert.That(permission["subject"]!.GetValue<string>()).IsEqualTo(route < 2 ? "app-connections" : "secrets");
        await Assert.That(permission["inverted"]!.GetValue<bool>()).IsTrue();
        await Assert.That(permission["action"]!.AsArray().Select(a => a!.GetValue<string>()).ToArray())
            .IsEquivalentTo(route < 2 ? new[] { "read", "connect" } : new[] { "describeSecret", "readValue" });
        JsonNode condition = permission["conditions"]![route < 2 ? "connectionId" : "environment"]!;
        await Assert.That(condition["$eq"]!.GetValue<string>()).IsEqualTo("selected-private");
        await Assert.That(condition["$ne"]!.GetValue<string>()).IsEqualTo("excluded-private");
        await Assert.That(condition["$in"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray())
            .IsEquivalentTo(new[] { "selected-private", "another-private" });
        if (route >= 2)
        {
            await Assert.That(permission["conditions"]!["secretPath"]!["$glob"]!.GetValue<string>()).IsEqualTo("/reviewed/**");
            await Assert.That(permission["conditions"]!["secretTags"]!["$all"]![0]!.GetValue<string>()).IsEqualTo("approved");
        }
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Revision).IsEqualTo(1);
        await Assert.That((await client.ExecuteAsync(request, authority, Grant(authority, route), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task AbsentNullEmptyDescriptionAndPermissionUpdatesRemainDistinct(int route)
    {
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        for (int choice = 0; choice < 3; choice++)
        {
            RoleDescription? description = choice == 0 ? null : new(choice == 1 ? null : "");
            using var request = route < 2
                ? MakeOrganization(route, new(name: "Description choice", slug: Slug,
                    description: description, permissions: []))
                : MakeProject(route, new(name: "Description choice", slug: Slug,
                    description: description, permissions: []));
            var target = route < 2
                ? OrganizationTarget(route, new(name: "Description choice", slug: Slug, description: description, permissions: []))
                : ProjectTarget(route, new(name: "Description choice", slug: Slug, description: description, permissions: []));
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(Operation(route), target), client.CreateReceipt(request));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(wire.State["permissions"]!.AsArray().Count).IsEqualTo(0);
            await Assert.That(wire.LastBody!.ContainsKey("description")).IsEqualTo(choice != 0);
            if (choice == 1) await Assert.That(wire.State["description"]).IsNull();
            else await Assert.That(wire.State["description"]!.GetValue<string>())
                .IsEqualTo(choice == 0 ? "original-private" : "");
        }
    }

    [Test]
    [Arguments(1)]
    [Arguments(3)]
    public async Task RenameOnlyUpdatePreservesExistingPermissionsAndDescription(int route)
    {
        using var request = route == 1
            ? RoleChangeOperations.UpdateOrganizationRole(Org, Role, new(name: "Rename only"))
            : RoleChangeOperations.UpdateProjectRole(Org, Project, Role, new(name: "Rename only"));
        var target = route == 1
            ? RoleChangeOperations.OrganizationUpdateTarget(Org, Role, new(name: "Rename only"))
            : RoleChangeOperations.ProjectUpdateTarget(Org, Project, Role, new(name: "Rename only"));
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(Operation(route), target),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.State["description"]!.GetValue<string>()).IsEqualTo("original-private");
        await Assert.That(wire.State["permissions"]!.AsArray().Count).IsEqualTo(1);
        await Assert.That(wire.State["slug"]!.GetValue<string>()).IsEqualTo(Slug);
        await Assert.That(wire.LastBody!.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(0, "intent")]
    [Arguments(1, "intent")]
    [Arguments(2, "intent")]
    [Arguments(3, "intent")]
    [Arguments(0, "condition")]
    [Arguments(1, "condition")]
    [Arguments(2, "condition")]
    [Arguments(3, "condition")]
    [Arguments(0, "inversion")]
    [Arguments(1, "inversion")]
    [Arguments(2, "inversion")]
    [Arguments(3, "inversion")]
    [Arguments(0, "description")]
    [Arguments(1, "description")]
    [Arguments(2, "description")]
    [Arguments(3, "description")]
    [Arguments(0, "issuer")]
    [Arguments(1, "role")]
    [Arguments(2, "project")]
    [Arguments(3, "organization")]
    [Arguments(0, "missing")]
    [Arguments(1, "operation")]
    public async Task IndependentGrantBindsScopeRoleAndEverySuppliedChangeBeforeTokens(int route, string defect)
    {
        using var request = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = Authority(client, route, tokens);
        string org = defect == "organization" ? "other" : Org;
        string project = defect == "project" ? "other" : Project;
        var issuer = defect is "issuer" or "organization" or "project"
            ? new ManagementAuthority(client.Authority, tokens, org, route < 2 ? null : project) : authority;
        var target = route < 2
            ? OrganizationTarget(route, OrganizationChange(defect), org, defect == "role" ? "other" : Role)
            : ProjectTarget(route, ProjectChange(defect), org, project);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, defect == "missing" ? null :
            issuer.IssueGrant(defect == "operation" ? "other" : Operation(route), target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments(0, "orgId")]
    [Arguments(1, "id")]
    [Arguments(2, "projectId")]
    [Arguments(3, "id")]
    [Arguments(0, "slug")]
    [Arguments(1, "slug")]
    [Arguments(2, "slug")]
    [Arguments(3, "orgId")]
    public async Task ReturnedCoordinatesNeverAttestAnotherRoleOrScope(int route, string field)
    {
        using var request = Request(route);
        var wire = new Wire(route) { Corrupt = field };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, route), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments(0, "role")]
    [Arguments(0, "orgId")]
    [Arguments(1, "id")]
    [Arguments(2, "projectId")]
    [Arguments(3, "permissions")]
    [Arguments(0, "createdAt")]
    [Arguments(1, "updatedAt")]
    [Arguments(2, "name")]
    public async Task MissingNativeResponseFieldsRemainUnknown(int route, string field)
    {
        using var request = Request(route);
        var wire = new Wire(route) { Missing = field };
        var result = await Execute(request, route, wire);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments(0, false)]
    [Arguments(1, false)]
    [Arguments(2, false)]
    [Arguments(3, false)]
    [Arguments(0, true)]
    [Arguments(1, true)]
    [Arguments(2, true)]
    [Arguments(3, true)]
    public async Task CancellationUsesExactNativeDispatchAndCommitBarriers(int route, bool afterCommit)
    {
        using var request = Request(route);
        var wire = new Wire(route) { HoldBeforeCommit = !afterCommit, HoldAfterCommit = afterCommit };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        var operation = client.ExecuteAsync(request, authority, Grant(authority, route), receipt, cancel.Token).AsTask();
        await (afterCommit ? wire.Committed.Task : wire.Entered.Task).WaitAsync(TimeSpan.FromSeconds(5));
        cancel.Cancel();
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Revision).IsEqualTo(afterCommit ? 1 : 0);
        if (afterCommit) await Assert.That(wire.State["name"]!.GetValue<string>()).IsEqualTo("Reviewed role");
        await Assert.That((await client.ExecuteAsync(request, authority, Grant(authority, route), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task PredispatchCancellationAndLostResponseDoNotReplay(int route)
    {
        using var request = Request(route);
        var wire = new Wire(route) { LoseResponse = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = Authority(client, route, tokens);
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        await Assert.That(async () => await client.ExecuteAsync(request, authority, Grant(authority, route),
            receipt, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, route), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.State["name"]!.GetValue<string>()).IsEqualTo("Reviewed role");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.ExecuteAsync(request, authority, Grant(authority, route), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task ReceiptCannotCrossImmutableRequestOrClient(int route)
    {
        using var request = Request(route);
        using var otherRequest = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var otherClient = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = Authority(client, route, tokens);
        foreach (ManagementReceipt foreign in new[] { client.CreateReceipt(otherRequest), otherClient.CreateReceipt(request) })
        {
            var result = await client.ExecuteAsync(request, authority, Grant(authority, route), foreign);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(foreign.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        }
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task ConcurrentReceiptUseCommitsExactlyOneStateTransition(int route)
    {
        using var request = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens { Rendezvous = true };
        var authority = Authority(client, route, tokens);
        var receipt = client.CreateReceipt(request);
        Task<SecretOutcome<RoleSummary>> first = client.ExecuteAsync(request, authority, Grant(authority, route), receipt).AsTask();
        Task<SecretOutcome<RoleSummary>> second = client.ExecuteAsync(request, authority, Grant(authority, route), receipt).AsTask();
        await tokens.BothEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        tokens.Release.TrySetResult();
        var results = await Task.WhenAll(first, second);
        await Assert.That(results.Count(r => r.Status == SecretStatus.Success)).IsEqualTo(1);
        await Assert.That(results.Count(r => r.Status == SecretStatus.Invalid)).IsEqualTo(1);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    public async Task ProtectedImmutableInputsOwnActionsConditionsAndPermissionSelections()
    {
        OrganizationRoleAction[] actions = [OrganizationRoleAction.Connect];
        string[] selectors = ["original-private"];
        RoleCondition[] conditions = [new(RoleConditionField.ConnectionId, RoleStringClause.Compare(included: selectors))];
        OrganizationRolePermission[] permissions = [new(OrganizationRoleSubject.AppConnections, actions, conditions: conditions)];
        var change = new OrganizationRoleChange("Original role", Slug, permissions: permissions);
        using var request = RoleChangeOperations.CreateOrganizationRole(Org, change);
        var target = RoleChangeOperations.OrganizationCreationTarget(Org, change);
        actions[0] = OrganizationRoleAction.Delete;
        selectors[0] = "broadened-private";
        conditions[0] = new(RoleConditionField.ConnectionId, RoleStringClause.Literal("broadened-private"));
        permissions[0] = new(OrganizationRoleSubject.Role, OrganizationRoleAction.Delete);
        var wire = new Wire(0);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, 0);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(Operation(0), target),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.State["permissions"]![0]!["action"]![0]!.GetValue<string>()).IsEqualTo("connect");
        await Assert.That(wire.State["permissions"]![0]!["conditions"]!["connectionId"]!["$in"]![0]!.GetValue<string>())
            .IsEqualTo("original-private");
        foreach (object protectedValue in new object[] { change, request, target, result.Value,
            new RoleDescription("private-description"), RoleStringClause.Literal("private-condition"),
            new RoleSecretTags(all: ["private-tag"]), new OrganizationRolePermission(OrganizationRoleSubject.Role, OrganizationRoleAction.Read),
            new ProjectRolePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read) })
        {
            await Assert.That(JsonSerializer.Serialize(protectedValue).Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(protectedValue.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    public async Task InvalidOrUnsupportedPermissionConstraintsRejectWithoutBroadening()
    {
        await Assert.That(() => new OrganizationRolePermission(OrganizationRoleSubject.Workspace, OrganizationRoleAction.Read)).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Workspace, ProjectRoleAction.Create)).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Role, ProjectRoleAction.ReadValue)).Throws<ArgumentException>();
        await Assert.That(() => new OrganizationRolePermission((OrganizationRoleSubject)999, OrganizationRoleAction.Read)).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Secrets, (ProjectRoleAction)999)).Throws<ArgumentException>();
        await Assert.That(() => new OrganizationRolePermission(OrganizationRoleSubject.Role, OrganizationRoleAction.Read, inverted: false)).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Role, ProjectRoleAction.Read,
            conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("production"))])).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.SecretFolders, ProjectRoleAction.Read,
            conditions: [new(RoleConditionField.Environment, RoleStringClause.Compare(glob: "*"))])).Throws<ArgumentException>();
        await Assert.That(() => new OrganizationRolePermission(OrganizationRoleSubject.AppConnections, OrganizationRoleAction.Read,
            conditions: [new(RoleConditionField.ConnectionId, RoleStringClause.Compare(glob: "*"))])).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.PkiSubscribers, ProjectRoleAction.Read,
            conditions: [new(RoleConditionField.Name, RoleStringClause.Compare(notEqual: "unselected"))])).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.SecretFolders, ProjectRoleAction.Read,
            secretTags: new(all: ["tag"]))).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Secrets, Array.Empty<ProjectRoleAction>())).Throws<ArgumentException>();
        await Assert.That(() => new OrganizationRoleChange()).Throws<ArgumentException>();
        await Assert.That(() => new OrganizationRoleChange(slug: new string('x', 65))).Throws<ArgumentException>();
        await Assert.That(() => RoleChangeOperations.CreateOrganizationRole(Org, new(name: "missing fields"))).Throws<ArgumentException>();
        await Assert.That(() => RoleChangeOperations.CreateProjectRole(Org, Project, new(name: "", slug: Slug, permissions: []))).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRoleChange(permissions: Enumerable.Repeat(
            new ProjectRolePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read), 129).ToArray())).Throws<ArgumentException>();
        var large = new ProjectRoleChange("Large", Slug, permissions: Enumerable.Range(0, 128).Select(_ =>
            new ProjectRolePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read, conditions:
                [new(RoleConditionField.SecretName, RoleStringClause.Literal(new string('\u4e00', 1024)))])).ToArray());
        await Assert.That(() => RoleChangeOperations.CreateProjectRole(Org, Project, large)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(2)]
    [Arguments(3)]
    public async Task ConcreteMetadataEntryMatchPreservesSameEntrySemantics(int route)
    {
        var change = new ProjectRoleChange("Metadata role", Slug, permissions:
        [
            new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Lease,
                metadata: new(key: RoleStringClause.Compare(equal: "owner", notEqual: "public"),
                    value: RoleStringClause.Compare(included: ["reviewed", "approved"]))),
            new(ProjectRoleSubject.Certificates, ProjectRoleAction.Read,
                metadata: new(key: RoleStringClause.Compare(equal: "owner"),
                    value: RoleStringClause.Compare(included: ["reviewed"])))
        ]);
        using var request = MakeProject(route, change);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(Operation(route), ProjectTarget(route, change)), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        JsonNode entry = wire.State["permissions"]![0]!["conditions"]!["metadata"]!["$elemMatch"]!;
        await Assert.That(entry["key"]!["$eq"]!.GetValue<string>()).IsEqualTo("owner");
        await Assert.That(entry["key"]!["$ne"]!.GetValue<string>()).IsEqualTo("public");
        await Assert.That(entry["value"]!["$in"]!.AsArray().Count).IsEqualTo(2);
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Certificates, ProjectRoleAction.Read,
            metadata: new(key: RoleStringClause.Compare(notEqual: "public")))).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
            metadata: new(key: RoleStringClause.Compare(equal: "owner")))).Throws<ArgumentException>();
        await Assert.That(() => new RoleMetadataMatch(key: RoleStringClause.Literal("owner"))).Throws<ArgumentException>();
        await Assert.That(() => new RoleMetadataMatch(value: RoleStringClause.Compare(glob: "*"))).Throws<ArgumentException>();
    }

    [Test]
    public async Task EveryActiveSubjectHasAnAuthorableNativeSelection()
    {
        OrganizationRolePermission[] organizationPermissions = Enum.GetValues<OrganizationRoleSubject>().Select(subject =>
            new OrganizationRolePermission(subject, subject switch
            {
                OrganizationRoleSubject.Workspace or OrganizationRoleSubject.Project or OrganizationRoleSubject.SubOrganization => OrganizationRoleAction.Create,
                OrganizationRoleSubject.OrganizationAdminConsole => OrganizationRoleAction.AccessAllProjects,
                OrganizationRoleSubject.SecretShare => OrganizationRoleAction.ManageSettings,
                OrganizationRoleSubject.Kmip => OrganizationRoleAction.Proxy,
                OrganizationRoleSubject.MachineIdentityAuthTemplate => OrganizationRoleAction.ListTemplates,
                OrganizationRoleSubject.Gateway => OrganizationRoleAction.ListGateways,
                OrganizationRoleSubject.GatewayPool => OrganizationRoleAction.ListGatewayPools,
                OrganizationRoleSubject.Relay => OrganizationRoleAction.ListRelays,
                OrganizationRoleSubject.KmipServer => OrganizationRoleAction.ListKmipServers,
                OrganizationRoleSubject.HoneyTokens => OrganizationRoleAction.Setup,
                _ => OrganizationRoleAction.Read
            })).ToArray();
        ProjectRolePermission[] projectPermissions = Enum.GetValues<ProjectRoleSubject>().Select(subject =>
            new ProjectRolePermission(subject, subject switch
            {
                ProjectRoleSubject.Workspace or ProjectRoleSubject.Kms => ProjectRoleAction.Edit,
                ProjectRoleSubject.DynamicSecrets => ProjectRoleAction.Lease,
                ProjectRoleSubject.SecretEventSubscriptions => ProjectRoleAction.SubscribeToCreationEvents,
                ProjectRoleSubject.Kmip => ProjectRoleAction.ReadClients,
                ProjectRoleSubject.SecretScanningDataSources => ProjectRoleAction.ReadDataSources,
                ProjectRoleSubject.SecretScanningFindings => ProjectRoleAction.ReadFindings,
                ProjectRoleSubject.SecretScanningConfigs => ProjectRoleAction.ReadConfigs,
                ProjectRoleSubject.AppConnections => ProjectRoleAction.ReadAppConnections,
                ProjectRoleSubject.HsmConnectors => ProjectRoleAction.ReadHsmConnectors,
                ProjectRoleSubject.ProjectFolderGrant => ProjectRoleAction.ReadGrant,
                _ => ProjectRoleAction.Read
            })).ToArray();
        var orgChange = new OrganizationRoleChange("All organization selections", Slug, permissions: organizationPermissions);
        var projectChange = new ProjectRoleChange("All project selections", Slug, permissions: projectPermissions);
        using var orgRequest = MakeOrganization(0, orgChange);
        using var projectRequest = MakeProject(2, projectChange);
        foreach (int route in new[] { 0, 2 })
        {
            var wire = new Wire(route);
            using var transport = Transport(wire);
            var client = new ManagementClient(transport);
            var authority = Authority(client, route);
            var result = await client.ExecuteAsync(route == 0 ? orgRequest : projectRequest, authority,
                authority.IssueGrant(Operation(route), route == 0 ? OrganizationTarget(route, orgChange) :
                    ProjectTarget(route, projectChange)), client.CreateReceipt(route == 0 ? orgRequest : projectRequest));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            string[] subjects = wire.State["permissions"]!.AsArray().Select(p => p!["subject"]!.GetValue<string>()).ToArray();
            string[] expected = (route == 0
                ? "workspace project role sub-organization member settings incident-contact sso scim github-org-sync github-org-sync-manual ldap groups secret-scanning billing identity kms audit-logs project-templates app-connections organization-admin-console secret-share kmip machine-identity-auth-template gateway gateway-pool relay kmip-server email-domains certificate-manager honey-tokens oauth-clients secrets-management-insights"
                : "secrets secret-folders secret-imports dynamic-secrets identity pki-subscribers certificate-templates secret-rotation secret-syncs pki-syncs secret-event-subscriptions certificate-profiles certificate-policies certificate-application certificate-authorities certificates secret-approval secret-rollback member groups role integrations webhooks service-tokens settings secret-validation-rules environments tags audit-logs insights ip-allowlist pki-alerts pki-collections certificate-inventory-views pki-discovery pki-certificate-installations code-signers workspace kms cmek kmip commits secret-scanning-data-sources secret-scanning-findings secret-scanning-configs app-connections hsm-connectors honey-tokens proxied-services agent-vault-access-bundles agent-vault-sessions agent-vault-proxies approval-requests approval-request-grants secret-approval-request project-folder-grant").Split(' ');
            await Assert.That(subjects).IsEquivalentTo(expected);
            await Assert.That(wire.State["permissions"]!.AsArray().All(p => p!["action"] is JsonValue)).IsTrue();
        }
    }

    [Test]
    [Arguments(ProjectRoleSubject.Identity, RoleConditionField.IdentityId, false)]
    [Arguments(ProjectRoleSubject.Identity, RoleConditionField.AssignableSubject, true)]
    [Arguments(ProjectRoleSubject.Member, RoleConditionField.UserEmail, true)]
    [Arguments(ProjectRoleSubject.Groups, RoleConditionField.GroupName, true)]
    [Arguments(ProjectRoleSubject.CertificateTemplates, RoleConditionField.Name, true)]
    [Arguments(ProjectRoleSubject.PkiSyncs, RoleConditionField.SubscriberName, true)]
    [Arguments(ProjectRoleSubject.CertificateProfiles, RoleConditionField.Slug, true)]
    [Arguments(ProjectRoleSubject.Certificates, RoleConditionField.AltNames, true)]
    [Arguments(ProjectRoleSubject.SecretEventSubscriptions, RoleConditionField.ConnectionId, false)]
    [Arguments(ProjectRoleSubject.Commits, RoleConditionField.Environment, true)]
    [Arguments(ProjectRoleSubject.HoneyTokens, RoleConditionField.SecretPath, true)]
    [Arguments(ProjectRoleSubject.ProxiedServices, RoleConditionField.Environment, true)]
    [Arguments(ProjectRoleSubject.ProjectFolderGrant, RoleConditionField.SecretPath, true)]
    public async Task TypedConditionFieldsPreserveConjunctiveOperators(ProjectRoleSubject subject, RoleConditionField field, bool glob)
    {
        ProjectRoleAction action = subject switch
        {
            ProjectRoleSubject.SecretEventSubscriptions => ProjectRoleAction.SubscribeToCreationEvents,
            ProjectRoleSubject.ProjectFolderGrant => ProjectRoleAction.ReadGrant,
            _ => ProjectRoleAction.Read
        };
        var change = new ProjectRoleChange("Constrained", Slug, permissions:
            [new(subject, action, inverted: false, conditions: [new(field, RoleStringClause.Compare(equal: "selected",
                notEqual: "excluded", included: ["selected"], glob: glob ? "reviewed*" : null))])]);
        using var request = MakeProject(2, change);
        var wire = new Wire(2);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, 2);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(Operation(2), ProjectTarget(2, change)), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var conditions = wire.State["permissions"]![0]!["conditions"]!.AsObject();
        await Assert.That(conditions.Count).IsEqualTo(1);
        var clause = conditions.First().Value!.AsObject();
        await Assert.That(clause["$eq"]!.GetValue<string>()).IsEqualTo("selected");
        await Assert.That(clause["$ne"]!.GetValue<string>()).IsEqualTo("excluded");
        await Assert.That(clause["$in"]![0]!.GetValue<string>()).IsEqualTo("selected");
        await Assert.That(clause.ContainsKey("$glob")).IsEqualTo(glob);
    }

    private static RoleStringClause Clause() =>
        RoleStringClause.Compare(equal: "selected-private", notEqual: "excluded-private", included: ["selected-private", "another-private"]);
    private static OrganizationRoleChange OrganizationChange(string? defect = null) =>
        new(defect == "intent" ? "Other role" : "Reviewed role", Slug,
            defect == "description" ? new(null) : new("Reviewed description"),
            [new(OrganizationRoleSubject.AppConnections, new[] { OrganizationRoleAction.Read, OrganizationRoleAction.Connect },
                inverted: defect != "inversion", conditions: [new(RoleConditionField.ConnectionId,
                    defect == "condition" ? RoleStringClause.Literal("broader") : Clause())])]);
    private static ProjectRoleChange ProjectChange(string? defect = null) =>
        new(defect == "intent" ? "Other role" : "Reviewed role", Slug,
            defect == "description" ? new(null) : new("Reviewed description"),
            [new(ProjectRoleSubject.Secrets, new[] { ProjectRoleAction.DescribeSecret, ProjectRoleAction.ReadValue },
                inverted: defect != "inversion", conditions:
                [new(RoleConditionField.Environment, defect == "condition" ? RoleStringClause.Literal("broader") : Clause()),
                new(RoleConditionField.SecretPath, RoleStringClause.Compare(glob: "/reviewed/**"))],
                secretTags: new(all: ["approved"]))]);
    private static ManagementRequest<RoleSummary> Request(int route) =>
        route < 2 ? MakeOrganization(route, OrganizationChange()) : MakeProject(route, ProjectChange());
    private static ManagementRequest<RoleSummary> MakeOrganization(int route, OrganizationRoleChange change) =>
        route == 0 ? RoleChangeOperations.CreateOrganizationRole(Org, change) :
            RoleChangeOperations.UpdateOrganizationRole(Org, Role, change);
    private static ManagementRequest<RoleSummary> MakeProject(int route, ProjectRoleChange change) =>
        route == 2 ? RoleChangeOperations.CreateProjectRole(Org, Project, change) :
            RoleChangeOperations.UpdateProjectRole(Org, Project, Role, change);
    private static ManagementTarget OrganizationTarget(int route, OrganizationRoleChange change,
        string org = Org, string role = Role) =>
        route == 0 ? RoleChangeOperations.OrganizationCreationTarget(org, change) :
            RoleChangeOperations.OrganizationUpdateTarget(org, role, change);
    private static ManagementTarget ProjectTarget(int route, ProjectRoleChange change,
        string org = Org, string project = Project) =>
        route == 2 ? RoleChangeOperations.ProjectCreationTarget(org, project, change) :
            RoleChangeOperations.ProjectUpdateTarget(org, project, Role, change);
    private static string Operation(int route) => route switch
    {
        0 => "infisical.post.v1.organization.roles",
        1 => "infisical.patch.v1.organization.roles.by.roleId",
        2 => "infisical.post.v1.projects.by.projectId.roles",
        _ => "infisical.patch.v1.projects.by.projectId.roles.by.roleId"
    };
    private static ManagementGrant Grant(ManagementAuthority authority, int route) =>
        authority.IssueGrant(Operation(route), route < 2
            ? OrganizationTarget(route, OrganizationChange()) : ProjectTarget(route, ProjectChange()));
    private static ManagementAuthority Authority(ManagementClient client, int route, Tokens? tokens = null) =>
        new(client.Authority, tokens ?? new Tokens(), Org, route < 2 ? null : Project);
    private static ManagementTransport Transport(Wire wire) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
    private static async Task<SecretOutcome<RoleSummary>> Execute(ManagementRequest<RoleSummary> request, int route, Wire wire)
    {
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        return await client.ExecuteAsync(request, authority, Grant(authority, route), client.CreateReceipt(request));
    }
    private sealed class Tokens : IInfisicalTokenSource
    {
        private int _entered;
        public bool Acquired { get; private set; }
        public bool Rendezvous { get; init; }
        public TaskCompletionSource BothEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            if (Rendezvous)
            {
                if (Interlocked.Increment(ref _entered) == 2) BothEntered.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-fixture-token")));
        }
    }
    private sealed class Wire(int route) : HttpMessageHandler
    {
        public JsonObject State { get; } = new()
        {
            ["id"] = Role,
            ["name"] = "Original",
            ["slug"] = Slug,
            ["description"] = "original-private",
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-01T00:00:00Z",
            [route < 2 ? "orgId" : "projectId"] = route < 2 ? Org : Project,
            ["permissions"] = new JsonArray(new JsonObject { ["subject"] = "role", ["action"] = "read" })
        };
        public JsonObject? LastBody { get; private set; }
        public int Revision { get; private set; }
        public bool HoldBeforeCommit { get; init; }
        public bool HoldAfterCommit { get; init; }
        public bool LoseResponse { get; init; }
        public string? Corrupt { get; init; }
        public string? Missing { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = route < 2 ? "/api/v1/organization/roles" : $"/api/v1/projects/{Project}/roles";
            if (route % 2 == 1) path += "/" + Role;
            if (request.RequestUri!.PathAndQuery != path || request.Method.Method != (route % 2 == 0 ? "POST" : "PATCH") ||
                request.Headers.Authorization?.Scheme != "Bearer")
                return new(HttpStatusCode.NotFound);
            LastBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
            Entered.TrySetResult();
            if (HoldBeforeCommit) await Release.Task.WaitAsync(cancellationToken);
            foreach (var field in LastBody) State[field.Key] = field.Value?.DeepClone();
            Revision++;
            Committed.TrySetResult();
            if (HoldAfterCommit) await Release.Task.WaitAsync(cancellationToken);
            if (LoseResponse) throw new IOException("Lost committed response.");
            JsonObject responseRole = State.DeepClone().AsObject();
            if (Corrupt is not null) responseRole[Corrupt] = Corrupt is "id" or "orgId" ? ForeignUuid : "other";
            if (Missing is not null) responseRole.Remove(Missing);
            JsonObject response = Missing == "role" ? new() : new() { ["role"] = responseRole };
            return new(HttpStatusCode.OK) { Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }
}
