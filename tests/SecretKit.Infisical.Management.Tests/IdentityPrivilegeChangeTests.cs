using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class IdentityPrivilegeChangeTests
{
    private const string Org = "org-private";
    private const string Project = "project-private";
    private const string ProjectSlug = "project-slug-private";
    private const string Identity = "identity-private";
    private const string Membership = "4dc64d95-bc40-4d5f-86a2-e5b7459cd018";
    private const string Id = "cf96114b-6b85-48f8-b25a-9f456747d74f";
    private const string ForeignUuid = "70bc9c42-31b3-4a13-ac45-dc937db4eb63";
    private const string Slug = "privilege-slug-private";
    private static readonly DateTimeOffset Start = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task FixedRoutesApplyExactNativeStateAndInspectWithoutReceipt(int route)
    {
        using var request = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var receipt = route == 5 ? null : client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, route), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Id).IsEqualTo(Id);
        await Assert.That(result.Value.Slug).IsEqualTo(Slug);
        await Assert.That(result.Value.IncludesPermissions).IsTrue();
        await Assert.That(result.Value.Permissions![0].Subject!.Values[0])
            .IsEqualTo(route == 5 ? "role" : "secrets");
        await Assert.That(result.Value.CreatedAt).IsEqualTo("2026-10-01T00:00:00Z");
        await Assert.That(result.Value.UpdatedAt).IsEqualTo("2026-10-01T00:00:00Z");
        await Assert.That(result.Value.IsTemporary).IsEqualTo(route is not (1 or 5));
        await Assert.That(wire.Revision).IsEqualTo(route == 5 ? 0 : 1);
        if (route == 5)
        {
            await Assert.That(() => client.CreateReceipt(request)).Throws<ArgumentException>();
            await Assert.That(wire.LastBody).IsNull();
            return;
        }
        await Assert.That(receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.State["permissions"]![0]!["subject"]!.GetValue<string>()).IsEqualTo("secrets");
        JsonNode permissions = wire.State["permissions"]![0]!;
        await Assert.That(permissions["conditions"]!["secretPath"]!["$glob"]!.GetValue<string>()).IsEqualTo("/reviewed/**");
        if (route < 3)
        {
            await Assert.That(permissions["action"]!.GetValue<string>()).IsEqualTo("read");
            await Assert.That(permissions["conditions"]!["environment"]!.GetValue<string>()).IsEqualTo("dev-private");
            await Assert.That(wire.LastBody!["projectSlug"]!.GetValue<string>()).IsEqualTo(ProjectSlug);
        }
        else
        {
            await Assert.That(permissions["action"]!.AsArray().Select(p => p!.GetValue<string>()).ToArray())
                .IsEquivalentTo(new[] { "describeSecret", "readValue" });
            await Assert.That(permissions["conditions"]!["environment"]!["$eq"]!.GetValue<string>()).IsEqualTo("dev-private");
            await Assert.That(permissions["inverted"]!.GetValue<bool>()).IsFalse();
            await Assert.That(permissions["conditions"]!["secretTags"]!["$all"]![0]!.GetValue<string>()).IsEqualTo("reviewed");
            await Assert.That(wire.LastBody!.ContainsKey("projectId")).IsEqualTo(route == 3);
        }
        await Assert.That(wire.State["isTemporary"]!.GetValue<bool>()).IsEqualTo(route != 1);
        if (route != 1)
        {
            await Assert.That(result.Value.Mode).IsEqualTo("relative");
            await Assert.That(result.Value.Range).IsEqualTo("1h");
            await Assert.That(DateTimeOffset.Parse(result.Value.StartsAt!)).IsEqualTo(Start);
        }
        await Assert.That((await client.ExecuteAsync(request, authority, Grant(authority, route), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task LegacyAlternativeHasPluralActionsAndRequiredEnvironment(int route)
    {
        var conditions = new LegacyPrivilegeConditions("prod-private", "/exact/**");
        var change = new LegacyPrivilegeChange(Slug, privilegePermission:
            new([LegacyPrivilegeAction.Read, LegacyPrivilegeAction.Edit], conditions));
        using var request = LegacyRequest(route, change);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(Operation(route),
            IdentityPrivilegeChangeOperations.LegacyChangeTarget(Selection(), change,
                route == 0 ? Slug : null, route == 0 ? null : Lifetime(route))), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        JsonObject body = (route == 0 ? wire.LastBody!["privilegeDetails"]! : wire.LastBody!).AsObject();
        await Assert.That(body.ContainsKey("permissions")).IsFalse();
        await Assert.That(body["privilegePermission"]!["actions"]!.AsArray().Select(a => a!.GetValue<string>()).ToArray())
            .IsEquivalentTo(new[] { "read", "edit" });
        await Assert.That(body["privilegePermission"]!["conditions"]!["environment"]!.GetValue<string>()).IsEqualTo("prod-private");
        await Assert.That(wire.State["permissions"]![0]!["action"]!.AsArray().Count).IsEqualTo(2);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task OptionalFieldsOmitRatherThanWriteNullAndEmptyPermissionsStayExplicit(int route)
    {
        using var request = route < 3 ? LegacyRequest(route, new(permissions: [])) :
            IdentityPrivilegeChangeOperations.CreateProjectPrivilege(Selection(), new([], PrivilegeLifetime.Permanent()));
        var target = route < 3
            ? IdentityPrivilegeChangeOperations.LegacyChangeTarget(Selection(), new(permissions: []),
                route == 0 ? Slug : null, route == 0 ? null : Lifetime(route))
            : IdentityPrivilegeChangeOperations.ProjectChangeTarget(Selection(), new([], PrivilegeLifetime.Permanent()));
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(Operation(route), target),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        JsonObject body = (route == 0 ? wire.LastBody!["privilegeDetails"]! : wire.LastBody!).AsObject();
        await Assert.That(body.ContainsKey("slug")).IsFalse();
        await Assert.That(body["permissions"]!.AsArray().Count).IsEqualTo(0);
        await Assert.That(body.ContainsKey("privilegePermission")).IsFalse();
        await Assert.That(wire.State["permissions"]!.AsArray().Count).IsEqualTo(0);
        if (route == 3)
        {
            await Assert.That(body["type"]!.AsObject().Count).IsEqualTo(1);
            await Assert.That(body["type"]!["isTemporary"]!.GetValue<bool>()).IsFalse();
        }
        else if (route != 2) await Assert.That(body.ContainsKey("temporaryRange")).IsFalse();
    }

    [Test]
    public async Task LegacyRenameAndPartialValidityPreserveOmittedFields()
    {
        var change = new LegacyPrivilegeChange(slug: "renamed-private", temporaryRange: "2h");
        using var request = IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege(Selection(), Slug, change);
        var wire = new Wire(0);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(Operation(0),
            IdentityPrivilegeChangeOperations.LegacyChangeTarget(Selection(), change, Slug)), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Slug).IsEqualTo("renamed-private");
        await Assert.That(wire.State["permissions"]!.AsArray().Count).IsEqualTo(1);
        await Assert.That(wire.State["temporaryRange"]!.GetValue<string>()).IsEqualTo("2h");
        await Assert.That(wire.LastBody!["privilegeDetails"]!.AsObject().Count).IsEqualTo(2);
    }

    [Test]
    [Arguments(0, "project")]
    [Arguments(1, "identity")]
    [Arguments(2, "membership")]
    [Arguments(3, "projectSlug")]
    [Arguments(4, "id")]
    [Arguments(5, "slug")]
    [Arguments(0, "intent")]
    [Arguments(1, "intent")]
    [Arguments(2, "intent")]
    [Arguments(3, "intent")]
    [Arguments(4, "intent")]
    [Arguments(0, "validity")]
    [Arguments(2, "validity")]
    [Arguments(3, "validity")]
    [Arguments(4, "validity")]
    [Arguments(0, "issuer")]
    [Arguments(3, "missing")]
    [Arguments(5, "organization")]
    public async Task IndependentHostGrantBindsScopeSlugMembershipAndExactIntentBeforeTokens(int route, string defect)
    {
        using var request = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = Authority(client, tokens);
        LegacyPrivilegeSelection selection = Selection(defect);
        var issuer = defect is "issuer" or "organization" or "project"
            ? new ManagementAuthority(client.Authority, tokens, selection.OrganizationId, selection.ProjectId) : authority;
        ManagementTarget target = Target(route, selection, defect);
        var receipt = route == 5 ? null : client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            defect == "missing" ? null : issuer.IssueGrant(Operation(route), target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments(0, "projectMembershipId")]
    [Arguments(1, "projectMembershipId")]
    [Arguments(2, "projectMembershipId")]
    [Arguments(0, "slug")]
    [Arguments(3, "slug")]
    [Arguments(4, "id")]
    [Arguments(4, "slug")]
    [Arguments(5, "slug")]
    public async Task SuppliedNativeCoordinatesAreValidatedWithoutInventingV2Scope(int route, string field)
    {
        using var request = Request(route);
        var wire = new Wire(route) { Corrupt = field };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var receipt = route == 5 ? null : client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, route), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(route == 5 ? 0 : 1);
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments(0, "privilege")]
    [Arguments(1, "projectMembershipId")]
    [Arguments(2, "permissions")]
    [Arguments(3, "createdAt")]
    [Arguments(4, "updatedAt")]
    [Arguments(5, "id")]
    public async Task MissingNativeResponseEvidenceRemainsUnknown(int route, string field)
    {
        using var request = Request(route);
        var wire = new Wire(route) { Missing = field };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, route),
            route == 5 ? null : client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments(0, false)]
    [Arguments(1, false)]
    [Arguments(2, false)]
    [Arguments(3, false)]
    [Arguments(4, false)]
    [Arguments(0, true)]
    [Arguments(1, true)]
    [Arguments(2, true)]
    [Arguments(3, true)]
    [Arguments(4, true)]
    public async Task CancellationUsesExactPrecommitAndPostcommitBarriers(int route, bool afterCommit)
    {
        using var request = Request(route);
        var wire = new Wire(route) { HoldBeforeCommit = !afterCommit, HoldAfterCommit = afterCommit };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        var operation = client.ExecuteAsync(request, authority, Grant(authority, route), receipt, cancel.Token).AsTask();
        await (afterCommit ? wire.Committed.Task : wire.Entered.Task).WaitAsync(TimeSpan.FromSeconds(5));
        cancel.Cancel();
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Revision).IsEqualTo(afterCommit ? 1 : 0);
        if (afterCommit) await Assert.That(wire.State["permissions"]![0]!["subject"]!.GetValue<string>()).IsEqualTo("secrets");
        await Assert.That((await client.ExecuteAsync(request, authority, Grant(authority, route), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task PredispatchCancellationAndCommittedLostResponseDoNotReplay(int route)
    {
        using var request = Request(route);
        var wire = new Wire(route) { LoseResponse = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = Authority(client, tokens);
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        await Assert.That(async () => await client.ExecuteAsync(request, authority, Grant(authority, route),
            receipt, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, route), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.State["permissions"]![0]!["subject"]!.GetValue<string>()).IsEqualTo("secrets");
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
    [Arguments(4)]
    public async Task RequiredReceiptsCannotCrossRequestOrClient(int route)
    {
        using var request = Request(route);
        using var differentRequest = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var otherClient = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = Authority(client, tokens);
        foreach (ManagementReceipt? receipt in new[] { null, client.CreateReceipt(differentRequest), otherClient.CreateReceipt(request) })
        {
            var result = await client.ExecuteAsync(request, authority, Grant(authority, route), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        }
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task TokenAcquisitionCancellationNeverBeginsNativeDispatch(int route)
    {
        using var request = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens { Hold = true };
        var authority = Authority(client, tokens);
        var receipt = route == 5 ? null : client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        var operation = client.ExecuteAsync(request, authority, Grant(authority, route), receipt, cancel.Token).AsTask();
        await tokens.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancel.Cancel();
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(wire.Revision).IsEqualTo(0);
        await Assert.That(wire.LastBody).IsNull();
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task ConcurrentSingleReceiptCommitsOnlyOnePrivilegeChange(int route)
    {
        using var request = Request(route);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens { Rendezvous = true };
        var authority = Authority(client, tokens);
        var receipt = client.CreateReceipt(request);
        var first = client.ExecuteAsync(request, authority, Grant(authority, route), receipt).AsTask();
        var second = client.ExecuteAsync(request, authority, Grant(authority, route), receipt).AsTask();
        await tokens.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        tokens.Release.TrySetResult();
        var outcomes = await Task.WhenAll(first, second);
        await Assert.That(outcomes.Count(r => r.Status == SecretStatus.Success)).IsEqualTo(1);
        await Assert.That(outcomes.Count(r => r.Status == SecretStatus.Invalid)).IsEqualTo(1);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments(0)]
    [Arguments(3)]
    public async Task PermissionInputsOwnBoundedCopiesAndProtectedFormatting(int route)
    {
        LegacyPrivilegePermission[] legacy = [new(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read)];
        ProjectRoleAction[] actions = [ProjectRoleAction.ReadValue];
        string[] included = ["dev-private"];
        RoleCondition[] conditions = [new(RoleConditionField.Environment, RoleStringClause.Compare(included: included))];
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Secrets, actions, conditions: conditions)];
        var legacyChange = new LegacyPrivilegeChange(Slug, legacy);
        var modernChange = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), Slug);
        using var request = route == 0 ? LegacyRequest(0, legacyChange) :
            IdentityPrivilegeChangeOperations.CreateProjectPrivilege(Selection(), modernChange);
        var target = route == 0 ? IdentityPrivilegeChangeOperations.LegacyChangeTarget(Selection(), legacyChange, Slug) :
            IdentityPrivilegeChangeOperations.ProjectChangeTarget(Selection(), modernChange);
        legacy[0] = new(ProjectRoleSubject.Role, LegacyPrivilegeAction.Delete);
        actions[0] = ProjectRoleAction.Delete;
        included[0] = "broader";
        conditions[0] = new(RoleConditionField.Environment, RoleStringClause.Literal("broader"));
        permissions[0] = new(ProjectRoleSubject.Secrets, ProjectRoleAction.Delete);
        var wire = new Wire(route);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(Operation(route), target), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        if (route == 0) await Assert.That(wire.State["permissions"]![0]!["action"]!.GetValue<string>()).IsEqualTo("read");
        else
        {
            await Assert.That(wire.State["permissions"]![0]!["action"]![0]!.GetValue<string>()).IsEqualTo("readValue");
            await Assert.That(wire.State["permissions"]![0]!["conditions"]!["environment"]!["$in"]![0]!.GetValue<string>()).IsEqualTo("dev-private");
        }
        foreach (object value in new object[] { legacyChange, modernChange, request, target, result.Value,
            Selection(), new LegacyPrivilegeConditions("private"), new LegacyPrivilegePermission(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read),
            new LegacySecretPrivilegePermission([LegacyPrivilegeAction.Read], new("private")), Lifetime(2) })
        {
            await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    public async Task InvalidTemporaryValidityAndCrossDomainConstraintsNeverBroaden()
    {
        foreach (string range in new[] { "0h", "-1h", "1", "1x", "01h", "1.5h", "184467440737095516160h" })
            await Assert.That(() => PrivilegeLifetime.Temporary(range, Start)).Throws<ArgumentException>();
        await Assert.That(() => new LegacyPrivilegeChange(isTemporary: true)).Throws<ArgumentException>();
        await Assert.That(() => new LegacyPrivilegeChange(isTemporary: false, temporaryRange: "1h")).Throws<ArgumentException>();
        await Assert.That(() => new LegacyPrivilegeChange(temporaryMode: (PrivilegeTemporaryMode)999)).Throws<ArgumentException>();
        await Assert.That(() => new LegacyPrivilegePermission((ProjectRoleSubject)999, LegacyPrivilegeAction.Read)).Throws<ArgumentException>();
        await Assert.That(() => new LegacyPrivilegePermission(ProjectRoleSubject.Secrets, (LegacyPrivilegeAction)999)).Throws<ArgumentException>();
        await Assert.That(() => new LegacySecretPrivilegePermission([], new("dev"))).Throws<ArgumentException>();
        await Assert.That(() => new LegacySecretPrivilegePermission([LegacyPrivilegeAction.Read], new())).Throws<ArgumentException>();
        await Assert.That(() => new LegacyPrivilegeConditions(secretPathGlob: "")).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Lease)).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Role, ProjectRoleAction.Read,
            conditions: [new(RoleConditionField.SecretPath, RoleStringClause.Compare(glob: "**"))])).Throws<ArgumentException>();
        await Assert.That(() => IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(Selection(), Id,
            new([], PrivilegeLifetime.Permanent()))).Throws<ArgumentException>();
        await Assert.That(() => IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege(Selection(), new(), PrivilegeLifetime.Permanent()))
            .Throws<ArgumentException>();
        await Assert.That(() => IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(Selection(), new(isTemporary: false)))
            .Throws<ArgumentException>();
        await Assert.That(() => new LegacyPrivilegeChange(slug: new string('x', 61))).Throws<ArgumentException>();
        await Assert.That(() => new ProjectPrivilegeChange(Enumerable.Repeat(
            new ProjectRolePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read), 129).ToArray(), PrivilegeLifetime.Permanent()))
            .Throws<ArgumentException>();
        var large = new LegacyPrivilegeChange(permissions: Enumerable.Range(0, 128).Select(_ =>
            new LegacyPrivilegePermission(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read,
                new(environment: new string('\u4e00', 1024)))).ToArray());
        await Assert.That(() => IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(Selection(), large)).Throws<ArgumentException>();
    }

    private static LegacyPrivilegeSelection Selection(string? defect = null) =>
        new(defect == "organization" ? "other" : Org, defect == "project" ? "other" : Project,
            defect == "projectSlug" ? "other" : ProjectSlug, defect == "identity" ? "other" : Identity,
            defect == "membership" ? "other" : Membership);
    private static PrivilegeLifetime Lifetime(int route, string? defect = null) =>
        route == 1 ? PrivilegeLifetime.Permanent() : PrivilegeLifetime.Temporary(defect == "validity" ? "2h" : "1h", Start);
    private static LegacyPrivilegeChange LegacyChange(int route, string? defect = null) =>
        new(Slug, [new(ProjectRoleSubject.Secrets, defect == "intent" ? LegacyPrivilegeAction.Delete : LegacyPrivilegeAction.Read,
            new("dev-private", "/reviewed/**"))], isTemporary: route == 0 ? true : null,
            temporaryMode: route == 0 ? PrivilegeTemporaryMode.Relative : null,
            temporaryRange: route == 0 ? defect == "validity" ? "2h" : "1h" : null,
            temporaryAccessStartTime: route == 0 ? Start : null);
    private static ProjectPrivilegeChange ModernChange(string? defect = null) =>
        new([new(ProjectRoleSubject.Secrets, new[] { ProjectRoleAction.DescribeSecret, defect == "intent" ? ProjectRoleAction.Delete : ProjectRoleAction.ReadValue },
            inverted: false, conditions: [new(RoleConditionField.Environment, RoleStringClause.Compare(equal: "dev-private")),
                new(RoleConditionField.SecretPath, RoleStringClause.Compare(glob: "/reviewed/**"))], secretTags: new(all: ["reviewed"]))],
            Lifetime(3, defect), Slug);
    private static ManagementRequest<IdentityPrivilegeSummary> LegacyRequest(int route, LegacyPrivilegeChange change) => route switch
    {
        0 => IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege(Selection(), Slug, change),
        1 => IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(Selection(), change),
        _ => IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege(Selection(), change, Lifetime(2))
    };
    private static ManagementRequest<IdentityPrivilegeSummary> Request(int route) => route switch
    {
        < 3 => LegacyRequest(route, LegacyChange(route)),
        3 => IdentityPrivilegeChangeOperations.CreateProjectPrivilege(Selection(), ModernChange()),
        4 => IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(Selection(), Id, ModernChange()),
        _ => IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug(Selection(), Slug)
    };
    private static ManagementTarget Target(int route, LegacyPrivilegeSelection selection, string? defect = null) => route switch
    {
        < 3 => IdentityPrivilegeChangeOperations.LegacyChangeTarget(selection, LegacyChange(route, defect),
            route == 0 ? Slug : null, route == 0 ? null : Lifetime(route, defect)),
        3 => IdentityPrivilegeChangeOperations.ProjectChangeTarget(selection, ModernChange(defect)),
        4 => IdentityPrivilegeChangeOperations.ProjectChangeTarget(selection, ModernChange(defect), defect == "id" ? "other" : Id),
        _ => selection.GrantTarget(defect == "slug" ? "other" : Slug)
    };
    private static string Operation(int route) => route switch
    {
        0 => "infisical.patch.v1.additional.privilege.identity",
        1 => "infisical.post.v1.additional.privilege.identity.permanent",
        2 => "infisical.post.v1.additional.privilege.identity.temporary",
        3 => "infisical.post.v2.identity.project.additional.privilege",
        4 => "infisical.patch.v2.identity.project.additional.privilege.by.id",
        _ => "infisical.get.v2.identity.project.additional.privilege.slug.by.privilegeSlug"
    };
    private static ManagementAuthority Authority(ManagementClient client, Tokens? tokens = null) =>
        new(client.Authority, tokens ?? new(), Org, Project);
    private static ManagementGrant Grant(ManagementAuthority authority, int route) =>
        authority.IssueGrant(Operation(route), Target(route, Selection()));
    private static ManagementTransport Transport(Wire wire) => new(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
    private sealed class Tokens : IInfisicalTokenSource
    {
        private int _entered;
        public bool Acquired { get; private set; }
        public bool Hold { get; init; }
        public bool Rendezvous { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            if (Hold || Rendezvous)
            {
                if (Interlocked.Increment(ref _entered) == (Rendezvous ? 2 : 1)) Entered.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token")));
        }
    }
    private sealed class Wire(int route) : HttpMessageHandler
    {
        public JsonObject State { get; } = new()
        {
            ["id"] = Id,
            ["slug"] = Slug,
            ["createdAt"] = "2026-10-01T00:00:00Z",
            ["updatedAt"] = "2026-10-01T00:00:00Z",
            ["isTemporary"] = false,
            ["temporaryMode"] = null,
            ["temporaryRange"] = null,
            ["temporaryAccessStartTime"] = null,
            ["temporaryAccessEndTime"] = null,
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
            string path = route switch
            {
                0 => "/api/v1/additional-privilege/identity",
                1 => "/api/v1/additional-privilege/identity/permanent",
                2 => "/api/v1/additional-privilege/identity/temporary",
                3 => "/api/v2/identity-project-additional-privilege",
                4 => "/api/v2/identity-project-additional-privilege/" + Id,
                _ => "/api/v2/identity-project-additional-privilege/slug/" + Slug +
                    "?identityId=" + Identity + "&projectSlug=" + ProjectSlug
            };
            string method = route is 0 or 4 ? "PATCH" : route == 5 ? "GET" : "POST";
            if (request.RequestUri!.PathAndQuery != path || request.Method.Method != method ||
                request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.NotFound);
            if (route != 5)
            {
                LastBody = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
                if (route < 3 && (LastBody["identityId"]?.GetValue<string>() != Identity ||
                    LastBody["projectSlug"]?.GetValue<string>() != ProjectSlug) ||
                    route == 3 && (LastBody["identityId"]?.GetValue<string>() != Identity ||
                    LastBody["projectId"]?.GetValue<string>() != Project) ||
                    route == 0 && LastBody["privilegeSlug"]?.GetValue<string>() != Slug)
                    return new(HttpStatusCode.BadRequest);
                Entered.TrySetResult();
                if (HoldBeforeCommit) await Release.Task.WaitAsync(cancellationToken);
                JsonObject details = (route == 0 ? LastBody["privilegeDetails"]! : LastBody).AsObject();
                foreach (var field in details)
                {
                    if (field.Key == "type")
                    {
                        foreach (var lifetime in field.Value!.AsObject()) State[lifetime.Key] = lifetime.Value?.DeepClone();
                    }
                    else if (field.Key == "privilegePermission")
                    {
                        var alternate = field.Value!.AsObject();
                        State["permissions"] = new JsonArray(new JsonObject
                        {
                            ["subject"] = "secrets",
                            ["action"] = alternate["actions"]!.DeepClone(),
                            ["conditions"] = alternate["conditions"]!.DeepClone()
                        });
                    }
                    else if (field.Key is not ("identityId" or "projectSlug" or "projectId")) State[field.Key] = field.Value?.DeepClone();
                }
                if (route is 1 or 2) State["isTemporary"] = route == 2;
                Revision++;
                Committed.TrySetResult();
                if (HoldAfterCommit) await Release.Task.WaitAsync(cancellationToken);
                if (LoseResponse) throw new IOException("Committed response lost.");
            }
            JsonObject privilege = State.DeepClone().AsObject();
            if (route < 3) privilege["projectMembershipId"] = Membership;
            if (Corrupt is not null) privilege[Corrupt] = Corrupt is "id" or "projectMembershipId" ? ForeignUuid : "other";
            if (Missing is not null) privilege.Remove(Missing);
            JsonObject response = Missing == "privilege" ? new() : new() { ["privilege"] = privilege };
            return new(HttpStatusCode.OK) { Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }
}
