using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class PermissionAuditWitnessTests
{
    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string Project = "10000000-0000-4000-8000-000000000002";
    private const string Id = "10000000-0000-4000-8000-000000000003";
    private const string Identity = "10000000-0000-4000-8000-000000000004";
    private const string Membership = "10000000-0000-4000-8000-000000000005";
    private const string Slug = "reader-private";
    private const string ProjectSlug = "project-private";
    private static readonly DateTimeOffset Start = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);

    // I09 routes: organization POST/PATCH, project POST/PATCH.
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task RoleAdaptersDenyEachIndependentFieldAndShape(int route)
    {
        string[] choices =
        [
            "slug", "subject", "action-value", "action-shape", "action-order", "action-length",
            "conditions-presence", "clause-empty", "clause-presence", "in-presence", "literal-eq", "eq-ne",
            "eq-value", "ne-value", "in-value", "in-order", "in-length"
        ];
        foreach (string choice in choices.Concat(route < 2 ? [] :
            new[] { "glob-value", "glob-eq", "tags-empty", "tags-in-presence", "tags-all-presence", "metadata-empty", "metadata-key-empty" }))
        {
            using var selected = RoleRequest(route, choice, false);
            using var approved = RoleRequest(route, choice, true);
            var wire = new Wire(RolePath(route), route % 2 == 0 ? "POST" : "PATCH", "{}");
            using var transport = Transport(wire);
            var client = new ManagementClient(transport);
            var tokens = new Tokens();
            var authority = new ManagementAuthority(client.Authority, tokens, Org, route < 2 ? null : Project);
            var receipt = client.CreateReceipt(selected);
            // Approval is constructed from separate host choices, not either request.Target.
            var denied = await client.ExecuteAsync(selected, authority,
                authority.IssueGrant(RoleOperation(route), RoleTarget(route, choice, true)), receipt);
            await Assert.That(denied.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(tokens.Acquired).IsFalse();
            await Assert.That(wire.Body).IsNull();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);

            // Both competing choices must actually serialize and parse at their own native adapter.
            foreach (bool alternative in new[] { false, true })
            {
                using var request = RoleRequest(route, choice, alternative);
                var fixture = RoleFixture(route < 2);
                fixture["slug"] = choice == "slug" && alternative ? "other-private" : Slug;
                wire.Response = new JsonObject { ["role"] = fixture }.ToJsonString();
                var ownReceipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(RoleOperation(route), RoleTarget(route, choice, alternative)), ownReceipt);
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                await Assert.That(ownReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                await Assert.That(request.OperationId).IsEqualTo(RoleOperation(route));
                await VerifyRoleBody(wire.Body!, route, choice, alternative);
                await Private(result.Value, request, RoleTarget(route, choice, alternative));
            }
        }
    }

    private static RoleStringClause Clause(string choice, bool alternative) => choice switch
    {
        "clause-presence" => alternative ? RoleStringClause.Compare() : RoleStringClause.Literal("value-private"),
        "in-presence" => alternative ? RoleStringClause.Compare(included: []) : RoleStringClause.Compare(),
        "literal-eq" => alternative ? RoleStringClause.Compare(equal: "value-private") : RoleStringClause.Literal("value-private"),
        "eq-ne" => alternative ? RoleStringClause.Compare(notEqual: "value-private") : RoleStringClause.Compare(equal: "value-private"),
        "eq-value" => RoleStringClause.Compare(equal: alternative ? "other-private" : "value-private"),
        "ne-value" => RoleStringClause.Compare(notEqual: alternative ? "other-private" : "value-private"),
        "in-value" => RoleStringClause.Compare(included: [alternative ? "other-private" : "value-private"]),
        "in-order" => RoleStringClause.Compare(included: alternative ? ["other-private", "value-private"] : ["value-private", "other-private"]),
        "in-length" => RoleStringClause.Compare(included: alternative ? ["value-private", "other-private"] : ["value-private"]),
        "glob-value" => RoleStringClause.Compare(glob: alternative ? "other-private*" : "value-private*"),
        "glob-eq" => alternative ? RoleStringClause.Compare(equal: "value-private*") : RoleStringClause.Compare(glob: "value-private*"),
        _ => RoleStringClause.Literal("value-private")
    };

    private static RoleCondition[]? Conditions(int route, string choice, bool alternative) =>
        choice == "conditions-presence" ? alternative ? [] : null :
        choice == "clause-empty" ? alternative ?
            [new(route < 2 ? RoleConditionField.ConnectionId : RoleConditionField.Environment, RoleStringClause.Compare())] : [] :
        choice is "clause-presence" or "in-presence" or "literal-eq" or "eq-ne" or "eq-value" or "ne-value" or
            "in-value" or "in-order" or "in-length" or "glob-value" or "glob-eq"
            ? [new(route < 2 ? RoleConditionField.ConnectionId : RoleConditionField.Environment, Clause(choice, alternative))]
            : null;

    private static OrganizationRoleChange OrganizationChange(string choice, bool alternative)
    {
        var subject = choice == "subject" && alternative ? OrganizationRoleSubject.Role : OrganizationRoleSubject.AppConnections;
        var conditions = Conditions(0, choice, alternative);
        OrganizationRolePermission permission = choice switch
        {
            "action-shape" when alternative => new(subject, new[] { OrganizationRoleAction.Read }),
            "action-order" => new(subject, alternative ? new[] { OrganizationRoleAction.Edit, OrganizationRoleAction.Read } :
                new[] { OrganizationRoleAction.Read, OrganizationRoleAction.Edit }),
            "action-length" => new(subject, alternative ? new[] { OrganizationRoleAction.Read, OrganizationRoleAction.Edit } :
                new[] { OrganizationRoleAction.Read }),
            _ => new(subject, choice == "action-value" && alternative ? OrganizationRoleAction.Edit : OrganizationRoleAction.Read,
                conditions: conditions)
        };
        return new("Reviewed", choice == "slug" && alternative ? "other-private" : Slug, permissions: [permission]);
    }

    private static ProjectRoleChange ProjectChange(string choice, bool alternative)
        => new("Reviewed", choice == "slug" && alternative ? "other-private" : Slug,
            permissions: [ProjectPermission(choice, alternative)]);

    private static ProjectRolePermission ProjectPermission(string choice, bool alternative)
    {
        if (choice.StartsWith("tags-", StringComparison.Ordinal)) return ModernPermission(choice, alternative);
        if (choice is "metadata-empty" or "metadata-key-empty")
            return new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Lease,
                metadata: choice == "metadata-empty" && !alternative ? null :
                    choice == "metadata-key-empty" && alternative ? new(key: RoleStringClause.Compare()) : new());
        var subject = choice == "subject" && alternative ? ProjectRoleSubject.SecretFolders : ProjectRoleSubject.Secrets;
        var conditions = Conditions(2, choice, alternative);
        ProjectRolePermission permission = choice switch
        {
            "action-shape" when alternative => new(subject, new[] { ProjectRoleAction.Read }),
            "action-order" => new(subject, alternative ? new[] { ProjectRoleAction.Edit, ProjectRoleAction.Read } :
                new[] { ProjectRoleAction.Read, ProjectRoleAction.Edit }),
            "action-length" => new(subject, alternative ? new[] { ProjectRoleAction.Read, ProjectRoleAction.Edit } :
                new[] { ProjectRoleAction.Read }),
            _ => new(subject, choice == "action-value" && alternative ? ProjectRoleAction.Edit : ProjectRoleAction.Read,
                conditions: conditions)
        };
        return permission;
    }

    // I11 routes: legacy PATCH/permanent POST/temporary POST, v2 POST/PATCH.
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task PrivilegeAdaptersDenyEachIndependentLeafAndShape(int route)
    {
        string[] legacy =
        [
            "slug", "slug-presence", "subject", "environment-value", "environment-presence", "environment-empty",
            "path-value", "path-presence", "conditions-presence", "conditions-empty", "permissions-presence",
            "permissions-empty", "dialect", "alternate-action-value", "alternate-action-order", "alternate-action-length",
            "alternate-environment-value", "alternate-environment-empty", "alternate-path-value", "alternate-path-presence"
        ];
        string[] modern =
        [
            "slug", "subject", "action-shape", "action-order", "action-length",
            "conditions-presence", "clause-empty", "clause-presence", "in-presence", "literal-eq", "eq-ne",
            "eq-value", "ne-value", "in-value", "in-order", "in-length", "glob-value", "glob-eq",
            "path-value", "path-operator", "path-presence", "inversion-presence", "inversion-value",
            "tags-presence", "tags-empty", "tags-in-presence", "tags-all-presence", "tags-operator",
            "tags-in-value", "tags-all-value", "tags-in-order", "tags-all-order", "tags-in-length", "tags-all-length"
        ];
        var choices = (route < 3 ? legacy : modern).AsEnumerable();
        if (route != 1) choices = choices.Append("start-value");
        if (route == 3) choices = choices.Append("slug-presence");
        if (route == 0) choices = choices.Concat(["start-presence", "range-presence", "mode-presence", "temporary-presence"]);
        foreach (string choice in choices)
        {
            using var request = PrivilegeRequest(route, choice, false);
            var wire = new Wire(PrivilegePath(route), route is 0 or 4 ? "PATCH" : "POST", "{}");
            using var transport = Transport(wire);
            var client = new ManagementClient(transport);
            var tokens = new Tokens();
            var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
            var receipt = client.CreateReceipt(request);
            var denied = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(PrivilegeOperation(route), PrivilegeTarget(route, choice, true)), receipt);
            await Assert.That(denied.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(tokens.Acquired).IsFalse();
            await Assert.That(wire.Dispatched).IsFalse();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
            foreach (bool alternative in new[] { false, true })
            {
                using var own = PrivilegeRequest(route, choice, alternative);
                var fixture = PrivilegeFixture(route < 3);
                fixture["slug"] = choice == "slug" && alternative ? "other-private" : Slug;
                wire.Response = new JsonObject { ["privilege"] = fixture }.ToJsonString();
                var ownReceipt = client.CreateReceipt(own);
                var result = await client.ExecuteAsync(own, authority,
                    authority.IssueGrant(PrivilegeOperation(route), PrivilegeTarget(route, choice, alternative)), ownReceipt);
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                await Assert.That(own.OperationId).IsEqualTo(PrivilegeOperation(route));
                await Assert.That(ownReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                await VerifyPrivilegeBody(wire.Body!, route, choice, alternative);
                await Private(result.Value, own, PrivilegeTarget(route, choice, alternative));
            }
        }
    }

    private static LegacyPrivilegeSelection Selection() => new(Org, Project, ProjectSlug, Identity, Membership);

    private static LegacyPrivilegeChange LegacyChange(int route, string choice, bool alternative)
    {
        bool alternate = choice.StartsWith("alternate-", StringComparison.Ordinal) || choice == "dialect" && alternative;
        string? environment = choice is "environment-value" or "alternate-environment-value" && alternative ? "other-private" :
            choice is "environment-empty" or "alternate-environment-empty" && alternative ? "" :
            choice == "environment-presence" && alternative ? null : "value-private";
        string? path = choice is "path-value" or "alternate-path-value" && alternative ? "/other-private/**" :
            choice is "path-presence" or "alternate-path-presence" && alternative ? null : "/value-private/**";
        var conditions = choice == "conditions-presence" && alternative ? null :
            choice == "conditions-empty" && alternative ? new LegacyPrivilegeConditions() : new(environment, path);
        LegacyPrivilegePermission[]? permissions = alternate || choice == "permissions-presence" && alternative ? null :
            choice == "permissions-empty" && alternative ? [] :
            [new(choice == "subject" && alternative ? ProjectRoleSubject.Role : ProjectRoleSubject.Secrets,
                LegacyPrivilegeAction.Read, conditions)];
        LegacySecretPrivilegePermission? permission = !alternate ? null : new(choice switch
        {
            "alternate-action-value" => alternative ? [LegacyPrivilegeAction.Edit] : [LegacyPrivilegeAction.Read],
            "alternate-action-order" => alternative ? [LegacyPrivilegeAction.Edit, LegacyPrivilegeAction.Read] :
                [LegacyPrivilegeAction.Read, LegacyPrivilegeAction.Edit],
            "alternate-action-length" => alternative ? [LegacyPrivilegeAction.Read, LegacyPrivilegeAction.Edit] : [LegacyPrivilegeAction.Read],
            _ => [LegacyPrivilegeAction.Read]
        }, new(environment, path));
        return new(choice == "slug-presence" && alternative ? null : choice == "slug" && alternative ? "other-private" : Slug,
            permissions, permission,
            isTemporary: route == 0 && choice == "temporary-presence" && alternative ? false : null,
            temporaryMode: route == 0 && choice == "mode-presence" && alternative ? PrivilegeTemporaryMode.Relative : null,
            temporaryRange: route == 0 && choice == "range-presence" && alternative ? "1h" : null,
            temporaryAccessStartTime: route == 0 && choice is "start-value" or "start-presence"
                ? choice == "start-presence" && !alternative ? null : alternative && choice == "start-value" ? Start.AddHours(1) : Start : null);
    }

    private static PrivilegeLifetime Lifetime(string choice, bool alternative) =>
        PrivilegeLifetime.Temporary("1h", choice == "start-value" && alternative ? Start.AddHours(1) : Start);

    private static ProjectRolePermission ModernPermission(string choice, bool alternative)
    {
        if (choice.StartsWith("tags-", StringComparison.Ordinal))
        {
            RoleSecretTags? tags = choice == "tags-presence" && !alternative ? null :
                choice == "tags-empty" && !alternative ? new() :
                choice switch
                {
                    "tags-in-presence" => new(included: alternative ? [] : null),
                    "tags-all-presence" => new(all: alternative ? [] : null),
                    "tags-operator" => alternative ? new(all: ["value-private"]) : new(included: ["value-private"]),
                    "tags-in-value" => new(included: [alternative ? "other-private" : "value-private"]),
                    "tags-all-value" => new(all: [alternative ? "other-private" : "value-private"]),
                    "tags-in-order" => new(included: alternative ? ["other-private", "value-private"] : ["value-private", "other-private"]),
                    "tags-all-order" => new(all: alternative ? ["other-private", "value-private"] : ["value-private", "other-private"]),
                    "tags-in-length" => new(included: alternative ? ["value-private", "other-private"] : ["value-private"]),
                    "tags-all-length" => new(all: alternative ? ["value-private", "other-private"] : ["value-private"]),
                    _ => new(all: ["value-private"])
                };
            return new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
                conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("value-private"))], secretTags: tags);
        }
        if (choice is "inversion-presence" or "inversion-value")
            return new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
                inverted: choice == "inversion-presence" ? alternative ? false : null : alternative);
        if (choice is "path-value" or "path-operator" or "path-presence")
            return new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read, conditions:
                choice == "path-presence" && alternative ? [] :
                [new(RoleConditionField.SecretPath, choice == "path-operator" && alternative
                    ? RoleStringClause.Compare(equal: "/value-private/**") :
                    RoleStringClause.Compare(glob: choice == "path-value" && alternative ? "/other-private/**" : "/value-private/**"))]);
        return ProjectPermission(choice, alternative);
    }

    private static ProjectPrivilegeChange ModernChange(string choice, bool alternative) =>
        new([ModernPermission(choice, alternative)], Lifetime(choice, alternative),
            choice == "slug-presence" && alternative ? null : choice == "slug" && alternative ? "other-private" : Slug);

    private static ManagementRequest<IdentityPrivilegeSummary> PrivilegeRequest(int route, string choice, bool alternative) => route switch
    {
        0 => IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege(Selection(), Slug, LegacyChange(route, choice, alternative)),
        1 => IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(Selection(), LegacyChange(route, choice, alternative)),
        2 => IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege(Selection(), LegacyChange(route, choice, alternative), Lifetime(choice, alternative)),
        3 => IdentityPrivilegeChangeOperations.CreateProjectPrivilege(Selection(), ModernChange(choice, alternative)),
        4 => IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(Selection(), Id, ModernChange(choice, alternative)),
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static ManagementTarget PrivilegeTarget(int route, string choice, bool alternative) => route switch
    {
        < 3 => IdentityPrivilegeChangeOperations.LegacyChangeTarget(Selection(), LegacyChange(route, choice, alternative),
            route == 0 ? Slug : null, route == 0 ? null : route == 1 ? PrivilegeLifetime.Permanent() : Lifetime(choice, alternative)),
        3 => IdentityPrivilegeChangeOperations.ProjectChangeTarget(Selection(), ModernChange(choice, alternative)),
        4 => IdentityPrivilegeChangeOperations.ProjectChangeTarget(Selection(), ModernChange(choice, alternative), Id),
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static string PrivilegeOperation(int route) => route switch
    {
        0 => "infisical.patch.v1.additional.privilege.identity",
        1 => "infisical.post.v1.additional.privilege.identity.permanent",
        2 => "infisical.post.v1.additional.privilege.identity.temporary",
        3 => "infisical.post.v2.identity.project.additional.privilege",
        4 => "infisical.patch.v2.identity.project.additional.privilege.by.id",
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static string PrivilegePath(int route) => route switch
    {
        0 => "/api/v1/additional-privilege/identity",
        1 => "/api/v1/additional-privilege/identity/permanent",
        2 => "/api/v1/additional-privilege/identity/temporary",
        3 => "/api/v2/identity-project-additional-privilege",
        4 => "/api/v2/identity-project-additional-privilege/" + Id,
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static async Task VerifyPrivilegeBody(JsonObject body, int route, string choice, bool alternative)
    {
        if (route < 3 || route == 3)
        {
            await Assert.That(body["identityId"]!.GetValue<string>()).IsEqualTo(Identity);
            await Assert.That(body[route < 3 ? "projectSlug" : "projectId"]!.GetValue<string>()).IsEqualTo(route < 3 ? ProjectSlug : Project);
        }
        var details = route == 0 ? body["privilegeDetails"]!.AsObject() : body;
        await Assert.That(details.ContainsKey("slug")).IsEqualTo(!(choice == "slug-presence" && alternative));
        if (details.ContainsKey("slug"))
            await Assert.That(details["slug"]!.GetValue<string>()).IsEqualTo(choice == "slug" && alternative ? "other-private" : Slug);
        if (route >= 3)
        {
            if (choice.StartsWith("tags-", StringComparison.Ordinal))
            {
                var permission = details["permissions"]![0]!.AsObject();
                var conditions = permission["conditions"]!.AsObject();
                await Assert.That(conditions["environment"]!.GetValue<string>()).IsEqualTo("value-private");
                await Assert.That(conditions.ContainsKey("secretTags")).IsEqualTo(choice != "tags-presence" || alternative);
                if (choice == "tags-presence" && !alternative) return;
                string expected = choice switch
                {
                    "tags-empty" => alternative ? """{"$all":["value-private"]}""" : "{}",
                    "tags-in-presence" => alternative ? """{"$in":[]}""" : "{}",
                    "tags-all-presence" => alternative ? """{"$all":[]}""" : "{}",
                    "tags-operator" => alternative ? """{"$all":["value-private"]}""" : """{"$in":["value-private"]}""",
                    "tags-in-value" => alternative ? """{"$in":["other-private"]}""" : """{"$in":["value-private"]}""",
                    "tags-all-value" => alternative ? """{"$all":["other-private"]}""" : """{"$all":["value-private"]}""",
                    "tags-in-order" => alternative ? """{"$in":["other-private","value-private"]}""" : """{"$in":["value-private","other-private"]}""",
                    "tags-all-order" => alternative ? """{"$all":["other-private","value-private"]}""" : """{"$all":["value-private","other-private"]}""",
                    "tags-in-length" => alternative ? """{"$in":["value-private","other-private"]}""" : """{"$in":["value-private"]}""",
                    "tags-all-length" => alternative ? """{"$all":["value-private","other-private"]}""" : """{"$all":["value-private"]}""",
                    _ => """{"$all":["value-private"]}"""
                };
                await Assert.That(permission["conditions"]!["secretTags"]!.ToJsonString()).IsEqualTo(expected);
            }
            else if (choice is "inversion-presence" or "inversion-value")
            {
                var permission = details["permissions"]![0]!.AsObject();
                await Assert.That(permission.ContainsKey("inverted")).IsEqualTo(choice != "inversion-presence" || alternative);
                if (permission.ContainsKey("inverted"))
                    await Assert.That(permission["inverted"]!.GetValue<bool>()).IsEqualTo(choice != "inversion-presence" && alternative);
            }
            else if (choice is "path-value" or "path-operator" or "path-presence")
            {
                var conditions = details["permissions"]![0]!["conditions"]!.AsObject();
                await Assert.That(conditions.ContainsKey("secretPath")).IsEqualTo(choice != "path-presence" || !alternative);
                if (conditions.ContainsKey("secretPath"))
                    await Assert.That(conditions["secretPath"]!.ToJsonString()).IsEqualTo(choice == "path-operator" && alternative
                        ? """{"$eq":"/value-private/**"}""" : choice == "path-value" && alternative
                            ? """{"$glob":"/other-private/**"}""" : """{"$glob":"/value-private/**"}""");
            }
            else if (choice != "start-value")
                await VerifyRoleBody(details, 2, choice == "slug-presence" ? "baseline" : choice, alternative,
                    verifySlug: choice != "slug-presence");
            var lifetime = details["type"]!.AsObject();
            await Assert.That(lifetime["temporaryRange"]!.GetValue<string>()).IsEqualTo("1h");
            await Assert.That(DateTimeOffset.Parse(lifetime["temporaryAccessStartTime"]!.GetValue<string>()))
                .IsEqualTo(choice == "start-value" && alternative ? Start.AddHours(1) : Start);
            return;
        }
        bool alternate = choice.StartsWith("alternate-", StringComparison.Ordinal) || choice == "dialect" && alternative;
        await Assert.That(details.ContainsKey("privilegePermission")).IsEqualTo(alternate);
        await Assert.That(details.ContainsKey("permissions")).IsEqualTo(!alternate && !(choice == "permissions-presence" && alternative));
        if (choice == "permissions-empty" && alternative)
            await Assert.That(details["permissions"]!.AsArray().Count).IsEqualTo(0);
        else if (alternate || details.ContainsKey("permissions"))
        {
            var permission = alternate ? details["privilegePermission"]!.AsObject() : details["permissions"]![0]!.AsObject();
            await Assert.That(permission["subject"]!.GetValue<string>()).IsEqualTo(choice == "subject" && alternative ? "role" : "secrets");
            if (alternate)
                await Assert.That(permission["actions"]!.ToJsonString()).IsEqualTo(choice switch
                {
                    "alternate-action-value" => alternative ? """["edit"]""" : """["read"]""",
                    "alternate-action-order" => alternative ? """["edit","read"]""" : """["read","edit"]""",
                    "alternate-action-length" => alternative ? """["read","edit"]""" : """["read"]""",
                    _ => """["read"]"""
                });
            else await Assert.That(permission["action"]!.GetValue<string>()).IsEqualTo("read");
            await Assert.That(permission.ContainsKey("conditions")).IsEqualTo(choice != "conditions-presence" || !alternative);
            if (permission.ContainsKey("conditions"))
            {
                var conditions = permission["conditions"]!.AsObject();
                bool empty = choice == "conditions-empty" && alternative;
                await Assert.That(conditions.ContainsKey("environment")).IsEqualTo(!empty && !(choice == "environment-presence" && alternative));
                if (conditions.ContainsKey("environment"))
                    await Assert.That(conditions["environment"]!.GetValue<string>()).IsEqualTo(
                        choice is "environment-value" or "alternate-environment-value" && alternative ? "other-private" :
                        choice is "environment-empty" or "alternate-environment-empty" && alternative ? "" : "value-private");
                await Assert.That(conditions.ContainsKey("secretPath")).IsEqualTo(!empty &&
                    !(choice is "path-presence" or "alternate-path-presence" && alternative));
                if (conditions.ContainsKey("secretPath"))
                    await Assert.That(conditions["secretPath"]!["$glob"]!.GetValue<string>()).IsEqualTo(
                        choice is "path-value" or "alternate-path-value" && alternative ? "/other-private/**" : "/value-private/**");
            }
        }
        if (choice == "start-value")
        {
            await Assert.That(DateTimeOffset.Parse(details["temporaryAccessStartTime"]!.GetValue<string>()))
                .IsEqualTo(alternative ? Start.AddHours(1) : Start);
            await Assert.That(details.ContainsKey("temporaryRange")).IsEqualTo(route == 2);
            if (route == 2) await Assert.That(details["temporaryRange"]!.GetValue<string>()).IsEqualTo("1h");
        }
        if (choice is "start-presence" or "range-presence" or "mode-presence" or "temporary-presence")
        {
            string field = choice switch
            {
                "start-presence" => "temporaryAccessStartTime",
                "range-presence" => "temporaryRange",
                "mode-presence" => "temporaryMode",
                _ => "isTemporary"
            };
            await Assert.That(details.ContainsKey(field)).IsEqualTo(alternative);
            if (alternative && choice == "start-presence")
                await Assert.That(DateTimeOffset.Parse(details[field]!.GetValue<string>())).IsEqualTo(Start);
            else if (alternative)
                await Assert.That(details[field]!.ToJsonString()).IsEqualTo(choice switch
                {
                    "range-presence" => "\"1h\"",
                    "mode-presence" => "\"relative\"",
                    _ => "false"
                });
        }
    }

    private static JsonObject PrivilegeFixture(bool legacy)
    {
        var fixture = new JsonObject
        {
            ["id"] = Id,
            ["slug"] = Slug,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-02T00:00:00Z",
            ["permissions"] = new JsonArray()
        };
        if (legacy) fixture["projectMembershipId"] = Membership;
        return fixture;
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task RoleAdaptersOwnInputCollectionsBeforeNativeDispatch(int route)
    {
        string[] included = ["value-private", "other-private"];
        RoleCondition[] orgConditions = [new(RoleConditionField.ConnectionId, RoleStringClause.Compare(included: included))];
        RoleCondition[] projectConditions = [new(RoleConditionField.Environment, RoleStringClause.Compare(included: included))];
        OrganizationRoleAction[] orgActions = [OrganizationRoleAction.Read, OrganizationRoleAction.Edit];
        ProjectRoleAction[] projectActions = [ProjectRoleAction.Read, ProjectRoleAction.Edit];
        OrganizationRolePermission[] orgPermissions = [new(OrganizationRoleSubject.AppConnections, orgActions, conditions: orgConditions)];
        ProjectRolePermission[] projectPermissions = [new(ProjectRoleSubject.Secrets, projectActions, conditions: projectConditions)];
        var orgChange = new OrganizationRoleChange("Reviewed", Slug, permissions: orgPermissions);
        var projectChange = new ProjectRoleChange("Reviewed", Slug, permissions: projectPermissions);
        using var request = route switch
        {
            0 => RoleChangeOperations.CreateOrganizationRole(Org, orgChange),
            1 => RoleChangeOperations.UpdateOrganizationRole(Org, Id, orgChange),
            2 => RoleChangeOperations.CreateProjectRole(Org, Project, projectChange),
            _ => RoleChangeOperations.UpdateProjectRole(Org, Project, Id, projectChange)
        };
        var approvedOrg = new OrganizationRoleChange("Reviewed", Slug, permissions:
            [new(OrganizationRoleSubject.AppConnections, new[] { OrganizationRoleAction.Read, OrganizationRoleAction.Edit },
                conditions: [new(RoleConditionField.ConnectionId, RoleStringClause.Compare(included: ["value-private", "other-private"]))])]);
        var approvedProject = new ProjectRoleChange("Reviewed", Slug, permissions:
            [new(ProjectRoleSubject.Secrets, new[] { ProjectRoleAction.Read, ProjectRoleAction.Edit },
                conditions: [new(RoleConditionField.Environment, RoleStringClause.Compare(included: ["value-private", "other-private"]))])]);
        var target = route switch
        {
            0 => RoleChangeOperations.OrganizationCreationTarget(Org, approvedOrg),
            1 => RoleChangeOperations.OrganizationUpdateTarget(Org, Id, approvedOrg),
            2 => RoleChangeOperations.ProjectCreationTarget(Org, Project, approvedProject),
            _ => RoleChangeOperations.ProjectUpdateTarget(Org, Project, Id, approvedProject)
        };
        included[0] = "broadened-private";
        orgConditions[0] = new(RoleConditionField.ConnectionId, RoleStringClause.Compare());
        projectConditions[0] = new(RoleConditionField.Environment, RoleStringClause.Compare());
        orgActions[0] = OrganizationRoleAction.Delete;
        projectActions[0] = ProjectRoleAction.Delete;
        orgPermissions[0] = new(OrganizationRoleSubject.Role, OrganizationRoleAction.Delete);
        projectPermissions[0] = new(ProjectRoleSubject.Role, ProjectRoleAction.Delete);
        var wire = new Wire(RolePath(route), route % 2 == 0 ? "POST" : "PATCH",
            new JsonObject { ["role"] = RoleFixture(route < 2) }.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, route < 2 ? null : Project);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(RoleOperation(route), target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        var permission = wire.Body!["permissions"]![0]!;
        await Assert.That(permission["action"]!.ToJsonString()).IsEqualTo("""["read","edit"]""");
        await Assert.That(permission["conditions"]![route < 2 ? "connectionId" : "environment"]!["$in"]!.ToJsonString())
            .IsEqualTo("""["value-private","other-private"]""");
        await Private(orgChange, projectChange, request, target);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task PrivilegeAdaptersOwnInputCollectionsBeforeNativeDispatch(int route)
    {
        LegacyPrivilegePermission[] legacy = [new(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read,
            new("value-private", "/value-private/**"))];
        LegacyPrivilegeAction[] legacyActions = [LegacyPrivilegeAction.Read, LegacyPrivilegeAction.Edit];
        ProjectRoleAction[] actions = [ProjectRoleAction.Read, ProjectRoleAction.Edit];
        string[] included = ["value-private"];
        string[] tags = ["tag-private"];
        RoleCondition[] conditions = [new(RoleConditionField.Environment, RoleStringClause.Compare(included: included))];
        ProjectRolePermission[] modern = [new(ProjectRoleSubject.Secrets, actions, conditions: conditions, secretTags: new(all: tags))];
        foreach (bool alternate in route < 3 ? new[] { false, true } : new[] { false })
        {
            var legacyChange = new LegacyPrivilegeChange(Slug, alternate ? null : legacy,
                alternate ? new(legacyActions, new("value-private", "/value-private/**")) : null);
            var modernChange = new ProjectPrivilegeChange(modern, Lifetime("baseline", false), Slug);
            using var request = route switch
            {
                0 => IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege(Selection(), Slug, legacyChange),
                1 => IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(Selection(), legacyChange),
                2 => IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege(Selection(), legacyChange, Lifetime("baseline", false)),
                3 => IdentityPrivilegeChangeOperations.CreateProjectPrivilege(Selection(), modernChange),
                _ => IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(Selection(), Id, modernChange)
            };
            var approvedLegacy = new LegacyPrivilegeChange(Slug, alternate ? null :
                [new(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read, new("value-private", "/value-private/**"))],
                alternate ? new([LegacyPrivilegeAction.Read, LegacyPrivilegeAction.Edit], new("value-private", "/value-private/**")) : null);
            var approvedModern = new ProjectPrivilegeChange(
                [new(ProjectRoleSubject.Secrets, new[] { ProjectRoleAction.Read, ProjectRoleAction.Edit },
                    conditions: [new(RoleConditionField.Environment, RoleStringClause.Compare(included: ["value-private"]))],
                    secretTags: new(all: ["tag-private"]))], Lifetime("baseline", false), Slug);
            var target = route < 3 ? IdentityPrivilegeChangeOperations.LegacyChangeTarget(Selection(), approvedLegacy,
                route == 0 ? Slug : null, route == 0 ? null : route == 1 ? PrivilegeLifetime.Permanent() : Lifetime("baseline", false)) :
                IdentityPrivilegeChangeOperations.ProjectChangeTarget(Selection(), approvedModern, route == 4 ? Id : null);
            legacy[0] = new(ProjectRoleSubject.Role, LegacyPrivilegeAction.Delete);
            legacyActions[0] = LegacyPrivilegeAction.Delete;
            actions[0] = ProjectRoleAction.Delete;
            included[0] = "broadened-private";
            tags[0] = "broadened-private";
            conditions[0] = new(RoleConditionField.Environment, RoleStringClause.Compare());
            modern[0] = new(ProjectRoleSubject.Role, ProjectRoleAction.Delete);
            var wire = new Wire(PrivilegePath(route), route is 0 or 4 ? "PATCH" : "POST",
                new JsonObject { ["privilege"] = PrivilegeFixture(route < 3) }.ToJsonString());
            using var transport = Transport(wire);
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(PrivilegeOperation(route), target), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            var details = route == 0 ? wire.Body!["privilegeDetails"]!.AsObject() : wire.Body!;
            if (route < 3)
            {
                if (alternate)
                    await Assert.That(details["privilegePermission"]!["actions"]!.ToJsonString()).IsEqualTo("""["read","edit"]""");
                else
                    await Assert.That(details["permissions"]![0]!["action"]!.GetValue<string>()).IsEqualTo("read");
            }
            else
            {
                var permission = details["permissions"]![0]!;
                await Assert.That(permission["action"]!.ToJsonString()).IsEqualTo("""["read","edit"]""");
                await Assert.That(permission["conditions"]!["environment"]!["$in"]!.ToJsonString()).IsEqualTo("""["value-private"]""");
                await Assert.That(permission["conditions"]!["secretTags"]!["$all"]!.ToJsonString()).IsEqualTo("""["tag-private"]""");
            }
            await Private(legacyChange, modernChange, request, target);
            // The second dialect receives fresh caller arrays, not arrays already mutated by this iteration.
            legacy = [new(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read, new("value-private", "/value-private/**"))];
            legacyActions = [LegacyPrivilegeAction.Read, LegacyPrivilegeAction.Edit];
        }
    }

    private static ManagementRequest<RoleSummary> RoleRequest(int route, string choice, bool alternative) => route switch
    {
        0 => RoleChangeOperations.CreateOrganizationRole(Org, OrganizationChange(choice, alternative)),
        1 => RoleChangeOperations.UpdateOrganizationRole(Org, Id, OrganizationChange(choice, alternative)),
        2 => RoleChangeOperations.CreateProjectRole(Org, Project, ProjectChange(choice, alternative)),
        3 => RoleChangeOperations.UpdateProjectRole(Org, Project, Id, ProjectChange(choice, alternative)),
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static ManagementTarget RoleTarget(int route, string choice, bool alternative) => route switch
    {
        0 => RoleChangeOperations.OrganizationCreationTarget(Org, OrganizationChange(choice, alternative)),
        1 => RoleChangeOperations.OrganizationUpdateTarget(Org, Id, OrganizationChange(choice, alternative)),
        2 => RoleChangeOperations.ProjectCreationTarget(Org, Project, ProjectChange(choice, alternative)),
        3 => RoleChangeOperations.ProjectUpdateTarget(Org, Project, Id, ProjectChange(choice, alternative)),
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static string RoleOperation(int route) => route switch
    {
        0 => "infisical.post.v1.organization.roles",
        1 => "infisical.patch.v1.organization.roles.by.roleId",
        2 => "infisical.post.v1.projects.by.projectId.roles",
        3 => "infisical.patch.v1.projects.by.projectId.roles.by.roleId",
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static string RolePath(int route) =>
        (route < 2 ? "/api/v1/organization/roles" : "/api/v1/projects/" + Project + "/roles") +
        (route % 2 == 1 ? "/" + Id : "");

    private static async Task VerifyRoleBody(JsonObject body, int route, string choice, bool alternative, bool verifySlug = true)
    {
        if (verifySlug)
            await Assert.That(body["slug"]!.GetValue<string>()).IsEqualTo(choice == "slug" && alternative ? "other-private" : Slug);
        var permission = body["permissions"]![0]!.AsObject();
        if (choice.StartsWith("tags-", StringComparison.Ordinal))
        {
            await Assert.That(permission["subject"]!.GetValue<string>()).IsEqualTo("secrets");
            await Assert.That(permission["action"]!.GetValue<string>()).IsEqualTo("read");
            var tags = permission["conditions"]!["secretTags"]!;
            await Assert.That(tags.ToJsonString()).IsEqualTo(choice switch
            {
                "tags-empty" => alternative ? """{"$all":["value-private"]}""" : "{}",
                "tags-in-presence" => alternative ? """{"$in":[]}""" : "{}",
                _ => alternative ? """{"$all":[]}""" : "{}"
            });
            return;
        }
        if (choice is "metadata-empty" or "metadata-key-empty")
        {
            await Assert.That(permission["subject"]!.GetValue<string>()).IsEqualTo("dynamic-secrets");
            await Assert.That(permission["action"]!.GetValue<string>()).IsEqualTo("lease");
            await Assert.That(permission.ContainsKey("conditions")).IsEqualTo(choice != "metadata-empty" || alternative);
            if (choice == "metadata-empty" && !alternative) return;
            await Assert.That(permission["conditions"]!["metadata"]!["$elemMatch"]!.ToJsonString())
                .IsEqualTo(choice == "metadata-key-empty" && alternative ? """{"key":{}}""" : "{}");
            return;
        }
        await Assert.That(permission["subject"]!.GetValue<string>()).IsEqualTo(choice == "subject" && alternative
            ? route < 2 ? "role" : "secret-folders" : route < 2 ? "app-connections" : "secrets");
        if (choice is "action-shape" or "action-order" or "action-length")
        {
            string expected = choice switch
            {
                "action-shape" => alternative ? """["read"]""" : "\"read\"",
                "action-order" => alternative ? """["edit","read"]""" : """["read","edit"]""",
                _ => alternative ? """["read","edit"]""" : """["read"]"""
            };
            await Assert.That(permission["action"]!.ToJsonString()).IsEqualTo(expected);
        }
        else await Assert.That(permission["action"]!.GetValue<string>()).IsEqualTo(choice == "action-value" && alternative ? "edit" : "read");
        bool hasConditions = choice == "conditions-presence" ? alternative :
            choice is "clause-empty" or "clause-presence" or "in-presence" or "literal-eq" or "eq-ne" or "eq-value" or "ne-value" or
                "in-value" or "in-order" or "in-length" or "glob-value" or "glob-eq";
        await Assert.That(permission.ContainsKey("conditions")).IsEqualTo(hasConditions);
        if (!hasConditions) return;
        if (choice == "clause-empty")
        {
            var conditions = permission["conditions"]!.AsObject();
            await Assert.That(conditions.Count).IsEqualTo(alternative ? 1 : 0);
            if (alternative)
                await Assert.That(conditions[route < 2 ? "connectionId" : "environment"]!.AsObject().Count).IsEqualTo(0);
            return;
        }
        if (choice == "conditions-presence")
        {
            await Assert.That(permission["conditions"]!.AsObject().Count).IsEqualTo(0);
            return;
        }
        await Assert.That(permission["conditions"]![route < 2 ? "connectionId" : "environment"]!.ToJsonString())
            .IsEqualTo(ExpectedClause(choice, alternative));
    }

    private static string ExpectedClause(string choice, bool alternative) => choice switch
    {
        "clause-presence" => alternative ? "{}" : "\"value-private\"",
        "in-presence" => alternative ? """{"$in":[]}""" : "{}",
        "literal-eq" => alternative ? """{"$eq":"value-private"}""" : "\"value-private\"",
        "eq-ne" => alternative ? """{"$ne":"value-private"}""" : """{"$eq":"value-private"}""",
        "eq-value" => alternative ? """{"$eq":"other-private"}""" : """{"$eq":"value-private"}""",
        "ne-value" => alternative ? """{"$ne":"other-private"}""" : """{"$ne":"value-private"}""",
        "in-value" => alternative ? """{"$in":["other-private"]}""" : """{"$in":["value-private"]}""",
        "in-order" => alternative ? """{"$in":["other-private","value-private"]}""" : """{"$in":["value-private","other-private"]}""",
        "in-length" => alternative ? """{"$in":["value-private","other-private"]}""" : """{"$in":["value-private"]}""",
        "glob-value" => alternative ? """{"$glob":"other-private*"}""" : """{"$glob":"value-private*"}""",
        "glob-eq" => alternative ? """{"$eq":"value-private*"}""" : """{"$glob":"value-private*"}""",
        _ => throw new ArgumentOutOfRangeException(nameof(choice))
    };

    // V04 row numbers follow the exact remainingIndependentUnits[V04].operationIds order.
    // The three inventory profiles (6,12,18) contain no permission field at all.
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    [Arguments(13)]
    [Arguments(14)]
    [Arguments(15)]
    [Arguments(16)]
    [Arguments(17)]
    [Arguments(19)]
    [Arguments(20)]
    [Arguments(21)]
    [Arguments(22)]
    [Arguments(23)]
    public async Task NativePermissionRowsOwnEachAdmittedResultAlternative(int row)
    {
        // Basis witnesses, not an invented Cartesian product of all alternatives.
        foreach (string shape in new[]
        {
            "scalar", "action-array", "action-empty", "action-empty-item",
            "subject-scalar", "subject-array", "subject-empty", "subject-empty-item",
            "inverted-false", "inverted-true", "opaque-conditions", "permissions-empty"
        })
        {
            var fixture = ResultFixture(row);
            var permission = new JsonObject { ["action"] = "read-private" };
            if (shape == "action-array") permission["action"] = new JsonArray("read-private", "edit-private");
            if (shape == "action-empty") permission["action"] = new JsonArray();
            if (shape == "action-empty-item") permission["action"] = new JsonArray("");
            if (shape == "subject-scalar") permission["subject"] = "secrets-private";
            if (shape == "subject-array") permission["subject"] = new JsonArray("secrets-private", "role-private");
            if (shape == "subject-empty") permission["subject"] = new JsonArray();
            if (shape == "subject-empty-item") permission["subject"] = new JsonArray("");
            if (shape is "inverted-false" or "inverted-true") permission["inverted"] = shape == "inverted-true";
            // This opaque value is a confidentiality witness only, never a typed B02 interpretation.
            if (shape == "opaque-conditions") permission["conditions"] = "unestablished-private";
            fixture["permissions"] = shape == "permissions-empty" ? new JsonArray() : new JsonArray(permission);
            await ExecuteResultRow(row, fixture, async permissions =>
            {
                await Assert.That(permissions).IsNotNull();
                await Assert.That(permissions!.Count).IsEqualTo(shape == "permissions-empty" ? 0 : 1);
                await Assert.That(() => ((IList<RolePermissionSummary>)permissions).Clear()).Throws<NotSupportedException>();
                if (shape == "permissions-empty") return;
                RolePermissionSummary summary = permissions[0];
                await Assert.That(summary.Action.IsScalar).IsEqualTo(!shape.StartsWith("action-", StringComparison.Ordinal));
                string[] actions = shape switch
                {
                    "action-array" => ["read-private", "edit-private"],
                    "action-empty" => [],
                    "action-empty-item" => [""],
                    _ => ["read-private"]
                };
                await Assert.That(summary.Action.Values.SequenceEqual(actions)).IsTrue();
                bool subjectPresent = shape.StartsWith("subject-", StringComparison.Ordinal);
                await Assert.That(summary.Subject is not null).IsEqualTo(subjectPresent);
                if (subjectPresent)
                {
                    await Assert.That(summary.Subject!.IsScalar).IsEqualTo(shape == "subject-scalar");
                    string[] subjects = shape switch
                    {
                        "subject-scalar" => ["secrets-private"],
                        "subject-array" => ["secrets-private", "role-private"],
                        "subject-empty" => [],
                        _ => [""]
                    };
                    await Assert.That(summary.Subject.Values.SequenceEqual(subjects)).IsTrue();
                    await Assert.That(() => ((IList<string>)summary.Subject.Values).Clear()).Throws<NotSupportedException>();
                    await Private(summary.Subject);
                }
                await Assert.That(summary.Inverted).IsEqualTo(shape == "inverted-false" ? false :
                    shape == "inverted-true" ? true : (bool?)null);
                await Assert.That(summary.HasConditions).IsEqualTo(shape == "opaque-conditions");
                await Assert.That(summary.IncludesConditionValues).IsFalse();
                await Assert.That(() => ((IList<string>)summary.Action.Values).Clear()).Throws<NotSupportedException>();
                await Private(summary, summary.Action);
            });
        }
    }

    [Test]
    [Arguments(6)]
    [Arguments(12)]
    [Arguments(18)]
    public async Task NativeInventoryProfilesDoNotInventPermissionPayloads(int row)
    {
        var fixture = ResultFixture(row);
        fixture.Remove("permissions");
        await ExecuteResultRow(row, fixture, async permissions => await Assert.That(permissions).IsNull());
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(18)]
    [Arguments(19)]
    [Arguments(20)]
    [Arguments(21)]
    [Arguments(22)]
    [Arguments(23)]
    public async Task PrivilegeRowsRequireDeclaredTimestampsAndPermissionPresence(int row)
    {
        foreach (string field in row == 18 ? new[] { "createdAt", "updatedAt" } :
            new[] { "createdAt", "updatedAt", "permissions" })
        {
            foreach (string shape in new[] { "absent", "null", "wrong-kind" })
            {
                var fixture = ResultFixture(row);
                if (shape == "absent") fixture.Remove(field);
                else fixture[field] = shape == "null" ? null : JsonValue.Create(false);
                await ExecuteResultRow(row, fixture, _ => Task.CompletedTask, SecretStatus.Unknown);
            }
        }
    }

    private static JsonObject ResultFixture(int row) => row is >= 6 and <= 17 ? RoleFixture(row < 12) :
        PrivilegeFixture(row < 6);

    private static async Task ExecuteResultRow(int row, JsonObject fixture,
        Func<IReadOnlyList<RolePermissionSummary>?, Task> verify, SecretStatus expected = SecretStatus.Success)
    {
        if (row is 6 or 12)
        {
            using var request = row == 6 ? ScopedAccessOperations.ListOrganizationRoles(Org) :
                ProjectOperations.ListProjectRoles(Org, Project);
            await ExecuteResult(request, row, new JsonObject { ["roles"] = new JsonArray(fixture) },
                new(Org, row == 6 ? null : Project), async page =>
                {
                    await Assert.That(page.IsComplete).IsTrue();
                    await Assert.That(page.Items.Count).IsEqualTo(1);
                    await Assert.That(() => ((IList<RoleSummary>)page.Items).Clear()).Throws<NotSupportedException>();
                    await Assert.That(page.Items[0].IncludesPermissions).IsFalse();
                    await verify(page.Items[0].Permissions);
                    await Private(page.Items[0]);
                }, expected);
        }
        else if (row is 1 or 18)
        {
            using var request = row == 1 ? LegacyIdentityPrivilegeOperations.ListPrivileges(Selection()) :
                IdentityPrivilegeOperations.ListProjectPrivileges(Org, Project, Identity);
            await ExecuteResult(request, row, new JsonObject { ["privileges"] = new JsonArray(fixture) },
                row == 1 ? Selection().GrantTarget() : new(Org, Project, Identity), async page =>
                {
                    await Assert.That(page.IsComplete).IsTrue();
                    await Assert.That(page.Items.Count).IsEqualTo(1);
                    await Assert.That(() => ((IList<IdentityPrivilegeSummary>)page.Items).Clear()).Throws<NotSupportedException>();
                    await Assert.That(page.Items[0].IncludesPermissions).IsEqualTo(row == 1);
                    await verify(page.Items[0].Permissions);
                    await Private(page.Items[0]);
                }, expected);
        }
        else if (row is >= 7 and <= 17)
        {
            using var request = ResultRoleRequest(row);
            var target = row switch
            {
                7 => RoleChangeOperations.OrganizationCreationTarget(Org, new("Reviewed", Slug, permissions: [])),
                10 => RoleChangeOperations.OrganizationUpdateTarget(Org, Id, new(name: "Reviewed")),
                13 => RoleChangeOperations.ProjectCreationTarget(Org, Project, new("Reviewed", Slug, permissions: [])),
                15 => RoleChangeOperations.ProjectUpdateTarget(Org, Project, Id, new(name: "Reviewed")),
                _ => new ManagementTarget(Org, row < 12 ? null : Project, row is 11 or 16 ? Slug : Id)
            };
            await ExecuteResult(request, row, new JsonObject { ["role"] = fixture }, target, async role =>
            {
                await Assert.That(role.Id).IsEqualTo(Id);
                await Assert.That(role.Slug).IsEqualTo(Slug);
                await Assert.That(role.IncludesPermissions).IsTrue();
                await verify(role.Permissions);
            }, expected);
        }
        else
        {
            using var request = ResultPrivilegeRequest(row);
            ManagementTarget target = row switch
            {
                2 => PrivilegeTarget(0, "baseline", false),
                4 => PrivilegeTarget(1, "baseline", false),
                5 => PrivilegeTarget(2, "baseline", false),
                19 => PrivilegeTarget(3, "baseline", false),
                22 => PrivilegeTarget(4, "baseline", false),
                0 or 3 or 23 => Selection().GrantTarget(Slug),
                _ => new(Org, Project, Identity, Id)
            };
            await ExecuteResult(request, row, new JsonObject { ["privilege"] = fixture }, target, async privilege =>
            {
                await Assert.That(privilege.Id).IsEqualTo(Id);
                await Assert.That(privilege.Slug).IsEqualTo(Slug);
                await Assert.That(privilege.IncludesPermissions).IsTrue();
                await verify(privilege.Permissions);
            }, expected);
        }
    }

    private static ManagementRequest<RoleSummary> ResultRoleRequest(int row) => row switch
    {
        7 => RoleChangeOperations.CreateOrganizationRole(Org, new("Reviewed", Slug, permissions: [])),
        8 => ScopedAccessOperations.DeleteOrganizationRole(Org, Id),
        9 => ScopedAccessOperations.GetOrganizationRole(Org, Id),
        10 => RoleChangeOperations.UpdateOrganizationRole(Org, Id, new(name: "Reviewed")),
        11 => ScopedAccessOperations.GetOrganizationRoleBySlug(Org, Slug),
        13 => RoleChangeOperations.CreateProjectRole(Org, Project, new("Reviewed", Slug, permissions: [])),
        14 => ProjectOperations.DeleteProjectRole(Org, Project, Id),
        15 => RoleChangeOperations.UpdateProjectRole(Org, Project, Id, new(name: "Reviewed")),
        16 => ProjectOperations.GetProjectRoleBySlug(Org, Project, Slug),
        17 => ProjectOperations.GetProjectRole(Org, Project, Id),
        _ => throw new ArgumentOutOfRangeException(nameof(row))
    };

    private static ManagementRequest<IdentityPrivilegeSummary> ResultPrivilegeRequest(int row) => row switch
    {
        0 => LegacyIdentityPrivilegeOperations.DeletePrivilege(Selection(), Slug),
        2 => PrivilegeRequest(0, "baseline", false),
        3 => LegacyIdentityPrivilegeOperations.GetPrivilege(Selection(), Slug),
        4 => PrivilegeRequest(1, "baseline", false),
        5 => PrivilegeRequest(2, "baseline", false),
        19 => PrivilegeRequest(3, "baseline", false),
        20 => IdentityPrivilegeOperations.DeleteProjectPrivilege(Org, Project, Identity, Id),
        21 => IdentityPrivilegeOperations.GetProjectPrivilege(Org, Project, Identity, Id),
        22 => PrivilegeRequest(4, "baseline", false),
        23 => IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug(Selection(), Slug),
        _ => throw new ArgumentOutOfRangeException(nameof(row))
    };

    private static async Task ExecuteResult<T>(ManagementRequest<T> request, int row, JsonObject envelope,
        ManagementTarget target, Func<T, Task> verify, SecretStatus expected = SecretStatus.Success) where T : notnull
    {
        var wire = new Wire(ResultPath(row), ResultMethod(row), envelope.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, row is >= 6 and <= 11 ? null : Project);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(ResultOperation(row), target), receipt);
        await Assert.That(request.OperationId).IsEqualTo(ResultOperation(row));
        await Assert.That(wire.Dispatched).IsTrue();
        await Assert.That(result.Status).IsEqualTo(expected);
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(
            expected == SecretStatus.Success ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
        if (expected != SecretStatus.Success) return;
        // All result assertions occur after response-document, request-body and transport ownership ends.
        request.Dispose();
        transport.Dispose();
        envelope.Clear();
        await verify(result.Value);
        await Private(result.Value, target, request);
    }

    private static string ResultOperation(int row) => row switch
    {
        0 => "infisical.delete.v1.additional.privilege.identity",
        1 => "infisical.get.v1.additional.privilege.identity",
        2 => PrivilegeOperation(0),
        3 => "infisical.get.v1.additional.privilege.identity.by.privilegeSlug",
        4 => PrivilegeOperation(1),
        5 => PrivilegeOperation(2),
        6 => "infisical.get.v1.organization.roles",
        7 => RoleOperation(0),
        8 => "infisical.delete.v1.organization.roles.by.roleId",
        9 => "infisical.get.v1.organization.roles.by.roleId",
        10 => RoleOperation(1),
        11 => "infisical.get.v1.organization.roles.slug.by.roleSlug",
        12 => "infisical.get.v1.projects.by.projectId.roles",
        13 => RoleOperation(2),
        14 => "infisical.delete.v1.projects.by.projectId.roles.by.roleId",
        15 => RoleOperation(3),
        16 => "infisical.get.v1.projects.by.projectId.roles.slug.by.roleSlug",
        17 => "infisical.get.v1.projects.roles.by.roleId",
        18 => "infisical.get.v2.identity.project.additional.privilege",
        19 => PrivilegeOperation(3),
        20 => "infisical.delete.v2.identity.project.additional.privilege.by.id",
        21 => "infisical.get.v2.identity.project.additional.privilege.by.id",
        22 => PrivilegeOperation(4),
        23 => "infisical.get.v2.identity.project.additional.privilege.slug.by.privilegeSlug",
        _ => throw new ArgumentOutOfRangeException(nameof(row))
    };

    private static string ResultMethod(int row) => row switch
    {
        0 or 8 or 14 or 20 => "DELETE",
        2 or 10 or 15 or 22 => "PATCH",
        4 or 5 or 7 or 13 or 19 => "POST",
        _ => "GET"
    };

    private static string ResultPath(int row) => row switch
    {
        0 or 2 => PrivilegePath(0),
        1 => PrivilegePath(0) + "?identityId=" + Identity + "&projectSlug=" + ProjectSlug,
        3 => PrivilegePath(0) + "/" + Slug + "?identityId=" + Identity + "&projectSlug=" + ProjectSlug,
        4 => PrivilegePath(1),
        5 => PrivilegePath(2),
        6 or 7 => RolePath(0),
        8 or 9 or 10 => RolePath(1),
        11 => RolePath(0) + "/slug/" + Slug,
        12 or 13 => RolePath(2),
        14 or 15 => RolePath(3),
        16 => RolePath(2) + "/slug/" + Slug,
        17 => "/api/v1/projects/roles/" + Id,
        18 => PrivilegePath(3) + "?projectId=" + Project + "&identityId=" + Identity,
        19 => PrivilegePath(3),
        20 or 21 or 22 => PrivilegePath(4),
        23 => PrivilegePath(3) + "/slug/" + Slug + "?identityId=" + Identity + "&projectSlug=" + ProjectSlug,
        _ => throw new ArgumentOutOfRangeException(nameof(row))
    };

    private static JsonObject RoleFixture(bool organization) => new()
    {
        ["id"] = Id,
        ["name"] = "Reviewed",
        ["slug"] = Slug,
        [organization ? "orgId" : "projectId"] = organization ? Org : Project,
        ["createdAt"] = "2026-01-01T00:00:00Z",
        ["updatedAt"] = "2026-01-02T00:00:00Z",
        ["permissions"] = new JsonArray()
    };

    private static async Task Private(params object[] values)
    {
        foreach (object value in values)
        {
            await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    private static ManagementTransport Transport(Wire wire) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, wire);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("offline-fixture-token"))));
        }
    }

    private sealed class Wire(string path, string method, string response) : HttpMessageHandler
    {
        public string Response { get; set; } = response;
        public JsonObject? Body { get; private set; }
        public bool Dispatched { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.PathAndQuery != path || request.Method.Method != method ||
                request.Headers.Authorization?.Scheme != "Bearer")
                return new(HttpStatusCode.NotFound);
            Dispatched = true;
            if (request.Content is not null)
                Body = JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))!.AsObject();
            return new(HttpStatusCode.OK) { Content = new StringContent(Response, Encoding.UTF8, "application/json") };
        }
    }
}
