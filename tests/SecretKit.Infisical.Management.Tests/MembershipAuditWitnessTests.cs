using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class MembershipAuditWitnessTests
{
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string Project = "22222222-2222-4222-8222-222222222222";
    private const string Group = "33333333-3333-4333-8333-333333333333";
    private const string Identity = "44444444-4444-4444-8444-444444444444";
    private const string Member = "55555555-5555-4555-8555-555555555555";
    private const string Foreign = "66666666-6666-4666-8666-666666666666";
    private const string Time = "2026-10-10T00:00:00Z";

    // N03: 0485 primitive DELETE; 0486 detail GET/PATCH/POST.
    // N06: 0530 list; 0532 primitive DELETE; 0533 detail POST.
    // N07: 0537 primitive DELETE/PATCH. No unlisted scope echoes or roles.
    [Test]
    [Arguments("org-delete")]
    [Arguments("org-get")]
    [Arguments("org-update")]
    [Arguments("org-add")]
    [Arguments("project-list")]
    [Arguments("project-delete")]
    [Arguments("project-add")]
    [Arguments("identity-delete")]
    [Arguments("identity-update")]
    public async Task EndpointSchemaValidBaselineSucceeds(string route)
    {
        await VerifyResponse(route, Fixture(route).ToJsonString(), SecretStatus.Success);
    }

    // Each argument changes exactly one required field. Fact IDs map to the frozen registry.
    [Test]
    [Arguments("org-delete", "$", "malformed", "field-00001")]
    [Arguments("org-delete", "groupMembership", "missing", "field-08873")]
    [Arguments("org-delete", "groupMembership", "malformed", "field-08873")]
    [Arguments("org-delete", "groupMembership.createdAt", "missing", "field-08874")]
    [Arguments("org-delete", "groupMembership.createdAt", "malformed", "field-08874")]
    [Arguments("org-delete", "groupMembership.groupId", "missing", "field-08875")]
    [Arguments("org-delete", "groupMembership.groupId", "malformed", "field-08875")]
    [Arguments("org-delete", "groupMembership.id", "missing", "field-08876")]
    [Arguments("org-delete", "groupMembership.id", "malformed", "field-08876")]
    [Arguments("org-delete", "groupMembership.orgId", "missing", "field-08877")]
    [Arguments("org-delete", "groupMembership.orgId", "malformed", "field-08877")]
    [Arguments("org-delete", "groupMembership.updatedAt", "missing", "field-08878")]
    [Arguments("org-delete", "groupMembership.updatedAt", "malformed", "field-08878")]
    [Arguments("org-get", "$", "malformed", "field-00001")]
    [Arguments("org-get", "groupMembership", "missing", "field-08873")]
    [Arguments("org-get", "groupMembership", "malformed", "field-08873")]
    [Arguments("org-get", "groupMembership.createdAt", "missing", "field-08874")]
    [Arguments("org-get", "groupMembership.createdAt", "malformed", "field-08874")]
    [Arguments("org-get", "groupMembership.group", "missing", "field-08879")]
    [Arguments("org-get", "groupMembership.group", "malformed", "field-08879")]
    [Arguments("org-get", "groupMembership.group.id", "missing", "field-08880")]
    [Arguments("org-get", "groupMembership.group.id", "malformed", "field-08880")]
    [Arguments("org-get", "groupMembership.group.name", "missing", "field-08881")]
    [Arguments("org-get", "groupMembership.group.name", "malformed", "field-08881")]
    [Arguments("org-get", "groupMembership.group.slug", "missing", "field-08883")]
    [Arguments("org-get", "groupMembership.group.slug", "malformed", "field-08883")]
    [Arguments("org-get", "groupMembership.groupId", "missing", "field-08875")]
    [Arguments("org-get", "groupMembership.groupId", "malformed", "field-08875")]
    [Arguments("org-get", "groupMembership.id", "missing", "field-08876")]
    [Arguments("org-get", "groupMembership.id", "malformed", "field-08876")]
    [Arguments("org-get", "groupMembership.roles", "missing", "field-08884")]
    [Arguments("org-get", "groupMembership.roles", "malformed", "field-08884")]
    [Arguments("org-get", "groupMembership.roles[]", "malformed", "field-08885")]
    [Arguments("org-get", "groupMembership.roles[].id", "missing", "field-08890")]
    [Arguments("org-get", "groupMembership.roles[].id", "malformed", "field-08890")]
    [Arguments("org-get", "groupMembership.roles[].isTemporary", "missing", "field-08891")]
    [Arguments("org-get", "groupMembership.roles[].isTemporary", "malformed", "field-08891")]
    [Arguments("org-get", "groupMembership.roles[].role", "missing", "field-08892")]
    [Arguments("org-get", "groupMembership.roles[].role", "malformed", "field-08892")]
    [Arguments("org-get", "groupMembership.updatedAt", "missing", "field-08878")]
    [Arguments("org-get", "groupMembership.updatedAt", "malformed", "field-08878")]
    [Arguments("org-update", "$", "malformed", "field-00001")]
    [Arguments("org-update", "groupMembership", "missing", "field-08873")]
    [Arguments("org-update", "groupMembership", "malformed", "field-08873")]
    [Arguments("org-update", "groupMembership.createdAt", "missing", "field-08874")]
    [Arguments("org-update", "groupMembership.createdAt", "malformed", "field-08874")]
    [Arguments("org-update", "groupMembership.group", "missing", "field-08879")]
    [Arguments("org-update", "groupMembership.group", "malformed", "field-08879")]
    [Arguments("org-update", "groupMembership.group.id", "missing", "field-08880")]
    [Arguments("org-update", "groupMembership.group.id", "malformed", "field-08880")]
    [Arguments("org-update", "groupMembership.group.name", "missing", "field-08881")]
    [Arguments("org-update", "groupMembership.group.name", "malformed", "field-08881")]
    [Arguments("org-update", "groupMembership.group.slug", "missing", "field-08883")]
    [Arguments("org-update", "groupMembership.group.slug", "malformed", "field-08883")]
    [Arguments("org-update", "groupMembership.groupId", "missing", "field-08875")]
    [Arguments("org-update", "groupMembership.groupId", "malformed", "field-08875")]
    [Arguments("org-update", "groupMembership.id", "missing", "field-08876")]
    [Arguments("org-update", "groupMembership.id", "malformed", "field-08876")]
    [Arguments("org-update", "groupMembership.roles", "missing", "field-08884")]
    [Arguments("org-update", "groupMembership.roles", "malformed", "field-08884")]
    [Arguments("org-update", "groupMembership.roles[]", "malformed", "field-08885")]
    [Arguments("org-update", "groupMembership.roles[].id", "missing", "field-08890")]
    [Arguments("org-update", "groupMembership.roles[].id", "malformed", "field-08890")]
    [Arguments("org-update", "groupMembership.roles[].isTemporary", "missing", "field-08891")]
    [Arguments("org-update", "groupMembership.roles[].isTemporary", "malformed", "field-08891")]
    [Arguments("org-update", "groupMembership.roles[].role", "missing", "field-08892")]
    [Arguments("org-update", "groupMembership.roles[].role", "malformed", "field-08892")]
    [Arguments("org-update", "groupMembership.updatedAt", "missing", "field-08878")]
    [Arguments("org-update", "groupMembership.updatedAt", "malformed", "field-08878")]
    [Arguments("org-add", "$", "malformed", "field-00001")]
    [Arguments("org-add", "groupMembership", "missing", "field-08873")]
    [Arguments("org-add", "groupMembership", "malformed", "field-08873")]
    [Arguments("org-add", "groupMembership.createdAt", "missing", "field-08874")]
    [Arguments("org-add", "groupMembership.createdAt", "malformed", "field-08874")]
    [Arguments("org-add", "groupMembership.group", "missing", "field-08879")]
    [Arguments("org-add", "groupMembership.group", "malformed", "field-08879")]
    [Arguments("org-add", "groupMembership.group.id", "missing", "field-08880")]
    [Arguments("org-add", "groupMembership.group.id", "malformed", "field-08880")]
    [Arguments("org-add", "groupMembership.group.name", "missing", "field-08881")]
    [Arguments("org-add", "groupMembership.group.name", "malformed", "field-08881")]
    [Arguments("org-add", "groupMembership.group.slug", "missing", "field-08883")]
    [Arguments("org-add", "groupMembership.group.slug", "malformed", "field-08883")]
    [Arguments("org-add", "groupMembership.groupId", "missing", "field-08875")]
    [Arguments("org-add", "groupMembership.groupId", "malformed", "field-08875")]
    [Arguments("org-add", "groupMembership.id", "missing", "field-08876")]
    [Arguments("org-add", "groupMembership.id", "malformed", "field-08876")]
    [Arguments("org-add", "groupMembership.roles", "missing", "field-08884")]
    [Arguments("org-add", "groupMembership.roles", "malformed", "field-08884")]
    [Arguments("org-add", "groupMembership.roles[]", "malformed", "field-08885")]
    [Arguments("org-add", "groupMembership.roles[].id", "missing", "field-08890")]
    [Arguments("org-add", "groupMembership.roles[].id", "malformed", "field-08890")]
    [Arguments("org-add", "groupMembership.roles[].isTemporary", "missing", "field-08891")]
    [Arguments("org-add", "groupMembership.roles[].isTemporary", "malformed", "field-08891")]
    [Arguments("org-add", "groupMembership.roles[].role", "missing", "field-08892")]
    [Arguments("org-add", "groupMembership.roles[].role", "malformed", "field-08892")]
    [Arguments("org-add", "groupMembership.updatedAt", "missing", "field-08878")]
    [Arguments("org-add", "groupMembership.updatedAt", "malformed", "field-08878")]
    [Arguments("project-list", "$", "malformed", "field-00001")]
    [Arguments("project-list", "groupMemberships", "missing", "field-08847")]
    [Arguments("project-list", "groupMemberships", "malformed", "field-08847")]
    [Arguments("project-list", "groupMemberships[]", "malformed", "field-08848")]
    [Arguments("project-list", "groupMemberships[].createdAt", "missing", "field-08849")]
    [Arguments("project-list", "groupMemberships[].createdAt", "malformed", "field-08849")]
    [Arguments("project-list", "groupMemberships[].group", "missing", "field-08850")]
    [Arguments("project-list", "groupMemberships[].group", "malformed", "field-08850")]
    [Arguments("project-list", "groupMemberships[].group.id", "missing", "field-08851")]
    [Arguments("project-list", "groupMemberships[].group.id", "malformed", "field-08851")]
    [Arguments("project-list", "groupMemberships[].group.name", "missing", "field-08852")]
    [Arguments("project-list", "groupMemberships[].group.name", "malformed", "field-08852")]
    [Arguments("project-list", "groupMemberships[].group.slug", "missing", "field-08854")]
    [Arguments("project-list", "groupMemberships[].group.slug", "malformed", "field-08854")]
    [Arguments("project-list", "groupMemberships[].groupId", "missing", "field-08855")]
    [Arguments("project-list", "groupMemberships[].groupId", "malformed", "field-08855")]
    [Arguments("project-list", "groupMemberships[].id", "missing", "field-08856")]
    [Arguments("project-list", "groupMemberships[].id", "malformed", "field-08856")]
    [Arguments("project-list", "groupMemberships[].projectId", "missing", "field-10198")]
    [Arguments("project-list", "groupMemberships[].projectId", "malformed", "field-10198")]
    [Arguments("project-list", "groupMemberships[].roles", "missing", "field-08857")]
    [Arguments("project-list", "groupMemberships[].roles", "malformed", "field-08857")]
    [Arguments("project-list", "groupMemberships[].roles[]", "malformed", "field-08858")]
    [Arguments("project-list", "groupMemberships[].roles[].id", "missing", "field-08863")]
    [Arguments("project-list", "groupMemberships[].roles[].id", "malformed", "field-08863")]
    [Arguments("project-list", "groupMemberships[].roles[].isTemporary", "missing", "field-08864")]
    [Arguments("project-list", "groupMemberships[].roles[].isTemporary", "malformed", "field-08864")]
    [Arguments("project-list", "groupMemberships[].roles[].role", "missing", "field-08865")]
    [Arguments("project-list", "groupMemberships[].roles[].role", "malformed", "field-08865")]
    [Arguments("project-list", "groupMemberships[].updatedAt", "missing", "field-08871")]
    [Arguments("project-list", "groupMemberships[].updatedAt", "malformed", "field-08871")]
    [Arguments("project-delete", "$", "malformed", "field-00001")]
    [Arguments("project-delete", "groupMembership", "missing", "field-08873")]
    [Arguments("project-delete", "groupMembership", "malformed", "field-08873")]
    [Arguments("project-delete", "groupMembership.createdAt", "missing", "field-08874")]
    [Arguments("project-delete", "groupMembership.createdAt", "malformed", "field-08874")]
    [Arguments("project-delete", "groupMembership.groupId", "missing", "field-08875")]
    [Arguments("project-delete", "groupMembership.groupId", "malformed", "field-08875")]
    [Arguments("project-delete", "groupMembership.id", "missing", "field-08876")]
    [Arguments("project-delete", "groupMembership.id", "malformed", "field-08876")]
    [Arguments("project-delete", "groupMembership.projectId", "missing", "field-10199")]
    [Arguments("project-delete", "groupMembership.projectId", "malformed", "field-10199")]
    [Arguments("project-delete", "groupMembership.updatedAt", "missing", "field-08878")]
    [Arguments("project-delete", "groupMembership.updatedAt", "malformed", "field-08878")]
    [Arguments("project-add", "$", "malformed", "field-00001")]
    [Arguments("project-add", "groupMembership", "missing", "field-08873")]
    [Arguments("project-add", "groupMembership", "malformed", "field-08873")]
    [Arguments("project-add", "groupMembership.createdAt", "missing", "field-08874")]
    [Arguments("project-add", "groupMembership.createdAt", "malformed", "field-08874")]
    [Arguments("project-add", "groupMembership.group", "missing", "field-08879")]
    [Arguments("project-add", "groupMembership.group", "malformed", "field-08879")]
    [Arguments("project-add", "groupMembership.group.id", "missing", "field-08880")]
    [Arguments("project-add", "groupMembership.group.id", "malformed", "field-08880")]
    [Arguments("project-add", "groupMembership.group.name", "missing", "field-08881")]
    [Arguments("project-add", "groupMembership.group.name", "malformed", "field-08881")]
    [Arguments("project-add", "groupMembership.group.slug", "missing", "field-08883")]
    [Arguments("project-add", "groupMembership.group.slug", "malformed", "field-08883")]
    [Arguments("project-add", "groupMembership.groupId", "missing", "field-08875")]
    [Arguments("project-add", "groupMembership.groupId", "malformed", "field-08875")]
    [Arguments("project-add", "groupMembership.id", "missing", "field-08876")]
    [Arguments("project-add", "groupMembership.id", "malformed", "field-08876")]
    [Arguments("project-add", "groupMembership.projectId", "missing", "field-10199")]
    [Arguments("project-add", "groupMembership.projectId", "malformed", "field-10199")]
    [Arguments("project-add", "groupMembership.roles", "missing", "field-08884")]
    [Arguments("project-add", "groupMembership.roles", "malformed", "field-08884")]
    [Arguments("project-add", "groupMembership.roles[]", "malformed", "field-08885")]
    [Arguments("project-add", "groupMembership.roles[].id", "missing", "field-08890")]
    [Arguments("project-add", "groupMembership.roles[].id", "malformed", "field-08890")]
    [Arguments("project-add", "groupMembership.roles[].isTemporary", "missing", "field-08891")]
    [Arguments("project-add", "groupMembership.roles[].isTemporary", "malformed", "field-08891")]
    [Arguments("project-add", "groupMembership.roles[].role", "missing", "field-08892")]
    [Arguments("project-add", "groupMembership.roles[].role", "malformed", "field-08892")]
    [Arguments("project-add", "groupMembership.updatedAt", "missing", "field-08878")]
    [Arguments("project-add", "groupMembership.updatedAt", "malformed", "field-08878")]
    [Arguments("identity-delete", "$", "malformed", "field-00001")]
    [Arguments("identity-delete", "identityMembership", "missing", "field-10228")]
    [Arguments("identity-delete", "identityMembership", "malformed", "field-10228")]
    [Arguments("identity-delete", "identityMembership.createdAt", "missing", "field-10229")]
    [Arguments("identity-delete", "identityMembership.createdAt", "malformed", "field-10229")]
    [Arguments("identity-delete", "identityMembership.id", "missing", "field-10230")]
    [Arguments("identity-delete", "identityMembership.id", "malformed", "field-10230")]
    [Arguments("identity-delete", "identityMembership.identityId", "missing", "field-10231")]
    [Arguments("identity-delete", "identityMembership.identityId", "malformed", "field-10231")]
    [Arguments("identity-delete", "identityMembership.projectId", "missing", "field-10232")]
    [Arguments("identity-delete", "identityMembership.projectId", "malformed", "field-10232")]
    [Arguments("identity-delete", "identityMembership.updatedAt", "missing", "field-10233")]
    [Arguments("identity-delete", "identityMembership.updatedAt", "malformed", "field-10233")]
    [Arguments("identity-update", "$", "malformed", "field-00001")]
    [Arguments("identity-update", "identityMembership", "missing", "field-10228")]
    [Arguments("identity-update", "identityMembership", "malformed", "field-10228")]
    [Arguments("identity-update", "identityMembership.createdAt", "missing", "field-10229")]
    [Arguments("identity-update", "identityMembership.createdAt", "malformed", "field-10229")]
    [Arguments("identity-update", "identityMembership.id", "missing", "field-10230")]
    [Arguments("identity-update", "identityMembership.id", "malformed", "field-10230")]
    [Arguments("identity-update", "identityMembership.identityId", "missing", "field-10231")]
    [Arguments("identity-update", "identityMembership.identityId", "malformed", "field-10231")]
    [Arguments("identity-update", "identityMembership.projectId", "missing", "field-10232")]
    [Arguments("identity-update", "identityMembership.projectId", "malformed", "field-10232")]
    [Arguments("identity-update", "identityMembership.updatedAt", "missing", "field-10233")]
    [Arguments("identity-update", "identityMembership.updatedAt", "malformed", "field-10233")]
    public async Task RequiredResponseFieldFailsClosed(string route, string field, string variant, string factId)
    {
        await Assert.That(factId.StartsWith("field-", StringComparison.Ordinal)).IsTrue();
        JsonNode body = Fixture(route);
        if (field == "$") body = JsonValue.Create(123)!;
        else ChangeField(body, field, variant == "missing", JsonValue.Create(123));
        await VerifyResponse(route, body.ToJsonString(), SecretStatus.Unknown);
    }

    [Test]
    [Arguments("org-delete", "groupMembership.groupId", "field-08875")]
    [Arguments("org-delete", "groupMembership.orgId", "field-08877")]
    [Arguments("org-get", "groupMembership.groupId", "field-08875")]
    [Arguments("org-get", "groupMembership.group.id", "field-08880")]
    [Arguments("org-get", "groupMembership.group.orgId", "field-08882")]
    [Arguments("org-update", "groupMembership.groupId", "field-08875")]
    [Arguments("org-update", "groupMembership.group.id", "field-08880")]
    [Arguments("org-update", "groupMembership.group.orgId", "field-08882")]
    [Arguments("org-add", "groupMembership.groupId", "field-08875")]
    [Arguments("org-add", "groupMembership.group.id", "field-08880")]
    [Arguments("org-add", "groupMembership.group.orgId", "field-08882")]
    [Arguments("project-list", "groupMemberships[].groupId", "field-08855")]
    [Arguments("project-list", "groupMemberships[].group.id", "field-08851")]
    [Arguments("project-list", "groupMemberships[].group.orgId", "field-08853")]
    [Arguments("project-list", "groupMemberships[].projectId", "field-10198")]
    [Arguments("project-delete", "groupMembership.groupId", "field-08875")]
    [Arguments("project-delete", "groupMembership.projectId", "field-10199")]
    [Arguments("project-add", "groupMembership.groupId", "field-08875")]
    [Arguments("project-add", "groupMembership.group.id", "field-08880")]
    [Arguments("project-add", "groupMembership.group.orgId", "field-08882")]
    [Arguments("project-add", "groupMembership.projectId", "field-10199")]
    [Arguments("identity-delete", "identityMembership.identityId", "field-10231")]
    [Arguments("identity-delete", "identityMembership.projectId", "field-10232")]
    [Arguments("identity-update", "identityMembership.identityId", "field-10231")]
    [Arguments("identity-update", "identityMembership.projectId", "field-10232")]
    public async Task ForeignKnownResponseCoordinateFailsClosed(string route, string field, string factId)
    {
        await Assert.That(factId.StartsWith("field-", StringComparison.Ordinal)).IsTrue();
        JsonNode body = Fixture(route);
        ChangeField(body, field, false, JsonValue.Create(Foreign));
        await VerifyResponse(route, body.ToJsonString(), SecretStatus.Invalid);
    }

    // I03: same coordinates, one body choice at a time, both approval directions.
    [Test]
    [Arguments("same", false)]
    [Arguments("role-omission", false)]
    [Arguments("role-omission", true)]
    [Arguments("active-omission-false", false)]
    [Arguments("active-omission-false", true)]
    [Arguments("metadata-omission-empty", false)]
    [Arguments("metadata-omission-empty", true)]
    [Arguments("metadata-omission-value", false)]
    [Arguments("metadata-omission-value", true)]
    [Arguments("metadata-empty-value", false)]
    [Arguments("metadata-empty-value", true)]
    [Arguments("metadata-order", false)]
    [Arguments("metadata-order", true)]
    [Arguments("metadata-key", false)]
    [Arguments("metadata-key", true)]
    public async Task OrganizationMemberBodyChoiceRequiresIndependentApproval(string choice, bool reverse)
    {
        string? role = "admin";
        bool? active = false;
        IdentityAttribute[]? metadata = [new("first", "same-value"), new("second", "same-value")];
        string? otherRole = role;
        bool? otherActive = active;
        IdentityAttribute[]? otherMetadata = metadata;
        switch (choice)
        {
            case "role-omission": otherRole = null; break;
            case "active-omission-false": otherActive = null; break;
            case "metadata-omission-empty": metadata = []; otherMetadata = null; break;
            case "metadata-omission-value": otherMetadata = null; break;
            case "metadata-empty-value": otherMetadata = []; break;
            case "metadata-order": otherMetadata = [new("second", "same-value"), new("first", "same-value")]; break;
            case "metadata-key": otherMetadata = [new("different", "same-value"), new("second", "same-value")]; break;
        }
        using var request = OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Member,
            reverse ? otherRole : role, reverse ? otherActive : active, reverse ? otherMetadata : metadata);
        var approved = OrganizationMembershipOperations.OrganizationMembershipUpdateTarget(Org, Member,
            reverse ? role : otherRole, reverse ? active : otherActive, reverse ? metadata : otherMetadata);
        string body = new JsonObject
        {
            ["membership"] = new JsonObject
            {
                ["id"] = Member,
                ["orgId"] = Org,
                ["role"] = "admin",
                ["createdAt"] = Time,
                ["updatedAt"] = Time
            }
        }.ToJsonString();
        await Execute(request, approved, body, choice == "same" ? SecretStatus.Success : SecretStatus.Denied);
    }

    // I06: offset and limit independently for project identities; offset and direction for org groups.
    [Test]
    [Arguments("project-identities", "same")]
    [Arguments("project-identities", "offset")]
    [Arguments("project-identities", "limit")]
    [Arguments("org-groups", "same")]
    [Arguments("org-groups", "offset")]
    [Arguments("org-groups", "orderDirection")]
    public async Task InventorySelectorRequiresIndependentApproval(string route, string field)
    {
        SecretStatus expected = field == "same" ? SecretStatus.Success : SecretStatus.Denied;
        if (route == "project-identities")
        {
            using var request = IdentityOperations.ListProjectIdentities(Org, Project, 0, 2, "selected");
            var approved = IdentityOperations.ProjectIdentityListTarget(Org, Project,
                field == "offset" ? 1 : 0, field == "limit" ? 3 : 2, "selected");
            await Execute(request, approved, "{\"identities\":[],\"totalCount\":0}", expected);
        }
        else
        {
            using var request = MembershipOperations.ListOrganizationGroups(Org, 0, 2,
                OrganizationGroupOrder.Name, ManagementListOrder.Ascending, "selected");
            var approved = MembershipOperations.OrganizationGroupListTarget(Org, field == "offset" ? 1 : 0, 2,
                OrganizationGroupOrder.Name,
                field == "orderDirection" ? ManagementListOrder.Descending : ManagementListOrder.Ascending, "selected");
            await Execute(request, approved, "{\"groupMemberships\":[],\"totalCount\":0}", expected);
        }
    }

    private static JsonObject Fixture(string route)
    {
        bool identity = route.StartsWith("identity", StringComparison.Ordinal);
        bool primitive = route.EndsWith("delete", StringComparison.Ordinal) || identity;
        var row = new JsonObject
        {
            ["id"] = Member,
            [identity ? "identityId" : "groupId"] = identity ? Identity : Group,
            ["createdAt"] = Time,
            ["updatedAt"] = Time
        };
        if (route == "org-delete") row["orgId"] = Org;
        if (route.StartsWith("project", StringComparison.Ordinal) || identity) row["projectId"] = Project;
        if (!primitive)
        {
            row["group"] = new JsonObject
            {
                ["id"] = Group,
                ["name"] = "selected-group",
                ["slug"] = "selected-group",
                ["orgId"] = Org
            };
            row["roles"] = new JsonArray(new JsonObject
            {
                ["id"] = "role-id",
                ["role"] = "viewer",
                ["isTemporary"] = false
            });
        }
        return route == "project-list" ? new JsonObject { ["groupMemberships"] = new JsonArray(row) }
            : new JsonObject { [identity ? "identityMembership" : "groupMembership"] = row };
    }

    private static void ChangeField(JsonNode root, string path, bool remove, JsonNode? replacement)
    {
        string[] parts = path.Split('.');
        JsonNode parent = root;
        for (int i = 0; i < parts.Length - 1; i++)
        {
            string part = parts[i];
            parent = part.EndsWith("[]", StringComparison.Ordinal) ? parent[part[..^2]]![0]! : parent[part]!;
        }
        string leaf = parts[^1];
        if (leaf.EndsWith("[]", StringComparison.Ordinal)) parent[leaf[..^2]]![0] = replacement;
        else if (remove) parent.AsObject().Remove(leaf);
        else parent[leaf] = replacement;
    }

    private static async Task VerifyResponse(string route, string body, SecretStatus expected)
    {
        if (route == "project-list")
        {
            using var list = MembershipOperations.ListProjectGroups(Org, Project);
            await Execute(list, new(Org, Project), body, expected);
            return;
        }
        using var request = route switch
        {
            "org-delete" => MembershipOperations.RemoveOrganizationGroup(Org, Group),
            "org-get" => MembershipOperations.GetOrganizationGroup(Org, Group),
            "org-update" => MembershipOperations.UpdateOrganizationGroupRoles(Org, Group, [new("viewer")]),
            "org-add" => MembershipOperations.AddOrganizationGroup(Org, Group, [new("viewer")]),
            "project-delete" => MembershipOperations.RemoveProjectGroup(Org, Project, Group),
            "project-add" => MembershipOperations.AddProjectGroup(Org, Project, Group, [new MembershipRole("viewer")]),
            "identity-delete" => MembershipOperations.RemoveProjectIdentity(Org, Project, Identity),
            "identity-update" => MembershipOperations.UpdateProjectIdentityRoles(Org, Project, Identity, [new("viewer")]),
            _ => throw new ArgumentOutOfRangeException(nameof(route))
        };
        ManagementTarget approved = route switch
        {
            "org-delete" or "org-get" => new(Org, resourceId: Group),
            "org-update" or "org-add" => MembershipOperations.RoleChangeTarget(Org, null, Group, new MembershipRole[] { new("viewer") }),
            "project-delete" => new(Org, Project, Group),
            "project-add" => MembershipOperations.RoleChangeTarget(Org, Project, Group, new MembershipRole[] { new("viewer") }),
            "identity-delete" => new(Org, Project, Identity),
            "identity-update" => MembershipOperations.RoleChangeTarget(Org, Project, Identity, new MembershipRole[] { new("viewer") }),
            _ => throw new ArgumentOutOfRangeException(nameof(route))
        };
        await Execute(request, approved, body, expected);
    }

    private static async Task Execute<T>(ManagementRequest<T> request, ManagementTarget approved,
        string body, SecretStatus expected) where T : notnull
    {
        var tokens = new Tokens();
        var wire = new Wire(body);
        using var transport = new ManagementTransport(new Uri("https://management.test"), 64 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, Org, approved.ProjectId);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(expected);
        await Assert.That(tokens.Acquired).IsEqualTo(expected != SecretStatus.Denied);
        await Assert.That(wire.Sent).IsEqualTo(expected != SecretStatus.Denied);
        if (receipt is not null)
            await Assert.That(receipt.Evidence).IsEqualTo(expected == SecretStatus.Denied ? DispatchEvidence.NotDispatched
                : expected == SecretStatus.Success ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }

    private sealed class Wire(string body) : HttpMessageHandler
    {
        public bool Sent { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
        }
    }
}

