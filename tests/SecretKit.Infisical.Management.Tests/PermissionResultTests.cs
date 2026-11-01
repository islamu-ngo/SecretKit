using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class PermissionResultTests
{
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string Id = "22222222-2222-4222-8222-222222222222";
    private const string Project = "33333333-3333-4333-8333-333333333333";
    private const string Identity = "44444444-4444-4444-8444-444444444444";
    private const string Membership = "55555555-5555-4555-8555-555555555555";
    private const string Time = "2026-10-31T00:00:00Z";
    private const string Conditions = """
        {"future-private":{"$unknown":[null,true,42,{"nested-private":["value-private",{},[]]}]},
         "number-private":1.2300e+4,"empty-private":""}
        """;

    [Test]
    public async Task ReturnedRoleConditionsAreAvailableThroughTheClient()
    {
        using var request = ScopedAccessOperations.GetOrganizationRole(Org, Id);
        var result = await Execute(request, new(Org, resourceId: Id), RoleResponse(
            $$"""{"action":["read-private"],"subject":"secrets-private","inverted":false,"conditions":{{Conditions}}}"""));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Permissions![0].HasConditions).IsTrue();
        await Assert.That(result.Value.Permissions[0].IncludesConditionValues).IsTrue();
        await AssertConditions(result.Value.Permissions[0].Conditions, Conditions);
    }

    [Test]
    [Arguments(null)]
    [Arguments("null")]
    [Arguments("{}")]
    [Arguments("[]")]
    [Arguments(Conditions)]
    [Arguments("""[{"future-private":[null,{},[],false]},1.2300e+4,"value-private"]""")]
    [Arguments("\"\\u0076alue-private\"")]
    [Arguments("90071992547409931234567890")]
    [Arguments("true")]
    [Arguments("false")]
    public async Task ReturnedConditionsRemainLosslessAcrossRoleTemplateAndPrivilegeClients(string? json)
    {
        string permission = Permission(json);
        using var roleRequest = ScopedAccessOperations.GetOrganizationRole(Org, Id);
        var role = await Execute(roleRequest, new(Org, resourceId: Id), RoleResponse(permission));
        await Assert.That(role.Status).IsEqualTo(SecretStatus.Success);
        var rolePermission = role.Value.Permissions![0];
        await AssertConditions(rolePermission.Conditions, json);
        await Assert.That(rolePermission.HasConditions).IsEqualTo(json is not null);
        await Assert.That(rolePermission.IncludesConditionValues).IsEqualTo(json is not null and not "null");
        await Assert.That(rolePermission.Action.IsScalar).IsFalse();
        await Assert.That(rolePermission.Action.Values.SequenceEqual(new[] { "read-private", "" })).IsTrue();
        await Assert.That(rolePermission.Subject!.IsScalar).IsTrue();
        await Assert.That(rolePermission.Subject.Values[0]).IsEqualTo("secrets-private");
        await Assert.That(rolePermission.Inverted).IsFalse();

        using var templateRequest = ProjectTemplateOperations.GetProjectTemplate(Org, Id);
        var template = await Execute(templateRequest, new(Org, resourceId: Id), TemplateResponse(permission));
        await Assert.That(template.Status).IsEqualTo(SecretStatus.Success);
        var templatePermission = template.Value.Roles[0].Permissions[0];
        await AssertConditions(templatePermission.Conditions, json);
        await Assert.That(templatePermission.HasConditions).IsEqualTo(json is not null);
        await Assert.That(templatePermission.IncludesConditionValues).IsEqualTo(json is not null and not "null");
        await Assert.That(templatePermission.Action.IsScalar).IsFalse();
        await Assert.That(templatePermission.Action.Values.SequenceEqual(new[] { "read-private", "" })).IsTrue();
        await Assert.That(templatePermission.Subject!.IsScalar).IsTrue();
        await Assert.That(templatePermission.Subject.Values[0]).IsEqualTo("secrets-private");
        await Assert.That(templatePermission.Inverted).IsFalse();

        using var privilegeRequest = IdentityPrivilegeOperations.GetProjectPrivilege(Org, Project, Identity, Id);
        var privilege = await Execute(privilegeRequest, new(Org, Project, Identity, Id), PrivilegeResponse(permission));
        await Assert.That(privilege.Status).IsEqualTo(SecretStatus.Success);
        await AssertConditions(privilege.Value.Permissions![0].Conditions, json);
        await AssertRedacted(privilege);
        await AssertRedacted(privilege.Value);

        var selection = new LegacyPrivilegeSelection(Org, Project, "project-private", Identity, Membership);
        using var legacyRequest = LegacyIdentityPrivilegeOperations.GetPrivilege(selection, "privilege-private");
        var legacy = await Execute(legacyRequest, selection.GrantTarget("privilege-private"),
            PrivilegeResponse(permission, legacy: true));
        await Assert.That(legacy.Status).IsEqualTo(SecretStatus.Success);
        await AssertConditions(legacy.Value.Permissions![0].Conditions, json);
        await AssertRedacted(legacy);
        await AssertRedacted(legacy.Value);
    }

    [Test]
    public async Task ParserSnapshotsOutliveDisposedDocumentsAndClearedResponseStorage()
    {
        string permission = $$"""{"action":"read-private","subject":["first-private",""],"inverted":true,"conditions":{{Conditions}}}""";
        byte[] roleBytes = Encoding.UTF8.GetBytes(RoleResponse(permission));
        byte[] templateBytes = Encoding.UTF8.GetBytes(TemplateResponse(permission));
        RolePermissionSummary role;
        ProjectTemplatePermissionSummary template;
        using (var roleRequest = ScopedAccessOperations.GetOrganizationRole(Org, Id))
        using (var templateRequest = ProjectTemplateOperations.GetProjectTemplate(Org, Id))
        using (var roleDocument = JsonDocument.Parse(roleBytes.AsMemory()))
        using (var templateDocument = JsonDocument.Parse(templateBytes.AsMemory()))
        {
            role = roleRequest.Parse(roleDocument.RootElement).Permissions![0];
            template = templateRequest.Parse(templateDocument.RootElement).Roles[0].Permissions[0];
        }
        Array.Clear(roleBytes);
        Array.Clear(templateBytes);

        await AssertConditions(role.Conditions, Conditions);
        await AssertConditions(template.Conditions, Conditions);
        await Assert.That(role.Action.IsScalar).IsTrue();
        await Assert.That(template.Action.IsScalar).IsTrue();
        await Assert.That(role.Action.Values[0]).IsEqualTo("read-private");
        await Assert.That(template.Action.Values[0]).IsEqualTo("read-private");
        await Assert.That(role.Subject!.IsScalar).IsFalse();
        await Assert.That(template.Subject!.IsScalar).IsFalse();
        await Assert.That(role.Subject.Values.SequenceEqual(new[] { "first-private", "" })).IsTrue();
        await Assert.That(template.Subject.Values.SequenceEqual(new[] { "first-private", "" })).IsTrue();
        await Assert.That(role.Inverted).IsTrue();
        await Assert.That(template.Inverted).IsTrue();
    }

    [Test]
    public async Task ConditionsDoNotInventOmittedSubjectInversionOrInventoryPermissions()
    {
        using var roleRequest = ScopedAccessOperations.GetOrganizationRole(Org, Id);
        var role = await Execute(roleRequest, new(Org, resourceId: Id), RoleResponse("""{"action":"read"}"""));
        await Assert.That(role.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(role.Value.Permissions![0].Subject).IsNull();
        await Assert.That(role.Value.Permissions[0].Inverted).IsNull();
        await AssertConditions(role.Value.Permissions[0].Conditions, null);

        using var templateRequest = ProjectTemplateOperations.GetProjectTemplate(Org, Id);
        var template = await Execute(templateRequest, new(Org, resourceId: Id), TemplateResponse("""{"action":"read"}"""));
        await Assert.That(template.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(template.Value.Roles[0].Permissions[0].Subject).IsNull();
        await Assert.That(template.Value.Roles[0].Permissions[0].Inverted).IsNull();
        await AssertConditions(template.Value.Roles[0].Permissions[0].Conditions, null);

        using var listRequest = IdentityPrivilegeOperations.ListProjectPrivileges(Org, Project, Identity);
        var list = await Execute(listRequest, new(Org, Project, Identity), $$$"""
            {"privileges":[{"id":"{{{Id}}}","slug":"privilege-private","createdAt":"{{{Time}}}","updatedAt":"{{{Time}}}"}]}
            """);
        await Assert.That(list.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(list.Value.Items[0].IncludesPermissions).IsFalse();
        await Assert.That(list.Value.Items[0].Permissions).IsNull();
    }

    [Test]
    [Arguments("""null""")]
    [Arguments("""[]""")]
    [Arguments("""{"conditions":{"private":true}}""")]
    [Arguments("""{"action":null,"conditions":{}}""")]
    [Arguments("""{"action":[null],"conditions":{}}""")]
    [Arguments("""{"action":"read","subject":null,"conditions":{}}""")]
    [Arguments("""{"action":"read","inverted":null,"conditions":{}}""")]
    [Arguments("""{"action":"read","inverted":"private","conditions":{}}""")]
    [Arguments("""{"action":"read","extra-private":true,"conditions":{}}""")]
    [Arguments("""{"action":"read","conditions":{"duplicate-private":1,"duplicate-private":2}}""")]
    public async Task UnconstrainedConditionsDoNotRelaxMalformedOuterContracts(string permission)
    {
        using var roleRequest = ScopedAccessOperations.GetOrganizationRole(Org, Id);
        var role = await Execute(roleRequest, new(Org, resourceId: Id), RoleResponse(permission));
        await Assert.That(role.Status).IsEqualTo(SecretStatus.Unknown);
        await AssertRedacted(role);

        using var templateRequest = ProjectTemplateOperations.GetProjectTemplate(Org, Id);
        var template = await Execute(templateRequest, new(Org, resourceId: Id), TemplateResponse(permission));
        await Assert.That(template.Status).IsEqualTo(SecretStatus.Unknown);
        await AssertRedacted(template);

        using var privilegeRequest = IdentityPrivilegeOperations.GetProjectPrivilege(Org, Project, Identity, Id);
        var privilege = await Execute(privilegeRequest, new(Org, Project, Identity, Id), PrivilegeResponse(permission));
        await Assert.That(privilege.Status).IsEqualTo(SecretStatus.Unknown);
        await AssertRedacted(privilege);

        var selection = new LegacyPrivilegeSelection(Org, Project, "project-private", Identity, Membership);
        using var legacyRequest = LegacyIdentityPrivilegeOperations.GetPrivilege(selection, "privilege-private");
        var legacy = await Execute(legacyRequest, selection.GrantTarget("privilege-private"),
            PrivilegeResponse(permission, legacy: true));
        await Assert.That(legacy.Status).IsEqualTo(SecretStatus.Unknown);
        await AssertRedacted(legacy);
    }

    [Test]
    public async Task SnapshotsAndTheirOwnersDoNotImplicitlyDiscloseReturnedConditions()
    {
        using var roleRequest = ScopedAccessOperations.GetOrganizationRole(Org, Id);
        var role = await Execute(roleRequest, new(Org, resourceId: Id), RoleResponse(Permission(Conditions)));
        await Assert.That(role.Status).IsEqualTo(SecretStatus.Success);
        var permission = role.Value.Permissions![0];
        foreach (object value in new object[]
        {
            role, role.Value, permission, permission.Action, permission.Subject!, permission.Conditions,
            permission.Conditions.Value, new { Returned = permission.Conditions.Value }
        })
            await AssertRedacted(value);

        using var templateRequest = ProjectTemplateOperations.GetProjectTemplate(Org, Id);
        var template = await Execute(templateRequest, new(Org, resourceId: Id), TemplateResponse(Permission(Conditions)));
        await Assert.That(template.Status).IsEqualTo(SecretStatus.Success);
        var templatePermission = template.Value.Roles[0].Permissions[0];
        foreach (object value in new object[]
        {
            template, template.Value, template.Value.Roles[0], templatePermission, templatePermission.Conditions,
            templatePermission.Conditions.Value
        })
            await AssertRedacted(value);

        // Only the deliberate export returns ordinary JSON that can disclose protected values.
        await Assert.That(permission.Conditions.Value.Export().GetProperty("future-private")
            .GetProperty("$unknown")[3].GetProperty("nested-private")[0].GetString()).IsEqualTo("value-private");
    }

    private static async Task AssertConditions(ProjectField<PermissionConditionSnapshot> conditions, string? json)
    {
        await Assert.That(conditions.IsPresent).IsEqualTo(json is not null);
        await Assert.That(conditions.IsNull).IsEqualTo(json == "null");
        if (json is null or "null")
        {
            await Assert.That(() => conditions.Value).Throws<InvalidOperationException>();
            return;
        }
        using var expected = JsonDocument.Parse(json);
        JsonElement exported = conditions.Value.Export();
        await Assert.That(conditions.Value.Kind).IsEqualTo(expected.RootElement.ValueKind);
        await Assert.That(exported.GetRawText()).IsEqualTo(json);
        await Assert.That(JsonElement.DeepEquals(exported, expected.RootElement)).IsTrue();
    }

    private static async Task AssertRedacted(object value)
    {
        await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(value.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    private static string Permission(string? conditions) =>
        """{"action":["read-private",""],"subject":"secrets-private","inverted":false""" +
        (conditions is null ? "" : ",\"conditions\":" + conditions) + "}";

    private static string RoleResponse(string permission) => $$$"""
        {"role":{"id":"{{{Id}}}","orgId":"{{{Org}}}","name":"role-private","slug":"role-private",
        "createdAt":"{{{Time}}}","updatedAt":"{{{Time}}}","permissions":[{{{permission}}}]}}
        """;

    private static string TemplateResponse(string permission) => $$$"""
        {"projectTemplate":{"id":"{{{Id}}}","orgId":"{{{Org}}}","name":"template-private",
        "createdAt":"{{{Time}}}","updatedAt":"{{{Time}}}",
        "roles":[{"name":"role-private","slug":"role-private","permissions":[{{{permission}}}]}],
        "environments":[],"users":[],"groups":[],"identities":[],"projectManagedIdentities":[]}}
        """;

    private static string PrivilegeResponse(string permission, bool legacy = false) => $$$"""
        {"privilege":{"id":"{{{Id}}}","slug":"privilege-private","createdAt":"{{{Time}}}","updatedAt":"{{{Time}}}",
        {{{(legacy ? "\"projectMembershipId\":\"" + Membership + "\"," : "")}}}"permissions":[{{{permission}}}]}}
        """;

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request,
        ManagementTarget target, string response) where T : notnull
    {
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024,
            null, false, new Wire(response));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, target.ProjectId);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("offline-token"))));
    }

    private sealed class Wire(string response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response) });
    }
}
