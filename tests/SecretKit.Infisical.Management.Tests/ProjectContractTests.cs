using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ProjectContractTests
{
    private const string Org = "0000000a-0000-0000-0000-00000000000a";
    private const string OtherOrg = "0000000b-0000-0000-0000-00000000000b";
    private const string Environment = "0000001e-0000-0000-0000-00000000001e";
    private const string Tag = "0000001f-0000-0000-0000-00000000001f";
    private const string Creator = "00000020-0000-0000-0000-000000000020";
    private const string DeletedIdentity = "00000021-0000-0000-0000-000000000021";
    private const string DeletedUser = "00000022-0000-0000-0000-000000000022";
    private const string CertificateKey = "00000023-0000-0000-0000-000000000023";
    private const string SecretKey = "00000024-0000-0000-0000-000000000024";
    private const string Role = "00000025-0000-0000-0000-000000000025";

    [Test]
    public async Task FractionalEnvironmentResultIsAnEstablishedNumber()
    {
        using var transport = Transport(new Server($$$"""
            {"environment":{"id":"{{{Environment}}}","projectId":"project","name":"private-env","slug":"dev",
            "position":1.5,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z"}}
            """));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
        using var request = ProjectOperations.GetEnvironment(Org, "project", Environment);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org, "project", Environment)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(Convert.ToDouble(result.Value.Position)).IsEqualTo(1.5);
    }

    [Test]
    public async Task DifferentProjectChangeCannotUseAnIndependentSelectedInputGrant()
    {
        var server = new Server(ProjectResponse);
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, "project");
        using var expected = ProjectOperations.UpdateProject(Org, "project", secretSharing: false);
        using var incoming = ProjectOperations.UpdateProject(Org, "project", secretSharing: true);
        var receipt = client.CreateReceipt(incoming);
        var result = await client.ExecuteAsync(incoming, authority,
            authority.IssueGrant(incoming.OperationId, expected.Target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(server.Dispatched).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    public async Task KnownMalformedProjectSettingsAreNotSilentlyDropped()
    {
        using var transport = Transport(new Server($$$"""
            {"project":{"id":"project","orgId":"{{{Org}}}","type":"secret-manager","name":"private-project",
            "slug":"project","hasDeleteProtection":"false"}}
            """));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
        using var request = ProjectOperations.GetProject(Org, "project");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org, "project")));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments(ProjectType.SecretManager)]
    [Arguments(ProjectType.CertificateManager)]
    [Arguments(ProjectType.Kms)]
    [Arguments(ProjectType.SecretScanning)]
    [Arguments(ProjectType.Pam)]
    [Arguments(ProjectType.AgentVault)]
    [Arguments(null)]
    public async Task EveryListTypeAndRoleSelectionHasExactWireAndIndependentIntent(ProjectType? type)
    {
        foreach (bool? roles in new bool?[] { null, false, true })
        {
            string? wireType = type switch
            {
                ProjectType.SecretManager => "secret-manager",
                ProjectType.CertificateManager => "cert-manager",
                ProjectType.Kms => "kms",
                ProjectType.SecretScanning => "secret-scanning",
                ProjectType.Pam => "pam",
                ProjectType.AgentVault => "agent-vault",
                _ => null
            };
            var state = FullProject();
            state["type"] = wireType ?? "kms";
            var server = new StatefulServer(state);
            using var transport = Transport(server);
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
            using var request = ProjectOperations.ListProjects(Org, type, roles);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
                ProjectOperations.ProjectListTarget(Org, type, roles)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Items[0].Type).IsEqualTo(wireType ?? "kms");
            await Assert.That(server.Query!.ContainsKey("type")).IsEqualTo(type is not null);
            if (type is not null) await Assert.That(server.Query["type"]).IsEqualTo(wireType);
            await Assert.That(server.Query.ContainsKey("includeRoles")).IsEqualTo(roles is not null);
            if (roles is not null) await Assert.That(server.Query["includeRoles"]).IsEqualTo(roles.Value ? "true" : "false");
            await AssertProjectMetadata(result.Value.Items[0], true);
            var role = result.Value.Items[0].Roles.Value[0];
            await Assert.That(role.Id).IsEqualTo(Role);
            await Assert.That(role.Name).IsEqualTo("private-role");
            await Assert.That(role.Slug).IsEqualTo("reader");
            await Assert.That(role.Description.IsNull).IsTrue();
            await Assert.That(role.CreatedAt).IsEqualTo("2026-01-01T00:00:00Z");
            await Assert.That(role.UpdatedAt).IsEqualTo("2026-01-02T00:00:00Z");
            await Assert.That(role.Version.Value).IsEqualTo(1.5);
            await Assert.That(role.HasPermissions).IsTrue();
            await Assert.That(role.IncludesPermissionValues).IsFalse();
            await AssertProtected(role);
        }
    }

    [Test]
    public async Task DefaultListProjectsAllKnownNestedMetadataWithoutEffectivePermissionClaims()
    {
        var server = new StatefulServer(FullProject());
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = ProjectOperations.ListProjects(Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectOperations.ProjectListTarget(Org)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await AssertProjectMetadata(result.Value.Items[0], true);
        var role = result.Value.Items[0].Roles.Value[0];
        await Assert.That(role.Id).IsEqualTo(Role);
        await Assert.That(role.Name).IsEqualTo("private-role");
        await Assert.That(role.Slug).IsEqualTo("reader");
        await Assert.That(role.CreatedAt).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(role.UpdatedAt).IsEqualTo("2026-01-02T00:00:00Z");
        await Assert.That(role.Version.Value).IsEqualTo(1.5);
        await Assert.That(role.Description.IsNull).IsTrue();
        await Assert.That(role.HasPermissions).IsTrue();
        await Assert.That(role.PermissionsIsNull).IsFalse();
        await Assert.That(role.IncludesPermissionValues).IsFalse();
        await AssertProtected(role);
    }

    [Test]
    [Arguments("type")]
    [Arguments("roles")]
    [Arguments("omittedType")]
    [Arguments("omittedRoles")]
    public async Task DifferentListSelectorGrantIsDeniedBeforeTokenAcquisition(string changed)
    {
        var server = new Server("""{"projects":[]}""");
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var request = ProjectOperations.ListProjects(Org,
            changed == "omittedType" ? null : changed == "type" ? ProjectType.Kms : ProjectType.SecretManager,
            changed == "omittedRoles" ? null : changed == "roles");
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectOperations.ProjectListTarget(Org)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(server.Dispatched).IsFalse();
    }

    [Test]
    [Arguments("get")]
    [Arguments("slug")]
    [Arguments("create")]
    [Arguments("update")]
    [Arguments("delete")]
    public async Task EachProjectEndpointProjectsOnlyItsEstablishedMetadata(string operation)
    {
        var server = new StatefulServer(FullProject());
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org,
            operation is "create" or "slug" ? null : "project");
        using var request = operation switch
        {
            "get" => ProjectOperations.GetProject(Org, "project"),
            "slug" => ProjectOperations.GetProjectBySlug(Org, "project"),
            "create" => ProjectOperations.CreateProject(Org, "private-project", "project"),
            "update" => ProjectOperations.UpdateProject(Org, "project", secretSharing: false),
            _ => ProjectOperations.DeleteProject(Org, "project")
        };
        var target = operation switch
        {
            "create" => ProjectOperations.ProjectCreateTarget(Org, "private-project", "project"),
            "update" => ProjectOperations.ProjectUpdateTarget(Org, "project", secretSharing: false),
            "slug" => new(Org, resourceId: "project"),
            _ => new ManagementTarget(Org, "project")
        };
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await AssertProjectMetadata(result.Value, operation is "get" or "slug" or "create");
        await Assert.That(result.Value.Roles.IsPresent).IsFalse();
        foreach (string field in operation is "update" or "delete"
            ? new[] { "roles", "_id", "environments", "deletedEnvironments" } : new[] { "roles" })
        {
            server.ExcludedMember = field;
            var rejectedReceipt = request.IsMutation ? client.CreateReceipt(request) : null;
            var rejected = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, target), rejectedReceipt);
            await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Unknown);
            if (rejectedReceipt is not null)
                await Assert.That(rejectedReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
    }

    [Test]
    [Arguments("name")]
    [Arguments("slug")]
    [Arguments("description")]
    [Arguments("deleteProtection")]
    [Arguments("retention")]
    [Arguments("sharing")]
    [Arguments("capitalization")]
    [Arguments("encryption")]
    [Arguments("versionLimit")]
    [Arguments("snapshots")]
    [Arguments("ignoreValues")]
    public async Task EveryProjectUpdateFieldParticipatesInWholeChangeGrant(string changed)
    {
        using var incoming = ProjectOperations.UpdateProject(Org, "project",
            name: changed == "name" ? "other" : "private-project", slug: changed == "slug" ? "other" : "project",
            description: changed == "description" ? "other" : "", deleteProtection: changed == "deleteProtection",
            auditRetentionDays: changed == "retention" ? 31 : 30, secretSharing: changed == "sharing",
            autoCapitalization: changed == "capitalization", encryptedMetadata: changed == "encryption",
            pointInTimeVersionLimit: changed == "versionLimit" ? 11 : 10, showLegacySnapshots: changed == "snapshots",
            secretDetectionIgnoreValues: changed == "ignoreValues" ? ["other"] : ["private-value"]);
        var target = ProjectOperations.ProjectUpdateTarget(Org, "project", name: "private-project", slug: "project",
            description: "", deleteProtection: false, auditRetentionDays: 30, secretSharing: false,
            autoCapitalization: false, encryptedMetadata: false, pointInTimeVersionLimit: 10,
            showLegacySnapshots: false, secretDetectionIgnoreValues: ["private-value"]);
        await AssertDeniedChange(incoming, target, "project");
    }

    [Test]
    [Arguments("name")]
    [Arguments("slug")]
    [Arguments("description")]
    [Arguments("deleteProtection")]
    [Arguments("environments")]
    [Arguments("template")]
    [Arguments("kmsKey")]
    public async Task EveryProjectCreateFieldParticipatesInWholeChangeGrant(string changed)
    {
        using var incoming = ProjectOperations.CreateProject(Org,
            changed == "name" ? "other" : "private-project", changed == "slug" ? "other-slug" : "project",
            changed == "description" ? "other" : "private-description", changed == "deleteProtection",
            changed != "environments", changed == "template" ? "other" : "private-template",
            changed == "kmsKey" ? "other" : "private-kms");
        var target = ProjectOperations.ProjectCreateTarget(Org, "private-project", "project",
            "private-description", false, true, "private-template", "private-kms");
        await AssertDeniedChange(incoming, target, null);
    }

    [Test]
    public async Task CopiedIgnoreValuesPersistAndOmittedEmptyFalseRemainDistinct()
    {
        var server = new StatefulServer(FullProject());
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
        string[] values = ["", "private-value\nline", "\u2603"];
        using var request = ProjectOperations.UpdateProject(Org, "project", secretDetectionIgnoreValues: values);
        values[1] = "attacker";
        byte[] copy = request.CopyBody()!;
        Array.Fill(copy, (byte)0);
        Array.Clear(copy);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectOperations.ProjectUpdateTarget(Org, "project", secretDetectionIgnoreValues: ["", "private-value\nline", "\u2603"])),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(server.Body!.Count).IsEqualTo(1);
        await Assert.That(result.Value.SecretDetectionIgnoreValues.Value[1]).IsEqualTo("private-value\nline");
        using var read = ProjectOperations.GetProject(Org, "project");
        var fresh = await client.ExecuteAsync(read, authority, authority.IssueGrant(read.OperationId, new(Org, "project")));
        await Assert.That(fresh.Value.SecretDetectionIgnoreValues.Value[1]).IsEqualTo("private-value\nline");
        await AssertProtected(result.Value);

        using var clear = ProjectOperations.UpdateProject(Org, "project", secretSharing: false, secretDetectionIgnoreValues: []);
        var cleared = await client.ExecuteAsync(clear, authority, authority.IssueGrant(clear.OperationId,
            ProjectOperations.ProjectUpdateTarget(Org, "project", secretSharing: false, secretDetectionIgnoreValues: [])),
            client.CreateReceipt(clear));
        await Assert.That(cleared.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(cleared.Value.SecretDetectionIgnoreValues.Value.Count).IsEqualTo(0);
        await Assert.That(cleared.Value.SecretSharing.Value).IsFalse();
        await Assert.That(server.Body!.Count).IsEqualTo(2);
        using var omitted = ProjectOperations.UpdateProject(Org, "project", description: "");
        byte[] omittedBytes = omitted.CopyBody()!;
        try
        {
            using var body = JsonDocument.Parse(omittedBytes);
            await Assert.That(body.RootElement.TryGetProperty("secretDetectionIgnoreValues", out _)).IsFalse();
            await Assert.That(body.RootElement.TryGetProperty("secretSharing", out _)).IsFalse();
            await Assert.That(body.RootElement.GetProperty("description").GetString()).IsEqualTo("");
        }
        finally { Array.Clear(omittedBytes); }
        await AssertDeniedChange(clear,
            ProjectOperations.ProjectUpdateTarget(Org, "project", secretSharing: false), "project");
    }

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("value")]
    public async Task OptionalResultFieldsPreservePresenceAndNativeNullability(string shape)
    {
        var state = FullProject();
        foreach (string field in new[] { "description", "auditLogsRetentionDays", "autoCapitalization", "defaultProduct",
            "kmsCertificateKeyId", "kmsSecretManagerKeyId", "hasDeleteProtection",
            "enforceEncryptedSecretManagerSecretMetadata", "secretDetectionIgnoreValues", "upgradeStatus" })
        {
            if (shape == "absent") state.Remove(field);
            else if (shape == "null") state[field] = null;
        }
        using var transport = Transport(new StatefulServer(state));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
        using var request = ProjectOperations.GetProject(Org, "project");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org, "project")));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var value = result.Value;
        bool present = shape != "absent", nil = shape == "null";
        foreach (bool actual in new[] { value.DescriptionField.IsPresent, value.AuditLogsRetentionDays.IsPresent,
            value.AutoCapitalization.IsPresent, value.DefaultProduct.IsPresent, value.KmsCertificateKeyId.IsPresent,
            value.KmsSecretManagerKeyId.IsPresent, value.HasDeleteProtection.IsPresent,
            value.EnforceEncryptedSecretManagerSecretMetadata.IsPresent, value.SecretDetectionIgnoreValues.IsPresent,
            value.UpgradeStatus.IsPresent })
            await Assert.That(actual).IsEqualTo(present);
        foreach (bool actual in new[] { value.DescriptionField.IsNull, value.AuditLogsRetentionDays.IsNull,
            value.AutoCapitalization.IsNull, value.DefaultProduct.IsNull, value.KmsCertificateKeyId.IsNull,
            value.KmsSecretManagerKeyId.IsNull, value.HasDeleteProtection.IsNull,
            value.EnforceEncryptedSecretManagerSecretMetadata.IsNull, value.SecretDetectionIgnoreValues.IsNull,
            value.UpgradeStatus.IsNull })
            await Assert.That(actual).IsEqualTo(nil);
        if (shape == "value")
        {
            await Assert.That(value.DescriptionField.Value).IsEqualTo("");
            await Assert.That(value.AutoCapitalization.Value).IsFalse();
        }
        else await Assert.That(() => value.AutoCapitalization.Value).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("get")]
    [Arguments("slug")]
    [Arguments("create")]
    [Arguments("update")]
    [Arguments("delete")]
    [Arguments("restore")]
    public async Task EachEnvironmentEndpointPreservesNumberAndDeletionMetadata(string operation)
    {
        double position = operation == "update" ? -0.5 : 1.5;
        var environment = FullEnvironment(position);
        var server = new StatefulServer(FullProject(), environment);
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
        using var request = operation switch
        {
            "get" => ProjectOperations.GetEnvironment(Org, "project", Environment),
            "slug" => ProjectOperations.GetEnvironmentBySlug(Org, "project", "dev"),
            "create" => ProjectOperations.CreateEnvironment(Org, "project", "private-env", "dev", position),
            "update" => ProjectOperations.UpdateEnvironment(Org, "project", Environment, position: position),
            "delete" => ProjectOperations.DeleteEnvironment(Org, "project", Environment),
            _ => ProjectOperations.RestoreEnvironment(Org, "project", Environment)
        };
        var target = operation switch
        {
            "create" => ProjectOperations.EnvironmentCreateTarget(Org, "project", "private-env", "dev", position),
            "update" => ProjectOperations.EnvironmentUpdateTarget(Org, "project", Environment, position: position),
            "slug" => new(Org, "project", "dev"),
            "delete" => new(Org, "project", Environment, "soft-delete"),
            _ => new ManagementTarget(Org, "project", Environment)
        };
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Position).IsEqualTo(position);
        await Assert.That(result.Value.CreatedAt.Value).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(result.Value.UpdatedAt.Value).IsEqualTo("2026-01-02T00:00:00Z");
        await Assert.That(result.Value.DeletedByUserId.IsNull).IsTrue();
        await Assert.That(result.Value.DeletedByIdentityId.Value).IsEqualTo(DeletedIdentity);
        await Assert.That(result.Value.DeleteAfterField.IsNull).IsTrue();
        await Assert.That(result.Value.SoftDeletedAtField.IsNull).IsTrue();
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        if (operation is "create" or "update")
            await Assert.That(server.Body!["position"]!.GetValue<double>()).IsEqualTo(position);
        await AssertProtected(result.Value);
        if (operation is "get" or "slug")
        {
            foreach (string field in new[] { "projectId", "message" })
            {
                server.ExcludedMember = field;
                var rejected = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
                await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Unknown);
            }
        }
    }

    [Test]
    [Arguments("list")]
    [Arguments("get")]
    [Arguments("slug")]
    [Arguments("create")]
    [Arguments("update")]
    [Arguments("delete")]
    public async Task EachTagEndpointProjectsKnownCreatorMetadata(string operation)
    {
        var server = new StatefulServer(FullProject());
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
        ProjectTag value;
        if (operation == "list")
        {
            using var request = ProjectOperations.ListTags(Org, "project");
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, "project")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            value = result.Value.Items[0];
        }
        else
        {
            using var request = operation switch
            {
                "get" => ProjectOperations.GetTag(Org, "project", Tag),
                "slug" => ProjectOperations.GetTagBySlug(Org, "project", "private-tag"),
                "create" => ProjectOperations.CreateTag(Org, "project", "private-tag", "blue"),
                "update" => ProjectOperations.UpdateTag(Org, "project", Tag, "private-tag", "blue"),
                _ => ProjectOperations.DeleteTag(Org, "project", Tag)
            };
            var target = operation switch
            {
                "create" => ProjectOperations.TagCreateTarget(Org, "project", "private-tag", "blue"),
                "update" => ProjectOperations.TagUpdateTarget(Org, "project", Tag, "private-tag", "blue"),
                "slug" => new(Org, "project", "private-tag"),
                _ => new ManagementTarget(Org, "project", Tag)
            };
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target),
                request.IsMutation ? client.CreateReceipt(request) : null);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            value = result.Value;
        }
        await Assert.That(value.Color).IsEqualTo("blue");
        await Assert.That(value.Name).IsEqualTo(operation is "get" or "slug" ? "private-tag-name" : null);
        await Assert.That(value.CreatedAt.Value).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(value.UpdatedAt.Value).IsEqualTo("2026-01-02T00:00:00Z");
        await Assert.That(value.CreatedBy.Value).IsEqualTo(Creator);
        await Assert.That(value.CreatedByActorType.Value).IsEqualTo("identity");
        await AssertProtected(value);
        if (operation is not ("get" or "slug"))
        {
            server.ExcludedMember = "name";
            if (operation == "list")
            {
                using var request = ProjectOperations.ListTags(Org, "project");
                var rejected = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, new(Org, "project")));
                await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Unknown);
            }
            else
            {
                using var request = operation switch
                {
                    "create" => ProjectOperations.CreateTag(Org, "project", "private-tag", "blue"),
                    "update" => ProjectOperations.UpdateTag(Org, "project", Tag, "private-tag", "blue"),
                    _ => ProjectOperations.DeleteTag(Org, "project", Tag)
                };
                var target = operation switch
                {
                    "create" => ProjectOperations.TagCreateTarget(Org, "project", "private-tag", "blue"),
                    "update" => ProjectOperations.TagUpdateTarget(Org, "project", Tag, "private-tag", "blue"),
                    _ => new ManagementTarget(Org, "project", Tag)
                };
                var receipt = client.CreateReceipt(request);
                var rejected = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, target), receipt);
                await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Unknown);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            }
        }
    }

    [Test]
    [Arguments("create")]
    [Arguments("update")]
    public async Task EnvironmentGrantBindsEachNameSlugAndFractionalPosition(string operation)
    {
        foreach (string field in new[] { "name", "slug", "position" })
        {
            using var request = operation == "create"
                ? ProjectOperations.CreateEnvironment(Org, "project", field == "name" ? "other" : "private-env",
                    field == "slug" ? "other" : "dev", field == "position" ? 2.5 : 1.5)
                : ProjectOperations.UpdateEnvironment(Org, "project", Environment, field == "name" ? "other" : "private-env",
                    field == "slug" ? "other" : "dev", field == "position" ? 2.5 : 1.5);
            var target = operation == "create"
                ? ProjectOperations.EnvironmentCreateTarget(Org, "project", "private-env", "dev", 1.5)
                : ProjectOperations.EnvironmentUpdateTarget(Org, "project", Environment, "private-env", "dev", 1.5);
            await AssertDeniedChange(request, target, "project");
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationKeepsNativeReceiptEvidenceAndCannotReplay(bool duringDispatch)
    {
        var server = new StatefulServer(FullProject()) { Hold = duringDispatch };
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, "project");
        using var request = ProjectOperations.UpdateProject(Org, "project", secretDetectionIgnoreValues: []);
        var grant = authority.IssueGrant(request.OperationId,
            ProjectOperations.ProjectUpdateTarget(Org, "project", secretDetectionIgnoreValues: []));
        var receipt = client.CreateReceipt(request);
        using var cancellation = new CancellationTokenSource();
        if (!duringDispatch) cancellation.Cancel();
        var entered = server.Entered.Task;
        var pending = client.ExecuteAsync(request, authority, grant, receipt, cancellation.Token).AsTask();
        if (duringDispatch)
        {
            await entered.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
        }
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(
            duringDispatch ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.NotDispatched);
        if (duringDispatch)
        {
            var replay = await client.ExecuteAsync(request, authority, grant, receipt);
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        }
        else await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    [Arguments("orgId")]
    [Arguments("id")]
    [Arguments("type")]
    [Arguments("slug")]
    public async Task NativeProjectScopeMismatchIsInvalid(string field)
    {
        var state = FullProject();
        state[field] = field == "orgId" ? OtherOrg : "wrong";
        using var transport = Transport(new StatefulServer(state));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = ProjectOperations.GetProjectBySlug(Org, "project");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org, resourceId: "project")));
        await Assert.That(result.Status).IsEqualTo(field == "id" ? SecretStatus.Success : SecretStatus.Invalid);
    }

    [Test]
    public async Task FiniteNumberAndLocalCollectionByteBudgetsAreExplicit()
    {
        foreach (double value in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity })
        {
            await Assert.That(() => ProjectOperations.CreateEnvironment(Org, "project", "env", "dev", value))
                .Throws<ArgumentException>();
            await Assert.That(() => ProjectOperations.UpdateEnvironment(Org, "project", Environment, position: value))
                .Throws<ArgumentException>();
        }
        await Assert.That(() => ProjectOperations.CreateEnvironment(Org, "project", "env", "dev", 0.5))
            .Throws<ArgumentException>();
        using var large = ProjectOperations.CreateEnvironment(Org, "project", "env", "dev", double.MaxValue);
        using var negative = ProjectOperations.UpdateEnvironment(Org, "project", Environment, position: -double.MaxValue);
        await Assert.That(() => ProjectOperations.ListProjects(Org, (ProjectType)999)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => ProjectOperations.UpdateProject(Org, "project",
            secretDetectionIgnoreValues: Enumerable.Repeat("", 1001).ToArray())).Throws<ArgumentException>();
        await Assert.That(() => ProjectOperations.UpdateProject(Org, "project",
            secretDetectionIgnoreValues: [null!])).Throws<ArgumentException>();
        await Assert.That(() => ProjectOperations.UpdateProject(Org, "project",
            secretDetectionIgnoreValues: [new string('x', 16385)])).Throws<ArgumentException>();
        await Assert.That(() => ProjectOperations.UpdateProject(Org, "project",
            secretDetectionIgnoreValues: Enumerable.Repeat(new string('x', 16384), 5).ToArray())).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("createdAt")]
    [Arguments("hasDeleteProtection")]
    [Arguments("version")]
    [Arguments("secretDetectionIgnoreValues")]
    [Arguments("environments")]
    [Arguments("deletedEnvironments")]
    [Arguments("deletedBy")]
    [Arguments("userField")]
    [Arguments("roleScope")]
    [Arguments("roles")]
    public async Task KnownMalformedNestedListMetadataFailsClosed(string field)
    {
        var state = FullProject();
        switch (field)
        {
            case "createdAt": state[field] = false; break;
            case "hasDeleteProtection": state[field] = "false"; break;
            case "version": state[field] = JsonNode.Parse("1e400"); break;
            case "secretDetectionIgnoreValues": state[field] = new JsonArray(false); break;
            case "environments": state[field] = new JsonArray(new JsonObject { ["id"] = "env" }); break;
            case "deletedEnvironments": state[field] = null; break;
            case "deletedBy": state["deletedEnvironments"]![0]!["deletedBy"]!["type"] = "unknown"; break;
            case "userField": state["deletedEnvironments"]![1]!["deletedBy"]!.AsObject().Remove("email"); break;
            case "roleScope": state["roles"]![0]!["projectId"] = "other"; break;
            case "roles": state[field] = null; break;
        }
        using var transport = Transport(new StatefulServer(state));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = ProjectOperations.ListProjects(Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectOperations.ProjectListTarget(Org)));
        await Assert.That(result.Status).IsEqualTo(field == "roleScope" ? SecretStatus.Invalid : SecretStatus.Unknown);
    }

    [Test]
    [Arguments("absent")]
    [Arguments("empty")]
    [Arguments("permissionNull")]
    public async Task ListCollectionAbsenceEmptyAndUnknownPermissionNullAreExplicit(string shape)
    {
        var state = FullProject();
        if (shape == "permissionNull") state["roles"]![0]!["permissions"] = null;
        else
            foreach (string field in new[] { "environments", "deletedEnvironments", "roles", "secretDetectionIgnoreValues" })
                if (shape == "absent") state.Remove(field);
                else state[field] = new JsonArray();
        using var transport = Transport(new StatefulServer(state));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = ProjectOperations.ListProjects(Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectOperations.ProjectListTarget(Org)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var value = result.Value.Items[0];
        if (shape == "permissionNull")
        {
            await Assert.That(value.Roles.Value[0].HasPermissions).IsTrue();
            await Assert.That(value.Roles.Value[0].PermissionsIsNull).IsTrue();
            await Assert.That(value.Roles.Value[0].IncludesPermissionValues).IsFalse();
        }
        else
        {
            foreach (bool actual in new[] { value.Environments.IsPresent, value.DeletedEnvironments.IsPresent,
                value.Roles.IsPresent, value.SecretDetectionIgnoreValues.IsPresent })
                await Assert.That(actual).IsEqualTo(shape == "empty");
            if (shape == "empty")
            {
                await Assert.That(value.Environments.Value.Count).IsEqualTo(0);
                await Assert.That(value.DeletedEnvironments.Value.Count).IsEqualTo(0);
                await Assert.That(value.Roles.Value.Count).IsEqualTo(0);
                await Assert.That(value.SecretDetectionIgnoreValues.Value.Count).IsEqualTo(0);
            }
        }
    }

    [Test]
    [Arguments("position")]
    [Arguments("createdAt")]
    [Arguments("deletedByUserId")]
    [Arguments("scope")]
    public async Task MalformedEnvironmentResultsNeverAcknowledgeMutation(string field)
    {
        var environment = FullEnvironment(1.5);
        if (field == "scope") environment["projectId"] = "other";
        else environment[field] = field == "position" ? JsonNode.Parse("1e400") : JsonValue.Create(false);
        using var transport = Transport(new StatefulServer(FullProject(), environment));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
        // Omit a body update of the field under test when it is the returned position.
        using var incoming = field == "position"
            ? ProjectOperations.UpdateEnvironment(Org, "project", Environment, name: "private-env")
            : ProjectOperations.UpdateEnvironment(Org, "project", Environment, position: 1.5);
        var target = field == "position"
            ? ProjectOperations.EnvironmentUpdateTarget(Org, "project", Environment, name: "private-env")
            : ProjectOperations.EnvironmentUpdateTarget(Org, "project", Environment, position: 1.5);
        var receipt = client.CreateReceipt(incoming);
        var result = await client.ExecuteAsync(incoming, authority, authority.IssueGrant(incoming.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(field == "scope" ? SecretStatus.Invalid : SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task NativeOmittedPositionAndEmptyDescriptionHaveExactEncoding()
    {
        using var create = ProjectOperations.CreateEnvironment(Org, "project", "env", "dev");
        byte[] bytes = create.CopyBody()!;
        try
        {
            using var body = JsonDocument.Parse(bytes);
            await Assert.That(body.RootElement.TryGetProperty("position", out _)).IsFalse();
        }
        finally { Array.Clear(bytes); }
        using var project = ProjectOperations.CreateProject(Org, "name", "project", description: "");
        byte[] projectBytes = project.CopyBody()!;
        try
        {
            using var body = JsonDocument.Parse(projectBytes);
            await Assert.That(body.RootElement.GetProperty("projectDescription").GetString()).IsEqualTo("");
            await Assert.That(body.RootElement.TryGetProperty("template", out _)).IsFalse();
            await Assert.That(body.RootElement.TryGetProperty("kmsKeyId", out _)).IsFalse();
        }
        finally { Array.Clear(projectBytes); }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TagMutationGrantBindsBothSlugAndColor(bool update)
    {
        foreach (bool changeColor in new[] { false, true })
        {
            using var request = update
                ? ProjectOperations.UpdateTag(Org, "project", Tag, changeColor ? "tag" : "other", changeColor ? "red" : "blue")
                : ProjectOperations.CreateTag(Org, "project", changeColor ? "tag" : "other", changeColor ? "red" : "blue");
            var target = update ? ProjectOperations.TagUpdateTarget(Org, "project", Tag, "tag", "blue")
                : ProjectOperations.TagCreateTarget(Org, "project", "tag", "blue");
            await AssertDeniedChange(request, target, "project");
        }
    }

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("empty")]
    public async Task EnvironmentAndTagNullableCoordinatesPreserveTheirPresence(string shape)
    {
        var environment = FullEnvironment(0.5);
        foreach (string field in new[] { "deleteAfter", "softDeletedAt", "deletedByUserId", "deletedByIdentityId" })
        {
            if (shape == "absent") environment.Remove(field);
            else environment[field] = shape == "null" ? null :
                field == "deletedByUserId" ? DeletedUser : field == "deletedByIdentityId" ? DeletedIdentity :
                "2026-01-03T03:04:05+02:30";
        }
        using var transport = Transport(new StatefulServer(FullProject(), environment));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
        using var request = ProjectOperations.GetEnvironment(Org, "project", Environment);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org, "project", Environment)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        foreach (var field in new[] { result.Value.DeleteAfterField, result.Value.SoftDeletedAtField })
        {
            await Assert.That(field.IsPresent).IsEqualTo(shape != "absent");
            await Assert.That(field.IsNull).IsEqualTo(shape == "null");
            if (shape == "empty") await Assert.That(field.Value).IsEqualTo("2026-01-03T03:04:05+02:30");
        }
        foreach (var (field, coordinate) in new[] { (result.Value.DeletedByUserId, DeletedUser),
            (result.Value.DeletedByIdentityId, DeletedIdentity) })
        {
            await Assert.That(field.IsPresent).IsEqualTo(shape != "absent");
            await Assert.That(field.IsNull).IsEqualTo(shape == "null");
            if (shape == "empty") await Assert.That(field.Value).IsEqualTo(coordinate);
        }
        if (shape == "empty")
        {
            foreach (string field in new[] { "deleteAfter", "softDeletedAt" })
            {
                environment[field] = "";
                var invalid = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, new(Org, "project", Environment)));
                await Assert.That(invalid.Status).IsEqualTo(SecretStatus.Unknown);
                environment[field] = "2026-01-03T03:04:05+02:30";
            }
            foreach (string field in new[] { "deletedByUserId", "deletedByIdentityId" })
            {
                environment[field] = "";
                var invalid = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, new(Org, "project", Environment)));
                await Assert.That(invalid.Status).IsEqualTo(SecretStatus.Unknown);
                environment[field] = field == "deletedByUserId" ? DeletedUser : DeletedIdentity;
            }
        }
        var tag = JsonNode.Parse($$$"""{"id":"{{{Tag}}}","slug":"tag","name":"private-tag","projectId":"project","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}""")!.AsObject();
        if (shape != "absent")
        {
            tag["color"] = shape == "null" ? null : "";
            tag["createdBy"] = shape == "null" ? null : Creator;
        }
        using var getTag = ProjectOperations.GetTag(Org, "project", Tag);
        using var response = JsonDocument.Parse(new JsonObject { ["tag"] = tag }.ToJsonString());
        var value = getTag.Parse(response.RootElement);
        await Assert.That(value.ColorField.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(value.ColorField.IsNull).IsEqualTo(shape == "null");
        if (shape == "empty") await Assert.That(value.ColorField.Value).IsEqualTo("");
        await Assert.That(value.CreatedBy.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(value.CreatedBy.IsNull).IsEqualTo(shape == "null");
        if (shape == "empty")
        {
            await Assert.That(value.CreatedBy.Value).IsEqualTo(Creator);
            tag["createdBy"] = "";
            using var invalidTransport = Transport(new Server(new JsonObject { ["tag"] = tag.DeepClone() }.ToJsonString()));
            var invalidClient = new ManagementClient(invalidTransport);
            var invalidAuthority = new ManagementAuthority(invalidClient.Authority, new Tokens(), Org, "project");
            var invalid = await invalidClient.ExecuteAsync(getTag, invalidAuthority,
                invalidAuthority.IssueGrant(getTag.OperationId, new(Org, "project", Tag)));
            await Assert.That(invalid.Status).IsEqualTo(SecretStatus.Unknown);
        }
    }

    private static async Task AssertDeniedChange<T>(ManagementRequest<T> request, ManagementTarget target,
        string? project) where T : notnull
    {
        var server = new Server(ProjectResponse);
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, project);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(server.Dispatched).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    private static async Task AssertProtected(object value)
    {
        await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(value.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
        foreach (string coordinate in new[] { Org, Environment, Tag, Creator, DeletedIdentity, DeletedUser,
            CertificateKey, SecretKey, Role })
        {
            await Assert.That(JsonSerializer.Serialize(value).Contains(coordinate, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains(coordinate, StringComparison.Ordinal)).IsFalse();
        }
    }

    private static async Task AssertProjectMetadata(ProjectSummary value, bool detailed)
    {
        await Assert.That(value.Id).IsEqualTo("project");
        await Assert.That(value.Name).IsEqualTo("private-project");
        await Assert.That(value.Description).IsEqualTo("");
        await Assert.That(value.CreatedAt.Value).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(value.UpdatedAt.Value).IsEqualTo("2026-01-02T00:00:00Z");
        await Assert.That(value.DefaultProduct.Value).IsEqualTo("private-product");
        await Assert.That(value.UpgradeStatus.Value).IsEqualTo("private-upgrade");
        await Assert.That(value.KmsCertificateKeyId.Value).IsEqualTo(CertificateKey);
        await Assert.That(value.KmsSecretManagerKeyId.Value).IsEqualTo(SecretKey);
        await Assert.That(value.AuditLogsRetentionDays.Value).IsEqualTo(30.5);
        await Assert.That(value.Version.Value).IsEqualTo(1.5);
        await Assert.That(value.PitVersionLimit.Value).IsEqualTo(10.5);
        await Assert.That(value.AutoCapitalization.Value).IsFalse();
        await Assert.That(value.HasDeleteProtection.Value).IsFalse();
        await Assert.That(value.EnforceEncryptedSecretManagerSecretMetadata.Value).IsFalse();
        await Assert.That(value.IsLegacyAdditionalPrivilegesEnabled.Value).IsFalse();
        await Assert.That(value.SecretBlindIndexEnabled.Value).IsFalse();
        await Assert.That(value.SecretSharing.Value).IsFalse();
        await Assert.That(value.ShowSnapshotsLegacy.Value).IsFalse();
        await Assert.That(value.SecretDetectionIgnoreValues.Value[0]).IsEqualTo("private-value");
        await Assert.That(value.Environments.IsPresent).IsEqualTo(detailed);
        await Assert.That(value.DeletedEnvironments.IsPresent).IsEqualTo(detailed);
        await Assert.That(value.NativeId.IsPresent).IsEqualTo(detailed);
        if (detailed)
        {
            await Assert.That(value.NativeId.Value).IsEqualTo("private-native-id");
            await Assert.That(value.Environments.Value[0].Name).IsEqualTo("private-env");
            var deleted = value.DeletedEnvironments.Value;
            await Assert.That(deleted.Count).IsEqualTo(3);
            await Assert.That(deleted[0].DeleteAfter).IsEqualTo("2026-01-03T00:00:00Z");
            await Assert.That(deleted[0].SoftDeletedAt).IsEqualTo("2026-01-02T00:00:00Z");
            await Assert.That(deleted[0].DeletedBy!.Type).IsEqualTo(ProjectDeletedByType.Identity);
            await Assert.That(deleted[0].DeletedBy!.Name).IsEqualTo("private-identity");
            await Assert.That(deleted[1].DeletedBy!.Type).IsEqualTo(ProjectDeletedByType.User);
            await Assert.That(deleted[1].DeletedBy!.Email is null).IsTrue();
            await Assert.That(deleted[1].DeletedBy!.Username).IsEqualTo("");
            await Assert.That(deleted[1].DeletedBy!.FirstName).IsEqualTo("private-first");
            await Assert.That(deleted[1].DeletedBy!.LastName).IsEqualTo("private-last");
            await Assert.That(deleted[2].DeletedBy is null).IsTrue();
            await AssertProtected(value.Environments.Value[0]);
            foreach (var environment in deleted)
            {
                await AssertProtected(environment);
                if (environment.DeletedBy is not null) await AssertProtected(environment.DeletedBy);
            }
        }
        await AssertProtected(value);
        await AssertProtected(value.SecretDetectionIgnoreValues);
    }

    private static JsonObject FullProject() => JsonNode.Parse($$$"""
        {"id":"project","orgId":"{{{Org}}}","type":"secret-manager","name":"private-project","slug":"project","description":"",
         "_id":"private-native-id","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z",
         "defaultProduct":"private-product","upgradeStatus":"private-upgrade","kmsCertificateKeyId":"{{{CertificateKey}}}",
         "kmsSecretManagerKeyId":"{{{SecretKey}}}","auditLogsRetentionDays":30.5,"version":1.5,"pitVersionLimit":10.5,
         "autoCapitalization":false,"hasDeleteProtection":false,"enforceEncryptedSecretManagerSecretMetadata":false,
         "isLegacyAdditionalPrivilegesEnabled":false,"secretBlindIndexEnabled":false,"secretSharing":false,
         "showSnapshotsLegacy":false,"secretDetectionIgnoreValues":["private-value"],
         "environments":[{"id":"env","name":"private-env","slug":"dev"}],
         "deletedEnvironments":[
           {"id":"deleted","name":"private-env","slug":"old","deleteAfter":"2026-01-03T00:00:00Z",
            "softDeletedAt":"2026-01-02T00:00:00Z","deletedBy":{"type":"identity","id":"private-id","name":"private-identity"}},
           {"id":"deleted2","name":"private-env","slug":"old2","deleteAfter":"2026-01-03T00:00:00Z",
            "softDeletedAt":"2026-01-02T00:00:00Z","deletedBy":{"type":"user","id":"private-id","email":null,
            "username":"","firstName":"private-first","lastName":"private-last"}},
           {"id":"deleted3","name":"private-env","slug":"old3","deleteAfter":"2026-01-03T00:00:00Z",
            "softDeletedAt":"2026-01-02T00:00:00Z","deletedBy":null}],
         "roles":[{"id":"{{{Role}}}","projectId":"project","name":"private-role","slug":"reader","description":null,
            "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z","version":1.5,
            "permissions":{"unestablished":"private-permission"}}]}
        """)!.AsObject();

    private static JsonObject FullEnvironment(double position) => new()
    {
        ["id"] = Environment,
        ["projectId"] = "project",
        ["name"] = "private-env",
        ["slug"] = "dev",
        ["position"] = position,
        ["createdAt"] = "2026-01-01T00:00:00Z",
        ["updatedAt"] = "2026-01-02T00:00:00Z",
        ["deleteAfter"] = null,
        ["softDeletedAt"] = null,
        ["deletedByUserId"] = null,
        ["deletedByIdentityId"] = DeletedIdentity
    };

    private static readonly string ProjectResponse = $$$"""
        {"project":{"id":"project","orgId":"{{{Org}}}","type":"secret-manager","name":"private-project","slug":"project"}}
        """;

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("test-token"))));
        }
    }

    private sealed class Server(string response) : HttpMessageHandler
    {
        public bool Dispatched { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Dispatched = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response, Encoding.UTF8, "application/json")
            });
        }
    }

    private sealed class StatefulServer(JsonObject project, JsonObject? environment = null) : HttpMessageHandler
    {
        public JsonObject? Body { get; private set; }
        public Dictionary<string, string>? Query { get; private set; }
        public bool Hold { get; init; }
        public string? ExcludedMember { get; set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.Unauthorized);
            Query = request.RequestUri!.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(part => part.Split('=', 2)).ToDictionary(pair => Uri.UnescapeDataString(pair[0]),
                    pair => Uri.UnescapeDataString(pair[1]), StringComparer.Ordinal);
            string path = request.RequestUri.AbsolutePath;
            if (request.Content is not null)
            {
                Body = JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))!.AsObject();
                var state = path.Contains("/environments", StringComparison.Ordinal) ? environment : project;
                if (state is not null)
                    foreach (var field in Body)
                        if (state.ContainsKey(field.Key)) state[field.Key] = field.Value?.DeepClone();
            }
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            var tag = JsonNode.Parse($$$"""
                {"id":"{{{Tag}}}","projectId":"project","slug":"private-tag","color":"blue","name":"private-tag-name",
                "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z",
                "createdBy":"{{{Creator}}}","createdByActorType":"identity"}
                """);
            bool projectList = path == "/api/v1/projects" && request.Method == HttpMethod.Get;
            var projectResponse = project.DeepClone().AsObject();
            if (!projectList && ExcludedMember != "roles") projectResponse.Remove("roles");
            if (request.Method == HttpMethod.Patch || request.Method == HttpMethod.Delete)
                foreach (string field in new[] { "_id", "environments", "deletedEnvironments" })
                    if (ExcludedMember != field) projectResponse.Remove(field);
            bool tagInspection = request.Method == HttpMethod.Get && path != "/api/v1/projects/project/tags";
            if (!tagInspection && ExcludedMember != "name") tag!.AsObject().Remove("name");
            JsonNode response = path switch
            {
                "/api/v1/projects" when request.Method == HttpMethod.Get =>
                    new JsonObject { ["projects"] = new JsonArray(projectResponse) },
                "/api/v1/projects/project/tags" when request.Method == HttpMethod.Get =>
                    new JsonObject { ["tags"] = new JsonArray(tag) },
                _ when path.Contains("/environments", StringComparison.Ordinal) =>
                    new JsonObject
                    {
                        ["projectId"] = "project",
                        ["environment"] = environment!.DeepClone(),
                        ["message"] = "private-provider-prose"
                    },
                _ when path.Contains("/tags", StringComparison.Ordinal) => new JsonObject { ["tag"] = tag },
                "/api/v1/projects/slug/project" => projectResponse,
                _ => new JsonObject { ["project"] = projectResponse }
            };
            if (path.Contains("/environments", StringComparison.Ordinal) && request.Method == HttpMethod.Get)
            {
                if (ExcludedMember != "projectId") response.AsObject().Remove("projectId");
                if (ExcludedMember != "message") response.AsObject().Remove("message");
            }
            return new(HttpStatusCode.OK) { Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }
}
