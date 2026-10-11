using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ProjectTemplateVariantTests
{
    private const string Org = "0000000a-0000-0000-0000-00000000000a";
    private const string Id = "10000000-0000-0000-0000-000000000001";
    private const string Identity = "20000000-0000-0000-0000-000000000002";

    [Test]
    public async Task AllOptionalInputsPersistAndFreshReadProjectsNativeConfiguration()
    {
        var handler = new Server();
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var configuration = Full();
        using var create = ProjectTemplateOperations.CreateProjectTemplate(Org, "private-name",
            description: "", configuration: configuration);
        var receipt = client.CreateReceipt(create);
        var created = await client.ExecuteAsync(create, authority, authority.IssueGrant(create.OperationId,
            ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "private-name",
                description: "", configuration: Full())), receipt);
        await Assert.That(created.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(handler.Body!.Count).IsEqualTo(9);
        await AssertConfiguration(created.Value);
        using var get = ProjectTemplateOperations.GetProjectTemplate(Org, Id);
        var read = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, new(Org, resourceId: Id)));
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Success);
        await AssertConfiguration(read.Value);

        var clear = new ProjectTemplateConfiguration(roles: [],
            environments: ProjectTemplateCollection<ProjectTemplateEnvironment>.Null(),
            users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([]),
            groups: ProjectTemplateCollection<ProjectTemplateGroup>.Null(),
            identities: ProjectTemplateCollection<ProjectTemplateIdentity>.Null(),
            projectManagedIdentities: ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([]));
        using var update = ProjectTemplateOperations.UpdateProjectTemplate(Org, Id, configuration: clear);
        var updated = await client.ExecuteAsync(update, authority, authority.IssueGrant(update.OperationId,
            ProjectTemplateOperations.ProjectTemplateUpdateTarget(Org, Id, configuration: clear)), client.CreateReceipt(update));
        await Assert.That(updated.Status).IsEqualTo(SecretStatus.Success);
        var after = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, new(Org, resourceId: Id)));
        await Assert.That(after.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(after.Value.Roles.Count).IsEqualTo(0);
        await Assert.That(after.Value.Environments is null).IsTrue();
        await Assert.That(after.Value.Users!.Count).IsEqualTo(0);
        await Assert.That(after.Value.Groups is null).IsTrue();
        await Assert.That(after.Value.Identities is null).IsTrue();
        await Assert.That(after.Value.ProjectManagedIdentities!.Count).IsEqualTo(0);
        await Assert.That(after.Value.Name).IsEqualTo("private-name");
    }

    private static async Task AssertConfiguration(ProjectTemplateSummary value)
    {
        await Assert.That(value.Roles[0].Name).IsEqualTo("private-role");
        await Assert.That(value.Roles[0].Slug).IsEqualTo("reader");
        var permission = value.Roles[0].Permissions[0];
        await Assert.That(permission.Action.IsScalar).IsFalse();
        await Assert.That(permission.Action.Values[0]).IsEqualTo("readValue");
        await Assert.That(permission.Subject!.IsScalar).IsTrue();
        await Assert.That(permission.Subject.Values[0]).IsEqualTo("secrets");
        await Assert.That(permission.Inverted).IsFalse();
        await Assert.That(permission.HasConditions).IsTrue();
        await Assert.That(permission.IncludesConditionValues).IsFalse();
        await Assert.That(value.Environments![0].Position).IsEqualTo(1.5);
        await Assert.That(value.Users![0].Username).IsEqualTo("private-user");
        await Assert.That(value.Groups![0].GroupSlug).IsEqualTo("private-group");
        await Assert.That(value.Identities![0].IdentityId).IsEqualTo(Identity);
        await Assert.That(value.Identities[0].IdentityName).IsEqualTo("returned-identity");
        await Assert.That(value.ProjectManagedIdentities![0].Name).IsEqualTo("private-machine");
        foreach (var item in new object[] { value, value.Roles[0], permission, permission.Action,
            value.Environments[0], value.Users[0], value.Groups[0], value.Identities[0], value.ProjectManagedIdentities[0] })
        {
            await Assert.That(JsonSerializer.Serialize(item).Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(item.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    [Arguments("roles")]
    [Arguments("environments")]
    [Arguments("users")]
    [Arguments("groups")]
    [Arguments("identities")]
    [Arguments("projectManagedIdentities")]
    [Arguments("description")]
    [Arguments("name")]
    [Arguments("permission")]
    [Arguments("scalar")]
    [Arguments("inversion")]
    [Arguments("condition")]
    [Arguments("principalRole")]
    [Arguments("null")]
    [Arguments("empty")]
    public async Task EveryWholeChangeFieldRejectsAnIndependentDifferentIntent(string changed)
    {
        using var incoming = ProjectTemplateOperations.UpdateProjectTemplate(Org, Id,
            name: changed == "name" ? "other" : null, description: changed == "description" ? "" : null,
            configuration: Full(changed));
        var handler = new Server();
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var receipt = client.CreateReceipt(incoming);
        var expected = ProjectTemplateOperations.ProjectTemplateUpdateTarget(Org, Id, configuration: Full());
        var result = await client.ExecuteAsync(incoming, authority, authority.IssueGrant(incoming.OperationId, expected), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(handler.Body is null).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NestedInputsAndWireBytesAreOwnedCopies(bool update)
    {
        string[] roleNames = ["reader"];
        var users = new[] { new ProjectTemplateUser("private-user", roleNames) };
        var selectedUsers = ProjectTemplateCollection<ProjectTemplateUser>.FromValues(users);
        ProjectRoleAction[] actions = [ProjectRoleAction.ReadValue];
        string[] included = ["development"];
        ProjectTemplateCondition[] conditions = [new(RoleConditionField.Environment,
            ProjectTemplateStringClause.Compare(included: included))];
        var permissions = new[] { new ProjectTemplatePermission(ProjectRoleSubject.Secrets, actions, conditions: conditions) };
        var roles = new[] { new ProjectTemplateRole("private-role", "reader", permissions) };
        var configuration = new ProjectTemplateConfiguration(roles, users: selectedUsers);
        roleNames[0] = "owner";
        users[0] = new("attacker", ["owner"]);
        actions[0] = ProjectRoleAction.Delete;
        included[0] = "production";
        conditions[0] = new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/other"));
        permissions[0] = new(ProjectRoleSubject.Secrets, ProjectRoleAction.Delete);
        roles[0] = new("other", "other", []);
        using var request = update
            ? ProjectTemplateOperations.UpdateProjectTemplate(Org, Id, configuration: configuration)
            : ProjectTemplateOperations.CreateProjectTemplate(Org, "private-name", configuration: configuration);
        byte[] body = request.CopyBody()!;
        Array.Fill(body, (byte)0);
        byte[] copy = request.CopyBody()!;
        try
        {
            using var parsed = JsonDocument.Parse(copy);
            var value = parsed.RootElement;
            await Assert.That(value.GetProperty("users")[0].GetProperty("username").GetString()).IsEqualTo("private-user");
            await Assert.That(value.GetProperty("users")[0].GetProperty("roles")[0].GetString()).IsEqualTo("reader");
            var permission = value.GetProperty("roles")[0].GetProperty("permissions")[0];
            await Assert.That(permission.GetProperty("action")[0].GetString()).IsEqualTo("readValue");
            await Assert.That(permission.GetProperty("conditions").GetProperty("environment").GetProperty("$in")[0].GetString())
                .IsEqualTo("development");
        }
        finally { Array.Clear(body); Array.Clear(copy); }
    }

    [Test]
    public async Task NativeEmptyObjectsArraysFalseAndOmittedConditionsRemainDistinct()
    {
        ProjectTemplatePermission[] permissions = [
            new(ProjectRoleSubject.Secrets, ProjectRoleAction.ReadValue),
            new(ProjectRoleSubject.Secrets, ProjectRoleAction.ReadValue, inverted: false, conditions: []),
            new(ProjectRoleSubject.Secrets, [ProjectRoleAction.ReadValue], conditions:
                [new(RoleConditionField.Environment, ProjectTemplateStringClause.Compare()),
                 new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Compare(included: [])),
                 new(RoleConditionField.SecretName, ProjectTemplateStringClause.Literal(""))],
                secretTags: new(included: [], all: [])),
            new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Lease, metadata: new()),
            new(ProjectRoleSubject.Certificates, ProjectRoleAction.Read, metadata:
                new(ProjectTemplateStringClause.Compare(included: []), ProjectTemplateStringClause.Compare()))
        ];
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "template",
            configuration: new(roles: [new("role", "role", permissions)]));
        byte[] copy = request.CopyBody()!;
        try
        {
            using var parsed = JsonDocument.Parse(copy);
            var items = parsed.RootElement.GetProperty("roles")[0].GetProperty("permissions");
            await Assert.That(items[0].TryGetProperty("inverted", out _)).IsFalse();
            await Assert.That(items[0].TryGetProperty("conditions", out _)).IsFalse();
            await Assert.That(items[1].GetProperty("inverted").GetBoolean()).IsFalse();
            await Assert.That(items[1].GetProperty("conditions").EnumerateObject().Count()).IsEqualTo(0);
            await Assert.That(items[2].GetProperty("action").ValueKind).IsEqualTo(JsonValueKind.Array);
            var conditions = items[2].GetProperty("conditions");
            await Assert.That(conditions.GetProperty("environment").EnumerateObject().Count()).IsEqualTo(0);
            await Assert.That(conditions.GetProperty("secretPath").GetProperty("$in").GetArrayLength()).IsEqualTo(0);
            await Assert.That(conditions.GetProperty("secretName").GetString()).IsEqualTo("");
            await Assert.That(conditions.GetProperty("secretTags").GetProperty("$all").GetArrayLength()).IsEqualTo(0);
            await Assert.That(items[3].GetProperty("conditions").GetProperty("metadata").GetProperty("$elemMatch")
                .EnumerateObject().Count()).IsEqualTo(0);
        }
        finally { Array.Clear(copy); }
    }

    [Test]
    [Arguments("literal")]
    [Arguments("$eq")]
    [Arguments("$ne")]
    [Arguments("$in")]
    [Arguments("$glob")]
    [Arguments("combined")]
    public async Task EveryStringComparisonAlternativeWritesItsEstablishedNativeField(string operation)
    {
        var clause = operation switch
        {
            "literal" => ProjectTemplateStringClause.Literal("development"),
            "$eq" => ProjectTemplateStringClause.Compare(equal: "development"),
            "$ne" => ProjectTemplateStringClause.Compare(notEqual: "production"),
            "$in" => ProjectTemplateStringClause.Compare(included: ["development", "staging"]),
            "$glob" => ProjectTemplateStringClause.Compare(glob: "dev*"),
            _ => ProjectTemplateStringClause.Compare(equal: "development", notEqual: "production",
                included: ["development"], glob: "dev*")
        };
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "template",
            configuration: new(roles: [new("role", "role",
                [new(ProjectRoleSubject.Secrets, ProjectRoleAction.ReadValue, conditions: [new(RoleConditionField.Environment, clause)])])]));
        byte[] body = request.CopyBody()!;
        try
        {
            using var parsed = JsonDocument.Parse(body);
            var value = parsed.RootElement.GetProperty("roles")[0].GetProperty("permissions")[0]
                .GetProperty("conditions").GetProperty("environment");
            if (operation == "literal") await Assert.That(value.GetString()).IsEqualTo("development");
            else if (operation == "combined") await Assert.That(value.EnumerateObject().Count()).IsEqualTo(4);
            else
            {
                await Assert.That(value.TryGetProperty(operation, out _)).IsTrue();
                await Assert.That(value.EnumerateObject().Count()).IsEqualTo(1);
            }
        }
        finally { Array.Clear(body); }
    }

    [Test]
    public async Task TagAndMetadataComparisonsOwnSelectionsAndPreserveEntryConjunction()
    {
        string[] included = ["private-tag"];
        string[] all = ["required-tag"];
        var tags = new ProjectTemplateSecretTags(included, all);
        var metadata = new ProjectTemplateMetadataMatch(
            ProjectTemplateStringClause.Compare(equal: "private-key", included: included),
            ProjectTemplateStringClause.Compare(notEqual: "denied-value"));
        included[0] = "changed-tag";
        all[0] = "changed-required-tag";
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "template",
            configuration: new(roles: [new("role", "role", [
                new(ProjectRoleSubject.Secrets, ProjectRoleAction.ReadValue, secretTags: tags),
                new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Lease, metadata: metadata)])]));
        byte[] body = request.CopyBody()!;
        try
        {
            using var parsed = JsonDocument.Parse(body);
            var permissions = parsed.RootElement.GetProperty("roles")[0].GetProperty("permissions");
            var wireTags = permissions[0].GetProperty("conditions").GetProperty("secretTags");
            await Assert.That(wireTags.GetProperty("$in")[0].GetString()).IsEqualTo("private-tag");
            await Assert.That(wireTags.GetProperty("$all")[0].GetString()).IsEqualTo("required-tag");
            var entry = permissions[1].GetProperty("conditions").GetProperty("metadata").GetProperty("$elemMatch");
            await Assert.That(entry.GetProperty("key").GetProperty("$eq").GetString()).IsEqualTo("private-key");
            await Assert.That(entry.GetProperty("key").GetProperty("$in")[0].GetString()).IsEqualTo("private-tag");
            await Assert.That(entry.GetProperty("value").GetProperty("$ne").GetString()).IsEqualTo("denied-value");
        }
        finally { Array.Clear(body); }
    }

    [Test]
    [Arguments("environments")]
    [Arguments("users")]
    [Arguments("groups")]
    [Arguments("identities")]
    [Arguments("projectManagedIdentities")]
    public async Task CollectionOmissionNullAndEmptyHaveDifferentIntentsAndWireValues(string field)
    {
        var omitted = new ProjectTemplateConfiguration(roles: []);
        var nil = Collection(field, true);
        var empty = Collection(field, false);
        var targets = new[] { omitted, nil, empty }.Select(c =>
            ProjectTemplateOperations.ProjectTemplateUpdateTarget(Org, Id, configuration: c).SecondaryId).ToArray();
        await Assert.That(targets.Distinct().Count()).IsEqualTo(3);
        foreach (var (configuration, kind) in new[] { (omitted, "omit"), (nil, "null"), (empty, "empty") })
        {
            using var request = ProjectTemplateOperations.UpdateProjectTemplate(Org, Id, configuration: configuration);
            byte[] body = request.CopyBody()!;
            try
            {
                using var parsed = JsonDocument.Parse(body);
                bool present = parsed.RootElement.TryGetProperty(field, out var value);
                await Assert.That(present).IsEqualTo(kind != "omit");
                if (present) await Assert.That(value.ValueKind).IsEqualTo(kind == "null" ? JsonValueKind.Null : JsonValueKind.Array);
            }
            finally { Array.Clear(body); }
        }
        if (field != "environments")
            await Assert.That(() => ProjectTemplateOperations.CreateProjectTemplate(Org, "template", configuration: nil))
                .Throws<ArgumentException>();
        else
        {
            using var allowed = ProjectTemplateOperations.CreateProjectTemplate(Org, "template", configuration: nil);
            await Assert.That(allowed.IsMutation).IsTrue();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationRetainsDispatchEvidenceAndDoesNotReplay(bool duringDispatch)
    {
        var handler = new Server { Hold = duringDispatch };
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "template", configuration: Full());
        var grant = authority.IssueGrant(request.OperationId,
            ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "template", configuration: Full()));
        var receipt = client.CreateReceipt(request);
        using var cancellation = new CancellationTokenSource();
        if (!duringDispatch) cancellation.Cancel();
        var entered = handler.Entered.Task;
        var pending = client.ExecuteAsync(request, authority, grant, receipt, cancellation.Token).AsTask();
        if (duringDispatch)
        {
            await entered.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
        }
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(duringDispatch ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.NotDispatched);
        if (duringDispatch)
        {
            var replay = await client.ExecuteAsync(request, authority, grant, receipt);
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        }
        else await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    [Arguments("roles")]
    [Arguments("environments")]
    [Arguments("users")]
    [Arguments("groups")]
    [Arguments("identities")]
    [Arguments("projectManagedIdentities")]
    public async Task RequiredConfigurationFieldsFailClosedWhenMissing(string missing)
    {
        var handler = new Server { RemoveField = missing };
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "template", configuration: Full());
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "template", configuration: Full())), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("array")]
    [Arguments("absent")]
    [Arguments("empty")]
    [Arguments("invalid")]
    public async Task ResultPermissionAlternativesDoNotGuessUnconstrainedConditions(string shape)
    {
        var handler = new Server { PermissionShape = shape };
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "template", configuration: Full());
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "template", configuration: Full())), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(shape == "invalid" ? SecretStatus.Unknown : SecretStatus.Success);
        if (shape == "invalid") return;
        var permission = result.Value.Roles[0].Permissions[0];
        await Assert.That(permission.Action.IsScalar).IsEqualTo(shape == "absent");
        if (shape == "absent")
        {
            await Assert.That(permission.Subject is null).IsTrue();
            await Assert.That(permission.Inverted is null).IsTrue();
            await Assert.That(permission.HasConditions).IsFalse();
        }
        else
        {
            await Assert.That(permission.Subject!.IsScalar).IsFalse();
            await Assert.That(permission.Subject.Values.Count).IsEqualTo(shape == "empty" ? 0 : 2);
            await Assert.That(permission.IncludesConditionValues).IsFalse();
            await Assert.That(permission.HasConditions).IsTrue();
        }
    }

    [Test]
    [Arguments("environmentPosition")]
    [Arguments("identityId")]
    [Arguments("identityName")]
    [Arguments("permissionSubject")]
    [Arguments("permissionInverted")]
    public async Task MalformedNestedProjectionsFailClosedWithoutAppliedReceipt(string malformed)
    {
        var handler = new Server { Malformed = malformed };
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "template", configuration: Full());
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "template", configuration: Full())), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task AllActivePermissionSubjectsSupportBothActionSelectionAlternatives()
    {
        foreach (ProjectRoleSubject subject in Enum.GetValues<ProjectRoleSubject>())
        {
            ProjectRoleAction action = subject switch
            {
                ProjectRoleSubject.DynamicSecrets => ProjectRoleAction.Lease,
                ProjectRoleSubject.SecretEventSubscriptions => ProjectRoleAction.SubscribeToCreationEvents,
                ProjectRoleSubject.Workspace or ProjectRoleSubject.Kms => ProjectRoleAction.Edit,
                ProjectRoleSubject.Kmip => ProjectRoleAction.ReadClients,
                ProjectRoleSubject.SecretScanningDataSources => ProjectRoleAction.ReadDataSources,
                ProjectRoleSubject.SecretScanningFindings => ProjectRoleAction.ReadFindings,
                ProjectRoleSubject.SecretScanningConfigs => ProjectRoleAction.ReadConfigs,
                ProjectRoleSubject.AppConnections => ProjectRoleAction.ReadAppConnections,
                ProjectRoleSubject.HsmConnectors => ProjectRoleAction.ReadHsmConnectors,
                ProjectRoleSubject.ProjectFolderGrant => ProjectRoleAction.ReadGrant,
                _ => ProjectRoleAction.Read
            };
            using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "template",
                configuration: new(roles: [new("role", "role",
                    [new(subject, action), new(subject, new[] { action })])]));
            byte[] body = request.CopyBody()!;
            try
            {
                using var parsed = JsonDocument.Parse(body);
                var permissions = parsed.RootElement.GetProperty("roles")[0].GetProperty("permissions");
                await Assert.That(permissions[0].GetProperty("action").ValueKind).IsEqualTo(JsonValueKind.String);
                await Assert.That(permissions[1].GetProperty("action").ValueKind).IsEqualTo(JsonValueKind.Array);
                await Assert.That(permissions[1].GetProperty("action")[0].GetString())
                    .IsEqualTo(permissions[0].GetProperty("action").GetString());
                await Assert.That(permissions[1].GetProperty("subject").GetString())
                    .IsEqualTo(permissions[0].GetProperty("subject").GetString());
            }
            finally { Array.Clear(body); }
        }
    }

    [Test]
    public async Task InvalidShapesAndBudgetsFailBeforeAuthorityOrDispatch()
    {
        await Assert.That(() => new ProjectTemplateEnvironment("name", "slug", double.NaN)).Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplateEnvironment("name", "slug", 0)).Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplateIdentity("not-uuid", ["reader"])).Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplateUser("user", [])).Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplateRole("role", new string('x', 65), [])).Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplatePermission(ProjectRoleSubject.Secrets, Array.Empty<ProjectRoleAction>()))
            .Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplatePermission(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Read))
            .Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplatePermission(ProjectRoleSubject.Role, ProjectRoleAction.Read, conditions: []))
            .Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplatePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
            conditions: [new(RoleConditionField.IdentityId, ProjectTemplateStringClause.Compare())])).Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplateMetadataMatch(ProjectTemplateStringClause.Literal("literal"))).Throws<ArgumentException>();
        await Assert.That(() => new ProjectTemplatePermission(ProjectRoleSubject.Certificates, ProjectRoleAction.Read,
            metadata: new(ProjectTemplateStringClause.Compare(notEqual: "x")))).Throws<ArgumentException>();
        await Assert.That(() => ProjectTemplateCollection<ProjectTemplateUser>.FromValues(
            Enumerable.Repeat(new ProjectTemplateUser("user", ["reader"]), 1001).ToArray())).Throws<ArgumentException>();
        await Assert.That(() => ProjectTemplateOperations.CreateProjectTemplate(Org, "template",
            configuration: new(users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues(
                Enumerable.Repeat(new ProjectTemplateUser(new string('x', 1000), ["reader"]), 100).ToArray()))))
            .Throws<ArgumentException>();
        using var disposed = ProjectTemplateOperations.CreateProjectTemplate(Org, "template");
        disposed.Dispose();
        await Assert.That(() => disposed.CopyBody()).Throws<ObjectDisposedException>();
    }

    private static ProjectTemplateConfiguration Collection(string field, bool nil) => field switch
    {
        "environments" => new(roles: [], environments: nil ? ProjectTemplateCollection<ProjectTemplateEnvironment>.Null() :
            ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([])),
        "users" => new(roles: [], users: nil ? ProjectTemplateCollection<ProjectTemplateUser>.Null() :
            ProjectTemplateCollection<ProjectTemplateUser>.FromValues([])),
        "groups" => new(roles: [], groups: nil ? ProjectTemplateCollection<ProjectTemplateGroup>.Null() :
            ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([])),
        "identities" => new(roles: [], identities: nil ? ProjectTemplateCollection<ProjectTemplateIdentity>.Null() :
            ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([])),
        "projectManagedIdentities" => new(roles: [], projectManagedIdentities: nil ? ProjectTemplateCollection<ProjectTemplateManagedIdentity>.Null() :
            ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([])),
        _ => throw new ArgumentException("Invalid test field.")
    };

    private static ProjectTemplateConfiguration Full(string? changed = null)
    {
        ProjectTemplateCondition[] conditions = [new(RoleConditionField.Environment,
            ProjectTemplateStringClause.Compare(equal: changed == "condition" ? "production" : "development"))];
        ProjectRoleAction action = changed == "permission" ? ProjectRoleAction.Delete : ProjectRoleAction.ReadValue;
        var permission = changed == "scalar"
            ? new ProjectTemplatePermission(ProjectRoleSubject.Secrets, action, false, conditions)
            : new ProjectTemplatePermission(ProjectRoleSubject.Secrets, new[] { action }, changed == "inversion", conditions);
        return new(
            roles: [new(changed == "roles" ? "other-role" : "private-role", "reader", [permission])],
            environments: changed == "null" ? ProjectTemplateCollection<ProjectTemplateEnvironment>.Null() :
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues(changed == "empty" ? [] :
                    [new("Development", changed == "environments" ? "other" : "development", 1.5)]),
            users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues(
                [new(changed == "users" ? "other-user" : "private-user", [changed == "principalRole" ? "owner" : "reader"])]),
            groups: ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([new(changed == "groups" ? "other-group" : "private-group", ["reader"])]),
            identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues(
                [new(changed == "identities" ? Id : Identity, ["reader"])]),
            projectManagedIdentities: ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues(
                [new(changed == "projectManagedIdentities" ? "other-machine" : "private-machine", ["reader"])]));
    }

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("test-token"))));
        }
    }

    private sealed class Server : HttpMessageHandler
    {
        private readonly JsonObject _state = new()
        {
            ["id"] = Id,
            ["orgId"] = Org,
            ["name"] = "template",
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-02T00:00:00Z",
            ["roles"] = new JsonArray(),
            ["environments"] = null,
            ["users"] = null,
            ["groups"] = null,
            ["identities"] = null,
            ["projectManagedIdentities"] = null
        };
        public JsonObject? Body { get; private set; }
        public bool Hold { get; init; }
        public string? RemoveField { get; init; }
        public string? PermissionShape { get; init; }
        public string? Malformed { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.Unauthorized);
            if (request.RequestUri!.AbsolutePath != "/api/v1/project-templates" &&
                request.RequestUri.AbsolutePath != "/api/v1/project-templates/" + Id) return new(HttpStatusCode.NotFound);
            if (request.Content is not null)
            {
                Body = JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))!.AsObject();
                foreach (var field in Body) _state[field.Key] = field.Value?.DeepClone();
                if (_state["identities"] is JsonArray identities)
                    foreach (var identity in identities) identity!["identityName"] = "returned-identity";
            }
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            var returned = _state.DeepClone().AsObject();
            if (RemoveField is not null) returned.Remove(RemoveField);
            if (PermissionShape is not null)
            {
                returned["roles"]![0]!["permissions"] = PermissionShape switch
                {
                    "array" => JsonNode.Parse("""[{"action":["read","future"],"subject":["secrets","future"],"inverted":false,"conditions":{"unknown":true}}]"""),
                    "absent" => JsonNode.Parse("""[{"action":"read"}]"""),
                    "empty" => JsonNode.Parse("""[{"action":[],"subject":[],"conditions":null}]"""),
                    _ => JsonNode.Parse("""[{"action":null}]""")
                };
            }
            switch (Malformed)
            {
                case "environmentPosition": returned["environments"]![0]!["position"] = 0; break;
                case "identityId": returned["identities"]![0]!["identityId"] = "not-uuid"; break;
                case "identityName": returned["identities"]![0]!.AsObject().Remove("identityName"); break;
                case "permissionSubject": returned["roles"]![0]!["permissions"]![0]!["subject"] = false; break;
                case "permissionInverted": returned["roles"]![0]!["permissions"]![0]!["inverted"] = "false"; break;
            }
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(new JsonObject { ["projectTemplate"] = returned }.ToJsonString(), Encoding.UTF8, "application/json")
            };
        }
    }
}
