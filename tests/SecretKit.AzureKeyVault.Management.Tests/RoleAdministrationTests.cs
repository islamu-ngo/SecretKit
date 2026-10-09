using System.Text.Json;
using Azure.ResourceManager.Authorization;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class RoleAdministrationTests
{
    [Test]
    public async Task NativeSdkDeleteNoContentBaseline()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(204, "")));
        var options = new Azure.ResourceManager.ArmClientOptions { Transport = backend };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.SetApiVersion("Microsoft.Authorization/roleAssignments", "2022-04-01");
        var client = new Azure.ResourceManager.ArmClient(new Credential(), null, options);
        Exception? observed = null;
        try
        {
            var operation = await client.GetRoleAssignmentResource(new Azure.Core.ResourceIdentifier(AssignmentPath))
                .DeleteAsync(Azure.WaitUntil.Started);
            _ = operation.HasCompleted;
        }
        catch (Exception exception)
        {
            observed = exception;
        }
        await Assert.That(observed).IsNotNull();
        await Assert.That(observed is NullReferenceException).IsTrue();
        Console.WriteLine("ROLE_DELETE_204_EXCEPTION_TYPE=" + observed!.GetType().FullName);
    }

    private static readonly Guid AssignmentId = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid DefinitionId = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid PrincipalId = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static RoleAssignmentScope Assignment() => new(ScopeAuthorityTests.Scope(), AssignmentId);
    private static RoleDefinitionScope Definition() =>
        new(ScopeAuthorityTests.Scope().ResourceGroup.Subscription, DefinitionId);
    private static string AssignmentPath =>
        $"{ScopeAuthorityTests.Id}/providers/Microsoft.Authorization/roleAssignments/{AssignmentId:D}";
    private static string DefinitionPath =>
        $"/subscriptions/{Definition().Subscription.SubscriptionId:D}/providers/Microsoft.Authorization/roleDefinitions/{DefinitionId:D}";
    private static string AssignmentJson(string? scope = null, Guid? principal = null) => JsonSerializer.Serialize(new
    {
        id = $"{scope ?? ScopeAuthorityTests.Id}/providers/Microsoft.Authorization/roleAssignments/{AssignmentId:D}",
        name = AssignmentId.ToString("D"),
        type = "Microsoft.Authorization/roleAssignments",
        properties = new
        {
            scope = scope ?? ScopeAuthorityTests.Id,
            roleDefinitionId = DefinitionPath,
            principalId = (principal ?? PrincipalId).ToString("D"),
            principalType = "ServicePrincipal",
            description = "protected-canary",
            condition = "protected-condition-canary",
            conditionVersion = "2.0"
        }
    });
    private static string DefinitionJson() => JsonSerializer.Serialize(new
    {
        id = DefinitionPath,
        name = DefinitionId.ToString("D"),
        type = "Microsoft.Authorization/roleDefinitions",
        properties = new
        {
            roleName = "protected-role-canary",
            description = "protected-description-canary",
            type = "CustomRole",
            permissions = new[] { new { actions = new[] { "Microsoft.KeyVault/vaults/read" },
                notActions = Array.Empty<string>(), dataActions = Array.Empty<string>(), notDataActions = Array.Empty<string>() } },
            assignableScopes = new[] { ScopeAuthorityTests.Id }
        }
    });

    [Test]
    public async Task NativeAncestorAssignmentsRemainMetadataNotMutationAuthority()
    {
        var vault = ScopeAuthorityTests.Scope();
        string group = $"/subscriptions/{vault.ResourceGroup.Subscription.SubscriptionId:D}/resourceGroups/{vault.ResourceGroup.ResourceGroup}";
        string subscription = $"/subscriptions/{vault.ResourceGroup.Subscription.SubscriptionId:D}";
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            "{\"value\":[" + AssignmentJson() + "," + AssignmentJson(group) + "," + AssignmentJson(subscription) + "]}")));
        var client = new VaultAdministration(new Credential(), backend);
        var rows = await client.ListRoleAssignmentsAsync(vault, new CollectionLimits());
        await Assert.That(rows.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(rows.Complete).IsTrue();
        await Assert.That(rows.Items.Count).IsEqualTo(3);
        bool denied = false;
        try
        {
            client.PrepareReceipt(rows.Items[1].Scope, ManagementMutation.CreateRoleAssignment);
        }
        catch (ArgumentException)
        {
            denied = true;
        }
        await Assert.That(denied).IsTrue();
        await Assert.That(JsonSerializer.Serialize(rows.Items[1])).IsEqualTo("{}");
    }

    [Test]
    public async Task SixOperationsUseActualSdkWithBoundCoordinatesAndRevision()
    {
        var credential = new Credential();
        var backend = new WireBackend(async (request, token) =>
        {
            var uri = request.RequestUri!;
            if (uri.Host != "management.azure.com" ||
                !uri.Query.Contains("api-version=2022-04-01", StringComparison.Ordinal))
                throw new InvalidOperationException("Wrong RBAC wire target.");
            if (request.Method == HttpMethod.Delete && uri.AbsolutePath == AssignmentPath)
                return WireBackend.Json(204, "");
            if (request.Method == HttpMethod.Put && uri.AbsolutePath == AssignmentPath)
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                var properties = body.RootElement.GetProperty("properties");
                if (properties.GetProperty("principalId").GetString() != PrincipalId.ToString("D") ||
                    properties.GetProperty("roleDefinitionId").GetString() != DefinitionPath)
                    throw new InvalidOperationException("Wrong RBAC body.");
                return WireBackend.Json(201, AssignmentJson());
            }
            if (uri.AbsolutePath == AssignmentPath) return WireBackend.Json(200, AssignmentJson());
            if (uri.AbsolutePath == DefinitionPath) return WireBackend.Json(200, DefinitionJson());
            if (uri.AbsolutePath.EndsWith("/roleAssignments", StringComparison.Ordinal))
                return WireBackend.Json(200, "{\"value\":[" + AssignmentJson() + "]}");
            if (uri.AbsolutePath.EndsWith("/roleDefinitions", StringComparison.Ordinal))
                return WireBackend.Json(200, "{\"value\":[" + DefinitionJson() + "]}");
            throw new InvalidOperationException("Unexpected RBAC dispatch.");
        });
        var client = new VaultAdministration(credential, backend);
        var scope = Assignment();
        var definition = Definition();
        var create = client.PrepareReceipt(scope, ManagementMutation.CreateRoleAssignment);
        var created = await client.CreateRoleAssignmentAsync(scope, definition, PrincipalId, create);
        await Assert.That(created.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(create.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That((await client.GetRoleAssignmentAsync(scope)).Value.PrincipalId).IsEqualTo(PrincipalId);
        var assignments = await client.ListRoleAssignmentsAsync(ScopeAuthorityTests.Scope(), new CollectionLimits());
        await Assert.That(assignments.Complete).IsTrue();
        await Assert.That(assignments.Items.Count).IsEqualTo(1);
        var role = await client.GetRoleDefinitionAsync(definition);
        await Assert.That(role.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(role.Value.Permissions[0].Actions[0]).IsEqualTo("Microsoft.KeyVault/vaults/read");
        await Assert.That((await client.ListRoleDefinitionsAsync(definition.Subscription, new CollectionLimits())).Complete)
            .IsTrue();
        var delete = client.PrepareReceipt(scope, ManagementMutation.DeleteRoleAssignment);
        await Assert.That((await client.DeleteRoleAssignmentAsync(scope, delete)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(delete.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(JsonSerializer.Serialize(created.Value)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(role.Value)).IsEqualTo("{}");
        await Assert.That(credential.Audiences.All(a => a == "https://management.azure.com/.default")).IsTrue();
    }

    [Test]
    public async Task ForeignReceiptAndDefinitionFailBeforeCredentials()
    {
        var credential = new Credential();
        var backend = new WireBackend((_, _) => throw new InvalidOperationException("Unexpected wire."));
        var client = new VaultAdministration(credential, backend);
        var scope = Assignment();
        var foreign = new VaultAdministration(new Credential(), backend)
            .PrepareReceipt(scope, ManagementMutation.CreateRoleAssignment);
        await Assert.That((await client.CreateRoleAssignmentAsync(scope, Definition(), PrincipalId, foreign)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateRoleAssignment);
        var definition = new RoleDefinitionScope(new SubscriptionScope(Guid.NewGuid()), DefinitionId);
        await Assert.That((await client.CreateRoleAssignmentAsync(scope, definition, PrincipalId, receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(credential.Audiences.Count).IsEqualTo(0);
    }

    [Test]
    public async Task ForeignReturnedScopeIsNotPublished()
    {
        var backend = new WireBackend((_, _) =>
            Task.FromResult(WireBackend.Json(200, AssignmentJson(ScopeAuthorityTests.Id + "-other"))));
        var result = await new VaultAdministration(new Credential(), backend).GetRoleAssignmentAsync(Assignment());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task WrongPrincipalAfterCreateRetainsUncertainEvidenceAndCannotReplay()
    {
        bool exists = false;
        var backend = new WireBackend((_, _) =>
        {
            if (exists) throw new InvalidOperationException("Mutation replayed.");
            exists = true;
            return Task.FromResult(WireBackend.Json(201, AssignmentJson(principal: Guid.NewGuid())));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Assignment();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateRoleAssignment);
        await Assert.That((await client.CreateRoleAssignmentAsync(scope, Definition(), PrincipalId, receipt)).Status)
            .IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.CreateRoleAssignmentAsync(scope, Definition(), PrincipalId, receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(exists).IsTrue();
    }
}
