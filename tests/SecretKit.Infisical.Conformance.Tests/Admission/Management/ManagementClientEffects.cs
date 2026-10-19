using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ManagementClientEffects
{
    // Each generic execution label selects a closed, typed factory's native scenario.
    // No reflection, request reconstruction, or arbitrary operation dispatch is permitted.
    internal static NativeCaseDefinition? Resolve(NativeCaseDefinition d, NativeEnvironment? environment = null)
    {
        string operation = d.Key.Variant["factory.".Length..];
        string? member = null;
        string[]? variants = null;
        bool mutation = false;
        if (InfisicalGovernanceFamilies.Bindings.TryGetValue(operation, out var local))
        { member = local.Member; variants = local.Variants; mutation = local.Mutation; }
        else if (InfisicalProjectFamilies.Bindings.TryGetValue(operation, out var project))
        { member = project.Member; variants = project.Variants; mutation = project.Mutation; }
        else if (InfisicalIdentityFamilies.Bindings.TryGetValue(operation, out var identity))
        { member = identity.Member; variants = identity.Variants; mutation = identity.Mutation; }
        else if (InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var permission))
        { member = permission.Member; variants = permission.Variants; mutation = permission.Mutation; }
        else if (InfisicalDatabaseFamilies.Bindings.TryGetValue(operation, out var database))
        { member = database.Member; variants = database.Variants; mutation = database.Mutation; }
        else if (InfisicalIdentityAuthenticationFamilies.Bindings.TryGetValue(operation, out var authentication))
        { member = authentication.Member; variants = authentication.Variants; mutation = authentication.Mutation; }
        if (member is null || variants is null || !mutation && d.Key.Case == "lost-response-no-replay") return null;
        if (environment is not null)
        {
            var principal = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = "ProjectTemplateConfiguration.users.value" }, member);
            if (TemplatePrincipalInput.Selected(environment, "C08-IM-ProjectTemplates", principal)) return principal;
            string metadataFamily = operation.Split('.')[2] switch
            {
                "ProjectTemplateOperations" => "C08-IM-ProjectTemplates",
                "RoleChangeOperations" => "C08-IM-RoleChanges",
                "IdentityPrivilegeChangeOperations" => "C08-IM-IdentityPrivilegeChanges",
                _ => ""
            };
            var dynamic = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = DynamicPermissionContract.Variant(operation, DynamicPermissionAction.Read) }, member);
            if (DynamicPermissionInput.Selected(environment, metadataFamily, dynamic))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = DynamicPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = DynamicPermissionContract.Variant(operation, input.Action) }, member);
            }
            var folder = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = FolderPermissionContract.Variant(operation, FolderPermissionAction.Read) }, member);
            if (FolderPermissionInput.Selected(environment, metadataFamily, folder))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = FolderPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = FolderPermissionContract.Variant(operation, input.Action) }, member);
            }
            var tag = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = TagPermissionContract.Variant(operation, TagPermissionAction.Read) }, member);
            if (TagPermissionInput.Selected(environment, metadataFamily, tag))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = TagPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = TagPermissionContract.Variant(operation, input.Action) }, member);
            }
            var import = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = ImportPermissionContract.Variant(operation, ImportPermissionAction.Read) }, member);
            if (ImportPermissionInput.Selected(environment, metadataFamily, import))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = ImportPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = ImportPermissionContract.Variant(operation, input.Action) }, member);
            }
            var rotation = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = RotationPermissionContract.Variant(RotationPermissionAction.Read) }, member);
            if (RotationPermissionInput.Selected(environment, metadataFamily, rotation))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = RotationPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = RotationPermissionContract.Variant(input.Action) }, member);
            }
            var memberPermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = MemberPermissionContract.Variant(MemberPermissionAction.Read) }, member);
            if (MemberPermissionInput.Selected(environment, metadataFamily, memberPermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = MemberPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = MemberPermissionContract.Variant(input.Action) }, member);
            }
            var groupPermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = GroupPermissionContract.Variant(GroupPermissionAction.Read) }, member);
            if (GroupPermissionInput.Selected(environment, metadataFamily, groupPermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = GroupPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = GroupPermissionContract.Variant(input.Action) }, member);
            }
            var identityPermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = IdentityPermissionContract.Variant(IdentityPermissionAction.Read) }, member);
            if (IdentityPermissionInput.Selected(environment, metadataFamily, identityPermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = IdentityPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = IdentityPermissionContract.Variant(input.Action) }, member);
            }
            var projectTemplatePermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = ProjectTemplatePermissionContract.Variant(ProjectTemplatePermissionAction.Read) }, member);
            if (ProjectTemplatePermissionInput.Selected(environment, metadataFamily, projectTemplatePermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = ProjectTemplatePermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = ProjectTemplatePermissionContract.Variant(input.Action) }, member);
            }
            var rolePermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = RolePermissionContract.Variant(RolePermissionAction.Read) }, member);
            if (RolePermissionInput.Selected(environment, metadataFamily, rolePermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = RolePermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = RolePermissionContract.Variant(input.Action) }, member);
            }
            var environmentPermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = EnvironmentPermissionContract.Variant(EnvironmentPermissionAction.Read) }, member);
            if (EnvironmentPermissionInput.Selected(environment, metadataFamily, environmentPermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = EnvironmentPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = EnvironmentPermissionContract.Variant(input.Action) }, member);
            }
            var auditPermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = AuditPermissionContract.Variant(AuditPermissionAction.Read) }, member);
            if (AuditPermissionInput.Selected(environment, metadataFamily, auditPermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = AuditPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = AuditPermissionContract.Variant(input.Action) }, member);
            }
            if (WorkspacePermissionContract.Operations.Contains(operation))
            {
                var workspacePermission = new NativeCaseDefinition(d.Key with
                {
                    Operation = operation,
                    Variant = WorkspacePermissionContract.Variant(WorkspacePermissionContract.Actions(WorkspacePermissionContract.Scope(operation))[0])
                }, member);
                if (WorkspacePermissionInput.Selected(environment, metadataFamily, workspacePermission))
                {
                    var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                    var input = WorkspacePermissionInput.FromScope(scope)!;
                    return new(d.Key with { Operation = operation, Variant = WorkspacePermissionContract.Variant(input.Action) }, member);
                }
            }
            var gatewayPermission = GatewayPermissionContract.Resolve(d, environment);
            if (gatewayPermission is not null) return gatewayPermission;
            var proxyPermission = ProxyPermissionContract.Resolve(d, environment);
            if (proxyPermission is not null) return proxyPermission;
            var validationPermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = ValidationPermissionContract.Variant(ValidationPermissionAction.Read) }, member);
            if (ValidationPermissionInput.Selected(environment, metadataFamily, validationPermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = ValidationPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = ValidationPermissionContract.Variant(input.Action) }, member);
            }
            var authTemplatePermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = AuthTemplatePermissionContract.Variant(AuthTemplatePermissionAction.List) }, member);
            if (AuthTemplatePermissionInput.Selected(environment, metadataFamily, authTemplatePermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = AuthTemplatePermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = AuthTemplatePermissionContract.Variant(input.Action) }, member);
            }
            var settingsPermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = SettingsPermissionContract.Variant(SettingsPermissionAction.Read) }, member);
            if (SettingsPermissionInput.Selected(environment, metadataFamily, settingsPermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = SettingsPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = SettingsPermissionContract.Variant(input.Action) }, member);
            }
            var integrationPermission = new NativeCaseDefinition(d.Key with
            { Operation = operation, Variant = IntegrationPermissionContract.Variant(IntegrationPermissionAction.Read) }, member);
            if (IntegrationPermissionInput.Selected(environment, metadataFamily, integrationPermission))
            {
                var scope = environment.RequireFamilyInput(metadataFamily).GetProperty("scopes").GetProperty(d.Key.Scope);
                var input = IntegrationPermissionInput.FromScope(scope)!;
                return new(d.Key with { Operation = operation, Variant = IntegrationPermissionContract.Variant(input.Action) }, member);
            }
            foreach (string variant in variants)
            {
                var profiled = new NativeCaseDefinition(d.Key with { Operation = operation, Variant = variant }, member);
                if (MetadataPermissionInput.Selected(environment, metadataFamily, profiled)) return profiled;
                if (WorkloadTransitionInput.Selected(environment, "C08-IM-WorkloadIdentityAuthentication", profiled))
                    return profiled;
            }
        }
        // The execution member admits factory selection, not the cross product of that factory's variants.
        // Prefer a legal baseline branch; unavailable factory contracts stay unavailable.
        string? preferred = operation switch
        {
            "i.management.GatewayAdministrationOperations.Create" => "auth.Token",
            "i.management.ProxiedServiceAdministrationOperations.Create" => "credential.static-secret",
            _ => null
        };
        IEnumerable<string> candidates = preferred is null ? variants : new[] { preferred }.Concat(variants);
        foreach (string variant in candidates)
        {
            var selected = new NativeCaseDefinition(d.Key with { Operation = operation, Variant = variant }, member);
            if (Reason(selected) is null) return selected;
        }
        return new(d.Key with { Operation = operation, Variant = variants[0] }, member);
    }

    private static string? Reason(NativeCaseDefinition d) =>
        InfisicalGovernanceFamilies.Owns(d.Key.Operation) ? InfisicalGovernanceFamilies.UnavailableReason(d) :
        InfisicalProjectFamilies.Owns(d.Key.Operation) ? InfisicalProjectFamilies.UnavailableReason(d) :
        InfisicalIdentityFamilies.Owns(d.Key.Operation) ? InfisicalIdentityFamilies.UnavailableReason(d) :
        InfisicalPermissionFamilies.Owns(d.Key.Operation) ? InfisicalPermissionFamilies.UnavailableReason(d) :
        InfisicalDatabaseFamilies.Owns(d.Key.Operation) ? InfisicalDatabaseFamilies.UnavailableReason(d) :
        InfisicalIdentityAuthenticationFamilies.Owns(d.Key.Operation) ? InfisicalIdentityAuthenticationFamilies.UnavailableReason(d) :
        "factory-specific-native-observer-unavailable";

    internal static string? UnavailableReason(NativeCaseDefinition d)
    {
        NativeCaseDefinition? selected = Resolve(d);
        return selected is null ? d.Key.Case == "lost-response-no-replay" ?
            "read-only-factory-has-no-mutation-receipt" : "factory-specific-native-observer-unavailable" : Reason(selected);
    }

    internal static async ValueTask ExecuteAsync(NativeEnvironment environment, NativeCaseDefinition d,
        NativeCaseProbe probe, GovernanceObservers observers, CancellationToken token)
    {
        NativeCaseDefinition selected = Resolve(d, environment) ?? throw new NativeCaseFailureException("observer-unavailable");
        var registry = new NativeCaseRegistry();
        NativeCaseDefinition[] expected = [selected];
        if (InfisicalGovernanceFamilies.Owns(selected.Key.Operation))
            InfisicalGovernanceFamilies.Register(registry, environment, expected, observers);
        else if (InfisicalProjectFamilies.Owns(selected.Key.Operation))
            InfisicalProjectFamilies.Register(registry, environment, expected, organizationUsers: observers.OrganizationUsers,
                projectTypes: observers.ProjectTypes, metadataPermissions: observers.MetadataPermissions,
                templatePrincipals: observers.TemplatePrincipals, dynamicPermissions: observers.DynamicPermissions,
                folderPermissions: observers.FolderPermissions, tagPermissions: observers.TagPermissions,
                importPermissions: observers.ImportPermissions, rotationPermissions: observers.RotationPermissions,
                rotationPermissionRuntime: observers.RotationPermissionRuntime, memberPermissions: observers.MemberPermissions,
                groupPermissions: observers.GroupPermissions, identityPermissions: observers.IdentityPermissions,
                projectTemplatePermissions: observers.ProjectTemplatePermissions, rolePermissions: observers.RolePermissions,
                environmentPermissions: observers.EnvironmentPermissions, auditPermissions: observers.AuditPermissions,
                workspacePermissions: observers.WorkspacePermissions, gatewayPermissions: observers.GatewayPermissions,
                proxyPermissions: observers.ProxyPermissions, validationPermissions: observers.ValidationPermissions,
                integrationPermissions: observers.IntegrationPermissions, settingsPermissions: observers.SettingsPermissions);
        else if (InfisicalIdentityFamilies.Owns(selected.Key.Operation))
            InfisicalIdentityFamilies.Register(registry, environment, expected);
        else if (InfisicalPermissionFamilies.Owns(selected.Key.Operation))
            InfisicalPermissionFamilies.Register(registry, environment, expected, metadataPermissions: observers.MetadataPermissions,
                dynamicPermissions: observers.DynamicPermissions, folderPermissions: observers.FolderPermissions,
                tagPermissions: observers.TagPermissions, importPermissions: observers.ImportPermissions,
                rotationPermissions: observers.RotationPermissions, rotationPermissionRuntime: observers.RotationPermissionRuntime,
                memberPermissions: observers.MemberPermissions, groupPermissions: observers.GroupPermissions,
                identityPermissions: observers.IdentityPermissions, projectTemplatePermissions: observers.ProjectTemplatePermissions,
                rolePermissions: observers.RolePermissions, environmentPermissions: observers.EnvironmentPermissions,
                auditPermissions: observers.AuditPermissions, workspacePermissions: observers.WorkspacePermissions,
                gatewayPermissions: observers.GatewayPermissions, proxyPermissions: observers.ProxyPermissions,
                validationPermissions: observers.ValidationPermissions, integrationPermissions: observers.IntegrationPermissions,
                settingsPermissions: observers.SettingsPermissions, authTemplatePermissions: observers.AuthTemplatePermissions);
        else if (InfisicalDatabaseFamilies.Owns(selected.Key.Operation))
        {
            string family = selected.Key.Operation.Split('.')[2] switch
            {
                "ProjectConnectionOperations" => "ProjectConnections",
                "PostgresSecretRotationOperations" => "PostgresSecretRotations",
                "MySqlSecretRotationOperations" => "MySqlSecretRotations",
                _ => "MsSqlSecretRotations"
            };
            _ = environment.RequireFamilyInput("C08-IM-" + family);
            InfisicalDatabaseFamilies.Register(registry, environment, expected, observers.Database);
        }
        else
            InfisicalIdentityAuthenticationFamilies.Register(registry, environment, expected,
                spiffeRefresh: observers.SpiffeRefresh, organizationUsers: observers.OrganizationUsers,
                workloadTransitions: observers.WorkloadTransitions);
        registry.ValidateAgainst(expected);
        NativeCaseRegistration registration = registry.Find(selected.Key) ??
            throw new NativeCaseFailureException("contract-mismatch");
        try { await registration.Execute(probe, token); }
        catch (NativeCaseFailureException error)
        {
            probe.Contract(false, error.Message switch
            {
                "missing-input" => NativeFailure.MissingInput,
                "missing-prerequisite" => NativeFailure.MissingPrerequisite,
                "observer-unavailable" => NativeFailure.ObserverUnavailable,
                "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                "effect-mismatch" => NativeFailure.EffectMismatch,
                "contract-mismatch" => NativeFailure.ContractMismatch,
                _ => NativeFailure.UnexpectedFailure
            });
        }
    }
}
