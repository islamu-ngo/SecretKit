using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ProjectsEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition definition) =>
        definition.Key.Operation.EndsWith(".ListProjects", StringComparison.Ordinal) &&
        definition.Key.Variant is "type.CertificateManager" or "type.Kms" or "type.SecretScanning" or
            "type.Pam" or "type.AgentVault" ? "owned-non-secret-project-witness-unavailable" : null;

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        if (c.Operation == "CreateProject")
        {
            await CreateAsync(c, token);
            return;
        }
        await c.EnsureProjectAsync(token);
        if (c.Operation.Contains("Environment", StringComparison.Ordinal))
            await EnvironmentAsync(c, token);
        else if (c.Operation.Contains("Tag", StringComparison.Ordinal))
            await TagAsync(c, token);
        else if (c.Operation.Contains("Role", StringComparison.Ordinal))
            await RoleAsync(c, token);
        else
            await ProjectAsync(c, token);
    }

    private static async ValueTask CreateAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string slug = ProjectFamilyContext.FreshName();
        string? description = c.Variant == "description.value" ? ProjectFamilyContext.FreshName() : null;
        bool protection = c.Variant == "deleteProtection.true";
        bool defaults = c.Variant != "createDefaultEnvironments.false";
        string? kms = c.Variant == "kmsKeyId.value" ? c.Required("kmsKeyId") : null;
        string? template = null;
        if (c.Variant == "template.value")
        {
            ProjectTemplateSummary seeded = await ProjectTemplatesEffects.SeedAsync(c,
                new ProjectTemplateConfiguration(environments: ProjectTemplateCollection<ProjectTemplateEnvironment>
                    .FromValues([new("Witness", "witness", 1)])), token);
            template = seeded.Id;
        }
        c.OwnProject(slug);
        Func<ManagementRequest<ProjectSummary>> request = () => ProjectOperations.CreateProject(c.OrganizationId,
            slug, slug, description, protection, defaults, template, kms);
        bool Match(ProjectSummary p) => p.Slug == slug && p.Name == slug && p.Description == description &&
            Field(p.HasDeleteProtection, protection) && (kms is null || Field(p.KmsSecretManagerKeyId, kms));
        await c.CaseAsync(request, Match, async (applied, ct) =>
        {
            SecretOutcome<ProjectSummary> observed = await c.ExecuteAsync(
                () => ProjectOperations.GetProjectBySlug(c.OrganizationId, slug), NativeIdentityRole.Observer, ct);
            if (!applied) return observed.Status == SecretStatus.Absent;
            if (!observed.IsSuccess || !Match(observed.Value) || !observed.Value.Environments.IsPresent ||
                observed.Value.Environments.IsNull) return false;
            IReadOnlyList<ProjectEnvironmentReference> environments = observed.Value.Environments.Value;
            return template is not null ? environments.Any(e => e.Slug == "witness") :
                defaults ? environments.Count > 0 : environments.Count == 0;
        }, token);
    }

    private static async ValueTask ProjectAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string org = c.OrganizationId, id = c.ProjectId;
        ProjectSummary before = await c.NeedAsync(() => ProjectOperations.GetProject(org, id),
            NativeIdentityRole.Observer, token);
        if (c.Operation == "ListProjects")
        {
            ProjectType? type = c.Variant switch
            {
                "type.omitted" => null,
                "type.CertificateManager" => ProjectType.CertificateManager,
                "type.Kms" => ProjectType.Kms,
                "type.SecretScanning" => ProjectType.SecretScanning,
                "type.Pam" => ProjectType.Pam,
                "type.AgentVault" => ProjectType.AgentVault,
                _ => ProjectType.SecretManager
            };
            bool? roles = c.Variant == "includeRoles.omitted" ? null : c.Variant == "includeRoles.true";
            string? expectedType = type switch
            {
                null => null,
                ProjectType.SecretManager => "secret-manager",
                ProjectType.CertificateManager => "cert-manager",
                ProjectType.Kms => "kms",
                ProjectType.SecretScanning => "secret-scanning",
                ProjectType.Pam => "pam",
                _ => "agent-vault"
            };
            Func<ManagementRequest<ManagementPage<ProjectSummary>>> request = () => ProjectOperations.ListProjects(org, type, roles);
            bool Match(ManagementPage<ProjectSummary> page) => page.IsComplete &&
                (roles != true || page.Items.All(p => p.Roles.IsPresent && !p.Roles.IsNull)) &&
                (expectedType is null || page.Items.All(p => p.Type == expectedType)) &&
                (type is null or ProjectType.SecretManager ? page.Items.Any(p => p.Id == id && p.Slug == before.Slug) :
                    page.Items.All(p => p.Id != id));
            await c.CaseAsync(request, Match, async (_, ct) =>
            {
                SecretOutcome<ManagementPage<ProjectSummary>> observed = await c.ExecuteAsync(request, NativeIdentityRole.Observer, ct);
                return observed.IsSuccess && Match(observed.Value);
            }, token);
            return;
        }
        if (c.Operation == "UpdateProject")
        {
            await UpdateAsync(c, before, token);
            return;
        }
        Func<ManagementRequest<ProjectSummary>> factory = c.Operation switch
        {
            "GetProject" => () => ProjectOperations.GetProject(org, id),
            "GetProjectBySlug" => () => ProjectOperations.GetProjectBySlug(org, before.Slug),
            "DeleteProject" => () => ProjectOperations.DeleteProject(org, id),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        await c.CaseAsync(factory, p => p.Id == id && p.Slug == before.Slug, async (applied, ct) =>
        {
            SecretOutcome<ProjectSummary> observed = await c.ExecuteAsync(
                () => ProjectOperations.GetProject(org, id), NativeIdentityRole.Observer, ct);
            return applied && c.Operation == "DeleteProject" ? observed.Status == SecretStatus.Absent :
                observed.IsSuccess && observed.Value.Id == id && observed.Value.Name == before.Name && observed.Value.Slug == before.Slug;
        }, token);
    }

    private static async ValueTask UpdateAsync(ProjectFamilyContext c, ProjectSummary before, CancellationToken token)
    {
        string v = c.Variant;
        string? name = v == "name.omitted" ? null : ProjectFamilyContext.FreshName();
        string? slug = v is "name.omitted" or "slug.value" ? ProjectFamilyContext.FreshName() : null;
        // Register the new owned selector before dispatch so cleanup remains possible
        // after a renamed project, including an uncertain operation result.
        if (slug is not null) c.OwnProject(slug, before.Id);
        string? description = v == "description.value" ? ProjectFamilyContext.FreshName() : null;
        bool? protection = BooleanVariant(v, "deleteProtection");
        int? retention = v == "auditRetentionDays.value" ? 7 : null;
        bool? sharing = BooleanVariant(v, "secretSharing");
        bool? caps = BooleanVariant(v, "autoCapitalization");
        bool? encrypted = BooleanVariant(v, "encryptedMetadata");
        int? versions = v == "pointInTimeVersionLimit.value" ? 3 : null;
        bool? snapshots = BooleanVariant(v, "showLegacySnapshots");
        string[]? ignores = v == "secretDetectionIgnoreValues.value" ? [ProjectFamilyContext.FreshName()] : null;
        Func<ManagementRequest<ProjectSummary>> request = () => ProjectOperations.UpdateProject(c.OrganizationId, c.ProjectId,
            name, slug, description, protection, retention, sharing, caps, encrypted, versions, snapshots, ignores);
        bool Match(ProjectSummary p, bool changed) => p.Id == before.Id &&
            p.Name == (changed ? name ?? before.Name : before.Name) &&
            p.Slug == (changed ? slug ?? before.Slug : before.Slug) &&
            p.Description == (changed ? description ?? before.Description : before.Description) &&
            Matches(p.HasDeleteProtection, before.HasDeleteProtection, changed ? protection : null) &&
            Matches(p.AuditLogsRetentionDays, before.AuditLogsRetentionDays, changed ? retention : null) &&
            Matches(p.SecretSharing, before.SecretSharing, changed ? sharing : null) &&
            Matches(p.AutoCapitalization, before.AutoCapitalization, changed ? caps : null) &&
            Matches(p.EnforceEncryptedSecretManagerSecretMetadata, before.EnforceEncryptedSecretManagerSecretMetadata, changed ? encrypted : null) &&
            Matches(p.PitVersionLimit, before.PitVersionLimit, changed ? versions : null) &&
            Matches(p.ShowSnapshotsLegacy, before.ShowSnapshotsLegacy, changed ? snapshots : null) &&
            (changed && ignores is not null ? p.SecretDetectionIgnoreValues.IsPresent && !p.SecretDetectionIgnoreValues.IsNull &&
                p.SecretDetectionIgnoreValues.Value.SequenceEqual(ignores) :
                SameCollection(p.SecretDetectionIgnoreValues, before.SecretDetectionIgnoreValues));
        await c.CaseAsync(request, p => Match(p, true), async (applied, ct) =>
        {
            SecretOutcome<ProjectSummary> observed = await c.ExecuteAsync(
                () => ProjectOperations.GetProject(c.OrganizationId, c.ProjectId), NativeIdentityRole.Observer, ct);
            return observed.IsSuccess && Match(observed.Value, applied);
        }, token);
    }

    private static async ValueTask EnvironmentAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string org = c.OrganizationId, project = c.ProjectId, slug = ProjectFamilyContext.FreshName();
        string name = ProjectFamilyContext.FreshName();
        bool creating = c.Operation == "CreateEnvironment";
        ProjectEnvironment? before = creating ? null : await c.NeedAsync(
            () => ProjectOperations.CreateEnvironment(org, project, name, slug, 2), NativeIdentityRole.Setup, token);
        if (c.Operation == "RestoreEnvironment")
            await c.NeedAsync(() => ProjectOperations.DeleteEnvironment(org, project, before!.Id), NativeIdentityRole.Setup, token);
        string id = before?.Id ?? "";
        double? position = c.Variant == "position.value" ? 3.5 : null;
        string? changedName = c.Variant == "name.omitted" ? null : ProjectFamilyContext.FreshName();
        string? changedSlug = c.Variant is "name.omitted" or "slug.value" ? ProjectFamilyContext.FreshName() : null;
        Func<ManagementRequest<ProjectEnvironment>> request = c.Operation switch
        {
            "CreateEnvironment" => () => ProjectOperations.CreateEnvironment(org, project, name, slug, position),
            "GetEnvironment" => () => ProjectOperations.GetEnvironment(org, project, id),
            "GetEnvironmentBySlug" => () => ProjectOperations.GetEnvironmentBySlug(org, project, slug),
            "UpdateEnvironment" => () => ProjectOperations.UpdateEnvironment(org, project, id, changedName, changedSlug, position),
            "DeleteEnvironment" => () => ProjectOperations.DeleteEnvironment(org, project, id, c.Variant == "permanently.true"),
            "RestoreEnvironment" => () => ProjectOperations.RestoreEnvironment(org, project, id),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        bool Match(ProjectEnvironment e, bool applied) => (creating || e.Id == id) &&
            e.Name == (applied && c.Operation == "UpdateEnvironment" ? changedName ?? name : name) &&
            e.Slug == (applied && c.Operation == "UpdateEnvironment" ? changedSlug ?? slug : slug) &&
            (creating ? position is null || e.Position == position : e.Position ==
                (applied && c.Operation == "UpdateEnvironment" ? position ?? before!.Position : before!.Position));
        await c.CaseAsync(request, e => Match(e, true), async (applied, ct) =>
        {
            ProjectSummary state = await c.NeedAsync(() => ProjectOperations.GetProject(org, project),
                NativeIdentityRole.Observer, ct);
            if (!state.Environments.IsPresent || state.Environments.IsNull ||
                !state.DeletedEnvironments.IsPresent || state.DeletedEnvironments.IsNull) return false;
            bool deleted = applied && c.Operation == "DeleteEnvironment" || !applied && c.Operation == "RestoreEnvironment";
            if (deleted)
                return state.Environments.Value.All(e => e.Id != id) &&
                    (c.Variant == "permanently.true" && applied
                        ? state.DeletedEnvironments.Value.All(e => e.Id != id)
                        : state.DeletedEnvironments.Value.Any(e => e.Id == id && e.Slug == slug));
            string selectedSlug = applied && c.Operation == "UpdateEnvironment" ? changedSlug ?? slug : slug;
            SecretOutcome<ProjectEnvironment> observed = await c.ExecuteAsync(
                () => ProjectOperations.GetEnvironmentBySlug(org, project, selectedSlug), NativeIdentityRole.Observer, ct);
            return creating && !applied ? observed.Status == SecretStatus.Absent :
                observed.IsSuccess && Match(observed.Value, applied) && observed.Value.SoftDeletedAt is null &&
                state.Environments.Value.Any(e => e.Id == observed.Value.Id && e.Slug == selectedSlug);
        }, token);
    }

    private static async ValueTask TagAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string org = c.OrganizationId, project = c.ProjectId, slug = ProjectFamilyContext.FreshName();
        bool creating = c.Operation == "CreateTag";
        ProjectTag? before = creating ? null : await c.NeedAsync(
            () => ProjectOperations.CreateTag(org, project, slug, "#123456"), NativeIdentityRole.Setup, token);
        string id = before?.Id ?? "", next = ProjectFamilyContext.FreshName();
        bool Match(ProjectTag tag, bool applied) => (creating || tag.Id == id) &&
            tag.Slug == (applied && c.Operation == "UpdateTag" ? next : slug) &&
            tag.Color == (applied && c.Operation == "UpdateTag" ? "#654321" : "#123456");
        if (c.Operation == "ListTags")
        {
            await c.CaseAsync(() => ProjectOperations.ListTags(org, project),
                page => page.IsComplete && page.Items.Any(t => Match(t, false)), async (_, ct) =>
                {
                    SecretOutcome<ProjectTag> observed = await c.ExecuteAsync(() => ProjectOperations.GetTag(org, project, id),
                        NativeIdentityRole.Observer, ct);
                    return observed.IsSuccess && Match(observed.Value, false);
                }, token);
            return;
        }
        Func<ManagementRequest<ProjectTag>> request = c.Operation switch
        {
            "CreateTag" => () => ProjectOperations.CreateTag(org, project, slug, "#123456"),
            "GetTag" => () => ProjectOperations.GetTag(org, project, id),
            "GetTagBySlug" => () => ProjectOperations.GetTagBySlug(org, project, slug),
            "UpdateTag" => () => ProjectOperations.UpdateTag(org, project, id, next, "#654321"),
            "DeleteTag" => () => ProjectOperations.DeleteTag(org, project, id),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        await c.CaseAsync(request, t => Match(t, true), async (applied, ct) =>
        {
            string selectedSlug = applied && c.Operation == "UpdateTag" ? next : slug;
            SecretOutcome<ProjectTag> observed = await c.ExecuteAsync(
                () => ProjectOperations.GetTagBySlug(org, project, selectedSlug), NativeIdentityRole.Observer, ct);
            return creating && !applied || applied && c.Operation == "DeleteTag" ?
                observed.Status == SecretStatus.Absent : observed.IsSuccess && Match(observed.Value, applied);
        }, token);
    }

    private static async ValueTask RoleAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string org = c.OrganizationId, project = c.ProjectId, slug = ProjectFamilyContext.FreshName();
        var change = new ProjectRoleChange(slug, slug, permissions:
            [new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
                conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("witness"))])]);
        RoleSummary seeded = await c.NeedAsync(() => RoleChangeOperations.CreateProjectRole(org, project, change),
            NativeIdentityRole.Setup, token);
        var canary = await ProjectCanary.CreateAsync(c, project, "witness", token);
        var outside = await ProjectCanary.CreateAsync(c, project, "outside", token);
        await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(org, project, c.Required("runtimeIdentityId"),
            new MembershipRoleSelection(roles: [new(slug)])), NativeIdentityRole.Setup, token);
        c.Probe.Contract(await canary.ReadAsync(NativeIdentityRole.Runtime, true, token) &&
            await outside.ReadAsync(NativeIdentityRole.Runtime, false, token), NativeFailure.MissingPrerequisite);
        bool Match(RoleSummary r) => r.Id == seeded.Id && r.Name == slug && r.Slug == slug &&
            (c.Operation == "ListProjectRoles" || r.Permissions is { Count: > 0 } &&
                r.Permissions.Any(p => p.HasConditions && !p.IncludesConditionValues));
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            SecretOutcome<RoleSummary> observed = await c.ExecuteAsync(
                () => ProjectOperations.GetProjectRole(org, project, seeded.Id), NativeIdentityRole.Observer, ct);
            bool deleted = applied && c.Operation == "DeleteProjectRole";
            return (deleted ? observed.Status == SecretStatus.Absent : observed.IsSuccess && Match(observed.Value)) &&
                await canary.ReadAsync(NativeIdentityRole.Runtime, !deleted, ct) &&
                await outside.ReadAsync(NativeIdentityRole.Runtime, false, ct);
        }
        if (c.Operation == "ListProjectRoles")
            await c.CaseAsync(() => ProjectOperations.ListProjectRoles(org, project),
                p => p.IsComplete && p.Items.Any(Match), Observe, token);
        else
        {
            Func<ManagementRequest<RoleSummary>> request = c.Operation switch
            {
                "GetProjectRole" => () => ProjectOperations.GetProjectRole(org, project, seeded.Id),
                "GetProjectRoleBySlug" => () => ProjectOperations.GetProjectRoleBySlug(org, project, slug),
                "DeleteProjectRole" => () => ProjectOperations.DeleteProjectRole(org, project, seeded.Id),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            await c.CaseAsync(request, Match, Observe, token);
        }
    }

    private static bool? BooleanVariant(string variant, string field) =>
        variant == field + ".true" ? true : variant == field + ".false" ? false : null;
    internal static bool Field<T>(ProjectField<T> field, T value) where T : notnull =>
        field.IsPresent && !field.IsNull && EqualityComparer<T>.Default.Equals(field.Value, value);
    private static bool Matches(ProjectField<bool> value, ProjectField<bool> before, bool? selected) =>
        selected is { } expected ? Field(value, expected) : Same(value, before);
    private static bool Matches(ProjectField<double> value, ProjectField<double> before, int? selected) =>
        selected is { } expected ? Field(value, (double)expected) : Same(value, before);
    private static bool Same<T>(ProjectField<T> value, ProjectField<T> before) where T : notnull =>
        value.IsPresent == before.IsPresent && value.IsNull == before.IsNull &&
        (!value.IsPresent || value.IsNull || EqualityComparer<T>.Default.Equals(value.Value, before.Value));
    private static bool SameCollection(ProjectField<IReadOnlyList<string>> value, ProjectField<IReadOnlyList<string>> before) =>
        value.IsPresent == before.IsPresent && value.IsNull == before.IsNull &&
        (!value.IsPresent || value.IsNull || value.Value.SequenceEqual(before.Value));
}

/// <summary>An owned secret value read through separately selected runtime and observer credentials.</summary>
internal sealed class ProjectCanary(ProjectFamilyContext context, string project, string environment, string key, SecretMaterial material)
{
    internal static async ValueTask<ProjectCanary> CreateAsync(ProjectFamilyContext c, string project, string environment,
        CancellationToken token, bool createEnvironment = true, IReadOnlyList<string>? tagIds = null)
    {
        if (createEnvironment)
            await c.NeedAsync(() => ProjectOperations.CreateEnvironment(c.OrganizationId, project, environment, environment, 1),
                NativeIdentityRole.Setup, token);
        string key = "K" + Guid.NewGuid().ToString("N");
        SecretMaterial material = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
        c.Cleanup(_ => { material.Dispose(); return ValueTask.FromResult(true); });
        await using InfisicalClient setup = c.Environment.CreateClient(NativeIdentityRole.Setup);
        if (tagIds is null)
        {
            var reference = new SecretReference(setup.Authority, new InfisicalSecretAddress(project, environment, "/", key));
            var receipt = new MutationReceipt(reference);
            SecretOutcome<InfisicalStaticChange> created = await setup.CreateAsync(reference, material, receipt, token);
            c.Probe.Contract(created.IsSuccess && created.Value.Disposition == InfisicalChangeDisposition.Applied &&
                receipt.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
        }
        else
        {
            var reference = new SecretReference(setup.Authority, new InfisicalBulkAddress(project, environment, "/"));
            InfisicalBulkSecret[] items = [new(key, material, tagIds: tagIds)];
            var receipt = new InfisicalBulkReceipt(setup, reference, items, InfisicalBulkOperation.Create);
            var authority = new InfisicalNativeAuthority(setup.Authority, c.Environment.Tokens(NativeIdentityRole.Setup),
                project, environment, "/");
            SecretOutcome<InfisicalBulkObservation> created = await setup.CreateSecretsAsync(reference,
                items, authority, receipt, token);
            c.Probe.Contract(created.IsSuccess && created.Value.AllApplied && created.Value.Items.Count == 1 &&
                receipt.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
        }
        var witness = new ProjectCanary(c, project, environment, key, material);
        c.Probe.Contract(await witness.ReadAsync(NativeIdentityRole.Observer, true, token), NativeFailure.MissingPrerequisite);
        return witness;
    }

    internal async ValueTask<bool> ReadAsync(NativeIdentityRole role, bool allowed, CancellationToken token)
    {
        await using InfisicalClient reader = context.Environment.CreateClient(role);
        bool matched = await ReadAsync(reader, allowed, token);
        if (matched && allowed && role == NativeIdentityRole.Runtime)
            context.Environment.ConfirmPrerequisite(context.Definition.Key.Scope,
                "selected-runtime-identity", NativeObservation.Matched);
        return matched;
    }

    internal async ValueTask<bool> ReadAsync(InfisicalClient reader, bool allowed, CancellationToken token)
    {
        var reference = new SecretReference(reader.Authority, new InfisicalSecretAddress(project, environment, "/", key));
        SecretOutcome<SecretRead> result = await reader.ReadAsync(reference, token);
        if (!result.IsSuccess) return !allowed && result.Status == SecretStatus.Denied;
        using SecretRead read = result.Value;
        if (!allowed) return false;
        char[] expected = material.ExportCharacters(), actual = read.Material.ExportCharacters();
        try
        {
            return actual.AsSpan().SequenceEqual(expected);
        }
        finally { Array.Clear(expected); Array.Clear(actual); }
    }

    internal async ValueTask<bool> InspectAsync(NativeIdentityRole role, bool allowed, CancellationToken token)
    {
        await using InfisicalClient reader = context.Environment.CreateClient(role);
        SecretOutcome<SecretInventory> result = await reader.InspectAsync(
            new InfisicalInventoryScope(reader.Authority, project, environment, "/"), token);
        if (!result.IsSuccess) return !allowed && result.Status == SecretStatus.Denied;
        return allowed && result.Value.IsComplete && result.Value.Items.Any(i =>
            i.Reference.Address is InfisicalSecretAddress address && address.ProjectId == project &&
            address.Environment == environment && address.Key == key);
    }

    internal async ValueTask<bool> ChangeAsync(ProjectRoleAction action, bool allowed, CancellationToken token)
    {
        string selectedKey = action == ProjectRoleAction.Create ? "K" + Guid.NewGuid().ToString("N") : key;
        using SecretMaterial changed = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
        await using InfisicalClient runtime = context.Environment.CreateRuntimeClient();
        bool matched;
        if (action == ProjectRoleAction.Delete)
        {
            var reference = new SecretReference(runtime.Authority, new InfisicalBulkAddress(project, environment, "/"));
            InfisicalBulkSecret[] items = [new(selectedKey)];
            var receipt = new InfisicalBulkReceipt(runtime, reference, items, InfisicalBulkOperation.Delete);
            var authority = new InfisicalNativeAuthority(runtime.Authority, context.Environment.Tokens(NativeIdentityRole.Runtime),
                project, environment, "/");
            SecretOutcome<InfisicalBulkObservation> outcome = await runtime.DeleteSecretsAsync(reference,
                items, authority, receipt, token);
            matched = allowed ? outcome.IsSuccess && outcome.Value.AllApplied && outcome.Value.Items.Count == 1 &&
                receipt.Evidence == DispatchEvidence.Applied :
                outcome.Status == SecretStatus.Denied && receipt.Evidence == DispatchEvidence.Rejected;
        }
        else
        {
            var reference = new SecretReference(runtime.Authority, new InfisicalSecretAddress(project, environment, "/", selectedKey));
            var receipt = new MutationReceipt(reference);
            SecretOutcome<InfisicalStaticChange> outcome = action == ProjectRoleAction.Create ?
                await runtime.CreateAsync(reference, changed, receipt, token) :
                await runtime.UpdateValueAsync(reference, changed, receipt, token);
            matched = allowed ? outcome.IsSuccess && outcome.Value.Disposition == InfisicalChangeDisposition.Applied &&
                receipt.Evidence == DispatchEvidence.Applied :
                outcome.Status == SecretStatus.Denied && receipt.Evidence == DispatchEvidence.Rejected;
        }
        await using InfisicalClient observer = context.Environment.CreateObserverClient();
        SecretOutcome<SecretRead> observed = await observer.ReadAsync(new(observer.Authority,
            new InfisicalSecretAddress(project, environment, "/", selectedKey)), token);
        if (allowed && action == ProjectRoleAction.Delete || !allowed && action == ProjectRoleAction.Create)
        {
            if (observed.IsSuccess) observed.Value.Dispose();
            return matched && observed.Status == SecretStatus.Absent;
        }
        if (!observed.IsSuccess) return false;
        using SecretRead read = observed.Value;
        char[] expected = (allowed ? changed : material).ExportCharacters(), actual = read.Material.ExportCharacters();
        try { return matched && actual.AsSpan().SequenceEqual(expected); }
        finally { Array.Clear(expected); Array.Clear(actual); }
    }
}
