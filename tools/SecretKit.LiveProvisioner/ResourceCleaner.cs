using SecretKit.Infisical.Management;

namespace SecretKit.LiveProvisioner;

internal sealed class ResourceCleaner(HttpClient? pipeline = null)
{
    internal static bool IsOwnedName(string slug) =>
        slug.Length <= 64 && slug.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-') &&
        ((slug.StartsWith("sdk-conformance-", StringComparison.Ordinal) && slug.Length > "sdk-conformance-".Length) ||
        (slug.StartsWith("sdk-live-", StringComparison.Ordinal) && slug.Length > "sdk-live-".Length));

    internal async Task<int> CleanAsync(LiveEnvConfig config, string? slug, string? projectId, bool apply, CancellationToken ct)
    {
        if ((apply && projectId is null) || (slug is not null && projectId is not null) ||
            (projectId is not null && (!Guid.TryParseExact(projectId, "D", out var parsed) ||
                parsed == Guid.Empty || projectId != parsed.ToString("D"))))
            throw new ProvisioningException("Cleanup apply requires one explicit canonical --project-id; slug filtering is preview-only.");
        if (slug is not null && !IsOwnedName(slug))
            throw new ProvisioningException("Refusing a project outside the owned fixture prefixes.");
        using var session = await ProvisioningSession.OpenAsync(config, pipeline, ct);
        string org = session.OrganizationId;
        var page = await session.Apply(ProjectOperations.ListProjects(org), "list cleanup candidates", ct);
        if (!page.IsComplete)
            throw new ProvisioningException("Incomplete project inventory; refusing cleanup.");
        var candidates = page.Items.Where(p => IsOwnedName(p.Slug) && (slug is null || p.Slug == slug) &&
            (projectId is null || p.Id == projectId)).ToArray();
        if (candidates.Any(candidate => page.Items.Count(p => p.Id == candidate.Id || p.Slug == candidate.Slug) != 1))
            throw new ProvisioningException("Ambiguous project ownership; refusing cleanup.");
        if (apply)
        {
            if (candidates is not [var project])
                throw new ProvisioningException("The selected project ID is not a single visible owned-prefix candidate.");
            using var enrollment = config.BeginMutation();
            var current = await session.Apply(ProjectOperations.GetProject(org, project.Id), "verify cleanup target", ct);
            if (current.Slug != project.Slug)
                throw new ProvisioningException("Project ownership changed; refusing cleanup.");
            config.VerifyEnrollment();
            var deleted = await session.Apply(ProjectOperations.DeleteProject(org, project.Id), "delete owned fixture project", ct);
            if (deleted.Slug != project.Slug)
                throw new ProvisioningException("Delete returned unexpected project metadata; verify native state before clearing the pin.");
            config.ClearProjectPin(project.Id);
        }
        return candidates.Length;
    }
}
