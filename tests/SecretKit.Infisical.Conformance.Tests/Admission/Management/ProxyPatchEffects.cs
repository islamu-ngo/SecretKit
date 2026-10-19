using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ProxyPatchEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, GovernanceObservers observers, CancellationToken token)
    {
        var backend = observers.Proxy ?? InfisicalProxyObserver.FromInputs(c.Environment) ??
            throw new NativeCaseFailureException("missing-input");
        ProxyPatchTrial? retainedTrial = null;
        c.Cleanup(async ct =>
        {
            if (retainedTrial is not null) await retainedTrial.DisposeAsync();
            return true;
        });
        await c.EnsureProjectAsync(token, true);
        const string environment = "witness";
        await c.NeedAsync(() => ProjectOperations.CreateEnvironment(c.OrganizationId, c.ProjectId,
            "Witness", environment), NativeIdentityRole.Setup, token);
        string name = ProjectFamilyContext.FreshName();
        string renamed = ProjectFamilyContext.FreshName();
        // First registered, last cleaned: the journal proves all original work
        // settled after SDK resources and references have been removed.
        var trial = await ProxyPatchTrial.OpenAsync(c, environment, name, renamed, observers.ProxyPatch,
            opened => retainedTrial = opened, token);
        string[] fixtureNames = [name + "-first", name + "-second", name + "-selected"];
        foreach (string owned in fixtureNames)
            c.Cleanup(async ct => await backend.RemoveFixtureAsync(c.ProjectId, owned,
                c.Environment.Tokens(NativeIdentityRole.Setup), ct) is SecretStatus.Success or SecretStatus.Absent);
        using var first = await backend.PrepareAsync(c.OrganizationId, c.ProjectId, environment,
            fixtureNames[0], c.Environment.Tokens(NativeIdentityRole.Setup), token);
        using var second = await backend.PrepareAsync(c.OrganizationId, c.ProjectId, environment,
            fixtureNames[1], c.Environment.Tokens(NativeIdentityRole.Setup), token);
        using var selected = await backend.PrepareAsync(c.OrganizationId, c.ProjectId, environment,
            fixtureNames[2], c.Environment.Tokens(NativeIdentityRole.Setup), token);
        c.Probe.Contract(first.SecretKey != second.SecretKey && first.SecretKey != selected.SecretKey &&
            second.SecretKey != selected.SecretKey && !Same(first.ExpectedValue, selected.ExpectedValue),
            NativeFailure.MissingPrerequisite);
        string? id = null;
        c.Cleanup(async ct =>
        {
            foreach (string candidate in new[] { name, renamed })
            {
                var current = await c.ExecuteAsync(() => ProxiedServiceAdministrationOperations.GetByName(
                    c.OrganizationId, c.ProjectId, environment, candidate), NativeIdentityRole.Observer, ct);
                if (current.Status == SecretStatus.Absent) continue;
                if (!current.IsSuccess) return false;
                using var found = current.Value;
                if (id is not null && found.Id != id) return false;
                var deleted = await c.ExecuteAsync(() => ProxiedServiceAdministrationOperations.Delete(
                    c.OrganizationId, c.ProjectId, found.Id), NativeIdentityRole.Setup, ct);
                if (deleted.IsSuccess) deleted.Value.Dispose();
                var absent = await c.ExecuteAsync(() => ProxiedServiceAdministrationOperations.Get(
                    c.OrganizationId, c.ProjectId, found.Id), NativeIdentityRole.Observer, ct);
                if (absent.IsSuccess) absent.Value.Dispose();
                if (!deleted.IsSuccess || absent.Status != SecretStatus.Absent) return false;
            }
            return true;
        });
        using var baselineFirst = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.HeaderRewrite,
            headerName: "X-First", headerPrefix: "First ", headerPurpose: ProxiedServiceHeaderPurpose.Password,
            secretKey: first.SecretKey);
        using var baselineSecond = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.CredentialSubstitution,
            placeholderKey: "SK_SECOND", secretKey: second.SecretKey,
            substitutionSurfaces: [ProxiedServiceSubstitutionSurface.Query]);
        using var creation = new ProxiedServiceCreation(c.ProjectId, environment, name,
            first.HostPattern, [baselineFirst, baselineSecond], isEnabled: true);
        await trial.ArmAsync("Create", "seed", "selected-contract", null, token);
        using var original = await c.NeedAsync(() => ProxiedServiceAdministrationOperations.Create(
            c.OrganizationId, creation), NativeIdentityRole.Setup, token);
        id = original.Id;
        await trial.CompleteAsync(DispatchEvidence.Applied, token);
        c.Probe.Contract(trial.Fence!.ServiceId == id && original.Credentials.Count == 2 &&
            original.Credentials.Select(row => row.SecretKey).Order().SequenceEqual(
                new[] { first.SecretKey, second.SecretKey }.Order()), NativeFailure.EffectMismatch);
        await trial.ObserveAsync(token);
        string variant = c.Variant;
        bool Omitted(string field) => variant == "ProxiedServiceCredentialInput." + field + ".omitted";
        bool substitute = variant is "credential.role.CredentialSubstitution" or
            "credential.surface.Header" or "credential.surface.Path" or "credential.surface.Query" or
            "credential.surface.Body" || variant.Contains("placeholder", StringComparison.Ordinal) ||
            variant.Contains("substitutionSurfaces", StringComparison.Ordinal);
        var role = substitute ? ProxiedServiceCredentialRole.CredentialSubstitution :
            ProxiedServiceCredentialRole.HeaderRewrite;
        var surface = variant switch
        {
            "credential.surface.Path" => ProxiedServiceSubstitutionSurface.Path,
            "credential.surface.Query" => ProxiedServiceSubstitutionSurface.Query,
            "credential.surface.Body" => ProxiedServiceSubstitutionSurface.Body,
            _ => ProxiedServiceSubstitutionSurface.Header
        };
        bool dynamic = variant == "credential.dynamic-secret" || variant.Contains("dynamicSecret", StringComparison.Ordinal);
        string? header = Omitted("headerName") ? null : "X-Selected";
        string? prefix = variant == "ProxiedServiceCredentialInput.headerPrefix.value" ? "Selected " : null;
        using var placeholder = variant == "ProxiedServiceCredentialInput.placeholderValue.value" ?
            SecretMaterial.FromText("SK_SELECTED") : null;
        using var changed = new ProxiedServiceCredentialInput(role,
            dynamic && !Omitted("dynamicSecretField") ? selected.DynamicSecretField : null,
            dynamic && !Omitted("dynamicSecretName") ? selected.DynamicSecretName : null,
            header, prefix, Omitted("headerPurpose") ? null :
                variant == "ProxiedServiceCredentialInput.headerPurpose.Username" ?
                    ProxiedServiceHeaderPurpose.Username : ProxiedServiceHeaderPurpose.Password,
            substitute && !Omitted("placeholderKey") ? "SK_SELECTED" : null, placeholder,
            !dynamic && !Omitted("secretKey") || variant == "ProxiedServiceCredentialInput.secretKey.value" ?
                selected.SecretKey : null,
            substitute && !Omitted("substitutionSurfaces") ? [surface] : null);
        bool empty = variant == "patch.empty";
        bool retained = empty || variant is "credentials.omitted" or "ProxiedServiceUpdate.credentials.omitted";
        bool rename = variant == "ProxiedServiceUpdate.name.value";
        bool? enabled = variant switch
        {
            "ProxiedServiceUpdate.isEnabled.false" => false,
            "ProxiedServiceUpdate.isEnabled.true" => true,
            _ => null
        };
        using var update = new ProxiedServiceUpdate(rename ? renamed : null,
            variant == "ProxiedServiceUpdate.hostPattern.value" ? selected.HostPattern : null,
            enabled, retained ? null : [changed]);
        await trial.ArmAsync("Update", variant, c.Definition.Key.Case, id, token);
        await c.CaseAsync(() => ProxiedServiceAdministrationOperations.Update(c.OrganizationId, c.ProjectId, id, update),
            result => result.Id == id, async (_, ct) =>
            {
                bool applied = trial.Fence!.Applied;
                string currentName = applied && rename ? renamed : name;
                using var current = await c.NeedAsync(() => ProxiedServiceAdministrationOperations.Get(
                    c.OrganizationId, c.ProjectId, id), NativeIdentityRole.Observer, ct);
                if (current.Name != currentName || current.IsEnabled != (applied ? enabled ?? true : true) ||
                    current.Credentials.Count != (applied && !retained ? 1 : 2)) return false;
                await trial.ObserveAsync(ct);
                if (!applied || retained)
                {
                    return await DeliverAsync(first, ProxiedServiceCredentialRole.HeaderRewrite,
                        ProxiedServiceSubstitutionSurface.Header, "X-First", "First ", true, ct) &&
                        await DeliverAsync(second, ProxiedServiceCredentialRole.CredentialSubstitution,
                            ProxiedServiceSubstitutionSurface.Query, null, null, true, ct);
                }
                bool referenceAvailable = dynamic ? !Omitted("dynamicSecretName") :
                    !Omitted("secretKey");
                return await DeliverAsync(selected, role, surface, header, prefix,
                    enabled != false && referenceAvailable, ct);
            }, token, complete: trial.CompleteAsync);

        async ValueTask<bool> DeliverAsync(ProxyCredentialFixture fixture, ProxiedServiceCredentialRole selectedRole,
            ProxiedServiceSubstitutionSurface selectedSurface, string? selectedHeader, string? selectedPrefix,
            bool allowed, CancellationToken ct)
        {
            string challenge = ProjectFamilyContext.FreshName();
            using var accepted = await backend.SendThroughAsync(id, challenge, selectedRole, selectedSurface,
                c.Environment.Tokens(NativeIdentityRole.Runtime), ct);
            using var denied = await backend.SendThroughAsync(id, challenge, selectedRole, selectedSurface,
                c.Environment.Tokens(NativeIdentityRole.Denied), ct);
            if (denied.ServiceId != id || denied.Challenge != challenge || denied.Status != SecretStatus.Denied ||
                denied.BackendRequests != 0 || denied.SubstitutedValue is not null ||
                accepted.ServiceId != id || accepted.Challenge != challenge) return false;
            if (!allowed) return accepted.Status is SecretStatus.Denied or SecretStatus.Absent &&
                accepted.BackendRequests == 0 && accepted.SubstitutedValue is null;
            return accepted.Status == SecretStatus.Success && accepted.BackendRequests == 1 &&
                accepted.ObservedRole == selectedRole && accepted.ObservedSurface == selectedSurface &&
                (selectedSurface != ProxiedServiceSubstitutionSurface.Header || selectedHeader is null ||
                    accepted.HeaderName == selectedHeader) &&
                accepted.SubstitutedValue is not null && Same(accepted.SubstitutedValue, fixture.ExpectedValue, selectedPrefix);
        }
    }

    private static bool Same(SecretMaterial observed, SecretMaterial expected, string? prefix = null)
    {
        char[] left = observed.ExportCharacters();
        char[] right = expected.ExportCharacters();
        try
        {
            int length = prefix?.Length ?? 0;
            return left.Length == right.Length + length &&
                (prefix is null || left.AsSpan(0, length).SequenceEqual(prefix)) &&
                left.AsSpan(length).SequenceEqual(right);
        }
        finally { Array.Clear(left); Array.Clear(right); }
    }
}
