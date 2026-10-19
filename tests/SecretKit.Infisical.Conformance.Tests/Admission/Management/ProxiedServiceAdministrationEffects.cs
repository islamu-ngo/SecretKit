using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal interface IProxyBackendObserver
{
    // Provision fresh credentials and backend within the newly owned project, not a canned pass report.
    ValueTask<ProxyCredentialFixture> PrepareAsync(string organizationId, string projectId,
        string environment, string ownedName, IInfisicalTokenSource setup, CancellationToken token);
    ValueTask<ProxyBackendFacts> SendThroughAsync(string serviceId, string challenge,
        ProxiedServiceCredentialRole role, ProxiedServiceSubstitutionSurface surface,
        IInfisicalTokenSource selectedIdentity, CancellationToken token);
    ValueTask<SecretStatus> RemoveFixtureAsync(string projectId, string ownedName,
        IInfisicalTokenSource setup, CancellationToken token);
}

internal sealed class ProxyCredentialFixture(string secretKey, string dynamicSecretName, string dynamicSecretField,
    string hostPattern, SecretMaterial expectedValue) : IDisposable
{
    [JsonIgnore] public string SecretKey { get; } = secretKey;
    [JsonIgnore] public string DynamicSecretName { get; } = dynamicSecretName;
    [JsonIgnore] public string DynamicSecretField { get; } = dynamicSecretField;
    [JsonIgnore] public string HostPattern { get; } = hostPattern;
    [JsonIgnore] public SecretMaterial ExpectedValue { get; } = expectedValue;
    public void Dispose() => ExpectedValue.Dispose();
    public override string ToString() => "[ProxyCredentialFixture]";
}

internal sealed class ProxyBackendFacts(string serviceId, string challenge, SecretStatus status,
    int backendRequests, SecretMaterial? substitutedValue, ProxiedServiceCredentialRole? observedRole = null,
    ProxiedServiceSubstitutionSurface? observedSurface = null, string? headerName = null) : IDisposable
{
    [JsonIgnore] public string ServiceId { get; } = serviceId;
    [JsonIgnore] public string Challenge { get; } = challenge;
    public SecretStatus Status { get; } = status;
    public int BackendRequests { get; } = backendRequests;
    [JsonIgnore] public SecretMaterial? SubstitutedValue { get; } = substitutedValue;
    public ProxiedServiceCredentialRole? ObservedRole { get; } = observedRole;
    public ProxiedServiceSubstitutionSurface? ObservedSurface { get; } = observedSurface;
    [JsonIgnore] public string? HeaderName { get; } = headerName;
    public void Dispose() => SubstitutedValue?.Dispose();
    public override string ToString() => "[ProxyBackendFacts]";
}

internal static class ProxiedServiceAdministrationEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d) =>
        d.Key.Operation.EndsWith(".Update", StringComparison.Ordinal) ? "primary-patch-persistence-contract" : null;

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, GovernanceObservers observers,
        CancellationToken token)
    {
        IProxyBackendObserver observer = observers.Proxy ?? InfisicalProxyObserver.FromInputs(c.Environment) ??
            throw new NativeCaseFailureException("missing-input");
        await c.EnsureProjectAsync(token, true);
        string environment = "witness";
        await c.NeedAsync(() => ProjectOperations.CreateEnvironment(c.OrganizationId, c.ProjectId,
            "Witness", environment), NativeIdentityRole.Setup, token);
        string name = ProjectFamilyContext.FreshName();
        c.Cleanup(async ct => await observer.RemoveFixtureAsync(c.ProjectId, name,
            c.Environment.Tokens(NativeIdentityRole.Setup), ct) is SecretStatus.Success or SecretStatus.Absent);
        using ProxyCredentialFixture fixture = await observer.PrepareAsync(c.OrganizationId, c.ProjectId,
            environment, name, c.Environment.Tokens(NativeIdentityRole.Setup), token);
        string v = c.Variant;
        string? path = v.EndsWith("secretPath.value", StringComparison.Ordinal) ? "/" : null;
        ProxiedServiceCredentialRole role = v is "credential.role.CredentialSubstitution" or
            "credential.surface.Header" or "credential.surface.Path" or "credential.surface.Query" or
            "credential.surface.Body" || v.Contains("placeholder", StringComparison.Ordinal) ||
            v.Contains("substitutionSurfaces", StringComparison.Ordinal) ?
            ProxiedServiceCredentialRole.CredentialSubstitution : ProxiedServiceCredentialRole.HeaderRewrite;
        ProxiedServiceSubstitutionSurface surface = v switch
        {
            "credential.surface.Path" => ProxiedServiceSubstitutionSurface.Path,
            "credential.surface.Query" => ProxiedServiceSubstitutionSurface.Query,
            "credential.surface.Body" => ProxiedServiceSubstitutionSurface.Body,
            _ => ProxiedServiceSubstitutionSurface.Header
        };
        bool dynamic = v == "credential.dynamic-secret" || v.Contains("dynamicSecret", StringComparison.Ordinal);
        bool Omitted(string field) => v == "ProxiedServiceCredentialInput." + field + ".omitted";
        string? headerName = Omitted("headerName") ? null : "X-SecretKit-Witness";
        string? prefix = v == "ProxiedServiceCredentialInput.headerPrefix.value" ? "Witness " : null;
        string? key = !dynamic && !Omitted("secretKey") || v == "ProxiedServiceCredentialInput.secretKey.value" ?
            fixture.SecretKey : null;
        using SecretMaterial? placeholder = v == "ProxiedServiceCredentialInput.placeholderValue.value" ?
            SecretMaterial.FromText("SK_PLACEHOLDER") : null;
        using var credential = new ProxiedServiceCredentialInput(role,
            dynamic && !Omitted("dynamicSecretField") ? fixture.DynamicSecretField : null,
            dynamic && !Omitted("dynamicSecretName") ? fixture.DynamicSecretName : null,
            headerName, prefix,
            Omitted("headerPurpose") ? null : v == "ProxiedServiceCredentialInput.headerPurpose.Username" ?
                ProxiedServiceHeaderPurpose.Username : ProxiedServiceHeaderPurpose.Password,
            role == ProxiedServiceCredentialRole.CredentialSubstitution && !Omitted("placeholderKey") ? "SK_PLACEHOLDER" : null,
            placeholder, key,
            role == ProxiedServiceCredentialRole.CredentialSubstitution && !Omitted("substitutionSurfaces") ? [surface] : null);
        bool? enabled = v == "ProxiedServiceCreation.isEnabled.false" ? false :
            v == "ProxiedServiceCreation.isEnabled.true" ? true : null;
        using var creation = new ProxiedServiceCreation(c.ProjectId, environment, name, fixture.HostPattern,
            [credential], path, enabled);
        string? id = null;
        // Resolve by the fresh owned name before cleanup. No create replay after an uncertain result.
        c.Cleanup(async ct =>
        {
            SecretOutcome<ProxiedServiceSummary> found = await c.ExecuteAsync(
                () => ProxiedServiceAdministrationOperations.GetByName(c.OrganizationId, c.ProjectId, environment, name, path),
                NativeIdentityRole.Observer, ct);
            if (found.Status == SecretStatus.Absent) return true;
            if (!found.IsSuccess) return false;
            using ProxiedServiceSummary service = found.Value;
            string selectedId = service.Id;
            if (id is not null && selectedId != id) return false;
            SecretOutcome<ProxiedServiceSummary> removed = await c.ExecuteAsync(
                () => ProxiedServiceAdministrationOperations.Delete(c.OrganizationId, c.ProjectId, selectedId),
                NativeIdentityRole.Setup, ct);
            if (removed.IsSuccess) removed.Value.Dispose();
            SecretOutcome<ProxiedServiceSummary> absent = await c.ExecuteAsync(
                () => ProxiedServiceAdministrationOperations.Get(c.OrganizationId, c.ProjectId, selectedId),
                NativeIdentityRole.Observer, ct);
            if (absent.IsSuccess) absent.Value.Dispose();
            return removed.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        if (c.Operation != "Create")
        {
            using ProxiedServiceSummary seeded = await c.NeedAsync(
                () => ProxiedServiceAdministrationOperations.Create(c.OrganizationId, creation), NativeIdentityRole.Setup, token);
            id = seeded.Id;
        }
        bool Match(ProxiedServiceSummary service)
        {
            if (service.Name != name || service.HostPattern != fixture.HostPattern ||
                id is not null && service.Id != id) return false;
            if (c.Operation == "Delete") return true;
            if (enabled is not null && service.IsEnabled != enabled || service.Credentials.Count != 1) return false;
            ProxiedServiceCredentialSummary actual = service.Credentials[0];
            return actual.Role == (role == ProxiedServiceCredentialRole.HeaderRewrite ? "header-rewrite" : "credential-substitution") &&
                (headerName is null || actual.HeaderName == headerName) && (prefix is null || actual.HeaderPrefix == prefix) &&
                (Omitted("headerPurpose") || actual.HeaderPurpose ==
                    (v == "ProxiedServiceCredentialInput.headerPurpose.Username" ? "username" : "password")) &&
                (key is null || actual.SecretKey == key) &&
                (placeholder is null || actual.PlaceholderValue is not null &&
                    SameMaterial(actual.PlaceholderValue, placeholder)) &&
                (role != ProxiedServiceCredentialRole.CredentialSubstitution || Omitted("placeholderKey") ||
                    actual.PlaceholderKey == "SK_PLACEHOLDER") &&
                (!dynamic || Omitted("dynamicSecretName") || actual.DynamicSecretName == fixture.DynamicSecretName) &&
                (!dynamic || Omitted("dynamicSecretField") || actual.DynamicSecretField == fixture.DynamicSecretField) &&
                (role != ProxiedServiceCredentialRole.CredentialSubstitution || Omitted("substitutionSurfaces") ||
                    actual.SubstitutionSurfaces is not null &&
                    actual.SubstitutionSurfaces.SequenceEqual([surface.ToString().ToLowerInvariant()]));
        }
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            SecretOutcome<ProxiedServiceSummary> found = await c.ExecuteAsync(
                () => ProxiedServiceAdministrationOperations.GetByName(c.OrganizationId, c.ProjectId, environment, name, path),
                NativeIdentityRole.Observer, ct);
            bool absent = c.Operation == "Create" && !applied || c.Operation == "Delete" && applied;
            if (absent && found.Status != SecretStatus.Absent || !absent && (!found.IsSuccess || !Match(found.Value)))
            {
                if (found.IsSuccess) found.Value.Dispose();
                return false;
            }
            string serviceId = found.IsSuccess ? found.Value.Id : id ?? name;
            if (found.IsSuccess) found.Value.Dispose();
            string challenge = ProjectFamilyContext.FreshName();
            using ProxyBackendFacts allowed = await observer.SendThroughAsync(serviceId, challenge, role, surface,
                c.Environment.Tokens(NativeIdentityRole.Runtime), ct);
            using ProxyBackendFacts denied = await observer.SendThroughAsync(serviceId, challenge, role, surface,
                c.Environment.Tokens(NativeIdentityRole.Denied), ct);
            if (denied.ServiceId != serviceId || denied.Challenge != challenge || denied.Status != SecretStatus.Denied ||
                denied.BackendRequests != 0 || denied.SubstitutedValue is not null) return false;
            if (allowed.ServiceId != serviceId || allowed.Challenge != challenge) return false;
            if (absent || enabled == false)
                return allowed.Status is SecretStatus.Denied or SecretStatus.Absent &&
                    allowed.BackendRequests == 0 && allowed.SubstitutedValue is null;
            bool matched = allowed.Status == SecretStatus.Success && allowed.BackendRequests == 1 &&
                allowed.ObservedRole == role && allowed.ObservedSurface == surface &&
                (surface != ProxiedServiceSubstitutionSurface.Header || headerName is null || allowed.HeaderName == headerName) &&
                allowed.SubstitutedValue is not null && SameMaterial(allowed.SubstitutedValue, fixture.ExpectedValue, prefix);
            if (matched)
                foreach (string prerequisite in new[] { "selected-runtime-identity", "owned-proxy-agent",
                    "proxy-backend-observer", "proxy-entitlement" })
                    c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope, prerequisite, NativeObservation.Matched);
            return matched;
        }
        if (c.Operation == "List")
            await c.CaseAsync(() => ProxiedServiceAdministrationOperations.List(c.OrganizationId, c.ProjectId, environment, path),
                list => list.ProjectSlug == c.ProjectSlug && list.Services.Count(s => Match(s)) == 1, Observe, token);
        else
        {
            Func<ManagementRequest<ProxiedServiceSummary>> factory = c.Operation switch
            {
                "Create" => () => ProxiedServiceAdministrationOperations.Create(c.OrganizationId, creation),
                "Get" => () => ProxiedServiceAdministrationOperations.Get(c.OrganizationId, c.ProjectId, id!),
                "GetByName" => () => ProxiedServiceAdministrationOperations.GetByName(c.OrganizationId, c.ProjectId, environment, name, path),
                "Delete" => () => ProxiedServiceAdministrationOperations.Delete(c.OrganizationId, c.ProjectId, id!),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            await c.CaseAsync(factory, service =>
            {
                if (!Match(service)) return false;
                if (c.Operation == "Create") id = service.Id;
                return true;
            }, Observe, token);
        }
    }

    internal static bool SameMaterial(SecretMaterial actual, SecretMaterial expected, string? prefix = null)
    {
        char[] a = actual.ExportCharacters(), e = expected.ExportCharacters();
        try
        {
            ReadOnlySpan<char> value = a;
            if (prefix is not null)
            {
                if (!value.StartsWith(prefix, StringComparison.Ordinal)) return false;
                value = value[prefix.Length..];
            }
            return value.SequenceEqual(e);
        }
        finally { Array.Clear(a); Array.Clear(e); }
    }
}
