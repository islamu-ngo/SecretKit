using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class NativeEnvironment : IDisposable
{
    private readonly SelectedTokens[] tokens;
    private readonly JsonElement families;
    private readonly ManagementTransport managementTransport;
    private readonly Uri requestOrigin;
    [JsonIgnore] public RotationPermissionRuntime RotationPermissionRuntime { get; }
    private readonly NativePrerequisiteObservations prerequisites = new();
    [JsonIgnore] public Uri Origin { get; }
    [JsonIgnore] public bool AllowLoopbackDevelopmentHttp { get; }

    private NativeEnvironment(Uri origin, bool loopback, SelectedTokens[] selected, JsonElement familyInputs,
        Uri? fixtureControlOrigin)
    {
        Origin = origin;
        AllowLoopbackDevelopmentHttp = loopback;
        tokens = selected;
        families = familyInputs;
        // Controlled split-plane fixtures can serve setup/observer resources on
        // a separately owned loopback origin. Native JSON never selects this seam.
        requestOrigin = fixtureControlOrigin ?? origin;
        managementTransport = new(requestOrigin, allowLoopbackDevelopmentHttp: loopback);
        RotationPermissionRuntime = new(origin, new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        }));
    }

    public static NativeEnvironment Create(JsonElement settings, Uri? fixtureControlOrigin = null)
    {
        var selected = new List<SelectedTokens>();
        try
        {
            Uri origin = new(settings.GetProperty("origin").GetString()!, UriKind.Absolute);
            bool loopback = settings.TryGetProperty("allowLoopbackDevelopmentHttp", out JsonElement allowed) &&
                allowed.GetBoolean();
            string[] roles = ["setup", "runtime", "denied", "administrative", "observer"];
            var distinct = new HashSet<string>(StringComparer.Ordinal);
            foreach (string role in roles)
            {
                string token = settings.GetProperty(role).GetString()!;
                if (string.IsNullOrWhiteSpace(token) || !distinct.Add(token))
                    throw new InvalidOperationException("native-missing-role");
                selected.Add(new(SecretMaterial.FromText(token)));
            }
            JsonElement familyInputs = settings.GetProperty("families");
            if (familyInputs.ValueKind != JsonValueKind.Object) throw new InvalidOperationException("native-missing-input");
            return new(origin, loopback, selected.ToArray(), familyInputs.Clone(), fixtureControlOrigin);
        }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or
            ArgumentException or FormatException)
        {
            foreach (SelectedTokens token in selected) token.Dispose();
            throw new InvalidOperationException("native-missing-input");
        }
    }

    public bool TryGetFamilyInput(string family, out JsonElement input)
    {
        if (!families.TryGetProperty(family, out input)) return false;
        if (input.ValueKind != JsonValueKind.Object) throw new NativeCaseFailureException("missing-input");
        return true;
    }
    public JsonElement RequireFamilyInput(string family) =>
        TryGetFamilyInput(family, out JsonElement input) ? input : throw new NativeCaseFailureException("missing-input");
    public IInfisicalTokenSource Tokens(NativeIdentityRole role) => tokens[(int)role];
    public InfisicalClient CreateClient(NativeIdentityRole role) => CreateClient(Tokens(role));
    internal InfisicalClient CreateClient(IInfisicalTokenSource identity) =>
        new(requestOrigin, identity, new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = AllowLoopbackDevelopmentHttp });
    public InfisicalClient CreateRuntimeClient() => CreateClient(NativeIdentityRole.Runtime);
    public InfisicalClient CreateDeniedClient() => CreateClient(NativeIdentityRole.Denied);
    public InfisicalClient CreateObserverClient() => CreateClient(NativeIdentityRole.Observer);
    public ManagementClient CreateManagementClient() => new(managementTransport);
    public ManagementAuthority CreateManagementAuthority(ManagementClient client, NativeIdentityRole role,
        string organizationId, string? projectId = null) =>
        new(client.Authority, Tokens(role), organizationId, projectId);
    public void ConfirmPrerequisite(string scope, string prerequisite, NativeObservation observation) =>
        prerequisites.Confirm("Infisical", scope, prerequisite, observation);
    public NativePrerequisiteResult[] PrerequisiteResults(IReadOnlyList<NativePrerequisiteKey> expected) =>
        prerequisites.Results(expected);
    public void Dispose()
    {
        managementTransport.Dispose();
        RotationPermissionRuntime.Transport.Dispose();
        foreach (SelectedTokens token in tokens) token.Dispose();
    }
    public override string ToString() => "[NativeEnvironment]";

    private sealed class SelectedTokens(SecretMaterial material) : IInfisicalTokenSource, IDisposable
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
        public void Dispose() => material.Dispose();
        public override string ToString() => "[SelectedTokens]";
    }
}

internal static partial class InfisicalNativeCases
{
    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected) => RegisterFamilies(registry, environment, expected);

    static partial void RegisterFamilies(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected);
}
