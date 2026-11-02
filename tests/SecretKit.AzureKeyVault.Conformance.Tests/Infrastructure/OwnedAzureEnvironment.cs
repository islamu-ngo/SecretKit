using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

internal sealed class OwnedAzureEnvironment : IDisposable
{
    private readonly SelectedCredential[] credentials;
    private readonly JsonElement families;
    private readonly NativePrerequisiteObservations prerequisites = new();
    [JsonIgnore] public Uri VaultUri { get; }

    private OwnedAzureEnvironment(Uri vaultUri, SelectedCredential[] selected, JsonElement familyInputs)
    {
        VaultUri = vaultUri;
        credentials = selected;
        families = familyInputs;
    }

    public static OwnedAzureEnvironment Create(JsonElement settings)
    {
        var selected = new List<SelectedCredential>();
        try
        {
            Uri vault = new(settings.GetProperty("vaultUri").GetString()!, UriKind.Absolute);
            if (vault.Scheme != "https" || vault.UserInfo.Length != 0 || vault.Query.Length != 0 ||
                vault.Fragment.Length != 0 || vault.AbsolutePath != "/")
                throw new InvalidOperationException("native-missing-input");
            string[] roles = ["setup", "runtime", "denied", "administrative", "observer"];
            var tokens = new HashSet<string>(StringComparer.Ordinal);
            foreach (string role in roles)
            {
                JsonElement input = settings.GetProperty(role);
                string token = input.GetProperty("token").GetString()!;
                DateTimeOffset expires = input.GetProperty("expiresAt").GetDateTimeOffset();
                if (string.IsNullOrWhiteSpace(token) || !tokens.Add(token) || expires <= DateTimeOffset.UtcNow)
                    throw new InvalidOperationException("native-missing-role");
                selected.Add(new SelectedCredential(SecretMaterial.FromText(token), expires));
            }
            JsonElement familyInputs = settings.GetProperty("families");
            if (familyInputs.ValueKind != JsonValueKind.Object) throw new InvalidOperationException("native-missing-input");
            return new(vault, selected.ToArray(), familyInputs.Clone());
        }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or
            ArgumentException or FormatException)
        {
            foreach (SelectedCredential credential in selected) credential.Dispose();
            throw new InvalidOperationException("native-missing-input");
        }
    }

    public JsonElement RequireFamilyInput(string family) =>
        families.TryGetProperty(family, out JsonElement input) && input.ValueKind == JsonValueKind.Object
            ? input : throw new NativeCaseFailureException("missing-input");

    public TokenCredential Credential(NativeIdentityRole role) => credentials[(int)role];
    public AzureKeyVaultClient CreateClient(NativeIdentityRole role, HttpPipelineTransport? transport = null) =>
        new(VaultUri, Credential(role), transport);
    public AzureKeyVaultClient CreateRuntimeClient(HttpPipelineTransport? transport = null) =>
        CreateClient(NativeIdentityRole.Runtime, transport);
    public AzureKeyVaultClient CreateDeniedClient(HttpPipelineTransport? transport = null) =>
        CreateClient(NativeIdentityRole.Denied, transport);
    public AzureKeyVaultClient CreateObserverClient(HttpPipelineTransport? transport = null) =>
        CreateClient(NativeIdentityRole.Observer, transport);
    public void ConfirmPrerequisite(string scope, string prerequisite, NativeObservation observation) =>
        prerequisites.Confirm("AzureKeyVault", scope, prerequisite, observation);
    public NativePrerequisiteResult[] PrerequisiteResults(IReadOnlyList<NativePrerequisiteKey> expected) =>
        prerequisites.Results(expected);
    public void Dispose()
    {
        foreach (SelectedCredential credential in credentials) credential.Dispose();
    }
    public override string ToString() => "[OwnedAzureEnvironment]";

    private sealed class SelectedCredential(SecretMaterial material, DateTimeOffset expiresAt) : TokenCredential, IDisposable
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (expiresAt <= DateTimeOffset.UtcNow) throw new NativeCaseFailureException("missing-input");
            return new(material.Reveal(), expiresAt);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
        public void Dispose() => material.Dispose();
        public override string ToString() => "[SelectedCredential]";
    }
}

internal static partial class AzureNativeCases
{
    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected) => RegisterFamilies(registry, environment, expected);

    static partial void RegisterFamilies(NativeCaseRegistry registry, OwnedAzureEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected);
}
