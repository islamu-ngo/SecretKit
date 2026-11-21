using System.Net.Http.Json;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;

namespace SecretKit.LiveProvisioner;

internal static class LocalBootstrap
{
    internal static async Task RunAsync(string directory, string originText, string owner, string email, string organization,
        SecretMaterial password, CancellationToken ct, HttpClient? pipeline = null,
        Func<string, string, Uri, CancellationToken, Task>? verifySandbox = null)
    {
        if (OperatingSystem.IsWindows())
            throw new ProvisioningException("Bootstrap requires Unix file permissions.");
        var origin = LiveEnvConfig.ValidateOrigin(originText, LiveTarget.Local);
        if (!LocalSandboxReadiness.IsOwner(owner) || origin.Scheme != Uri.UriSchemeHttp || origin.Host != "127.0.0.1")
            throw new ProvisioningException("Expected an exact sandbox owner and its IPv4 loopback HTTP origin.");
        string root = RepositoryEnvironment.FindRoot(directory);
        string path = RepositoryEnvironment.Guard(root, directory);
        if (File.Exists(path) || Directory.Exists(path))
            throw new ProvisioningException("Bootstrap refuses to overwrite an existing .env.");
        await (verifySandbox ?? LocalSandboxReadiness.VerifyAsync)(root, owner, origin, ct);

        using var owned = pipeline is null ? ProviderStatus.CreateHttpClient() : null;
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, "/api/v1/admin/bootstrap"))
        {
            Content = JsonContent.Create(new { email, password = password.Reveal(), organization })
        };
        using var response = await (pipeline ?? owned!).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        using var json = await ProviderStatus.ReadAsync(response, "local bootstrap", ct);
        var result = json.RootElement;
        string org = Read(result.GetProperty("organization"), "id");
        using var token = new InfisicalAccessToken(SecretMaterial.FromText(Read(
            result.GetProperty("identity").GetProperty("credentials"), "token")));
        using var session = new ProvisioningSession(origin, org,
            new InfisicalAccessToken(token.Material.Copy()), ProvisioningSession.Network(LiveTarget.Local, pipeline));
        var automation = await session.Apply(IdentityOperations.CreateOrganizationIdentity(org, "automation", "admin"),
            "create local automation", ct);
        var policy = new UniversalAuthConfigurationInput(accessTokenTTL: 3600, accessTokenMaxTTL: 7200,
            accessTokenNumUsesLimit: 0, accessTokenPeriod: 0);
        var auth = await session.Apply(IdentityAuthenticationOperations.AttachUniversalAuth(org, automation.Id, policy),
            "attach automation Universal Auth", ct);
        string clientId = auth.ClientId ?? throw new ProvisioningException("Bootstrap did not report a Universal Auth client ID.");
        using var secret = await session.Apply(IdentityAuthenticationOperations.CreateUniversalClientSecret(org, automation.Id),
            "issue automation client secret", ct);
        string clientSecret = secret.ClientSecret.Reveal();
        foreach (string value in new[] { org, clientId, clientSecret })
            ValidateField(value);
        _ = RepositoryEnvironment.Guard(root, directory);
        await using var file = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = RepositoryEnvironment.PrivateMode
        });
        // Once the exclusive create succeeds, complete the small local write despite caller cancellation.
        await using var writer = new StreamWriter(file);
        await writer.WriteAsync($"""
            INFISICAL_MODE=local
            INFISICAL_LOCAL_ORIGIN={origin.AbsoluteUri}
            INFISICAL_LOCAL_OWNER={owner}
            INFISICAL_LOCAL_ORGANIZATION_ID={org}
            INFISICAL_LOCAL_AUTOMATION_CLIENT_ID={clientId}
            INFISICAL_LOCAL_AUTOMATION_CLIENT_SECRET={clientSecret}

            """);
    }

    private static string Read(JsonElement parent, string key) =>
        parent.GetProperty(key).GetString() is { Length: > 0 } value
            ? value : throw new ProvisioningException("Bootstrap returned incomplete credentials.");

    private static void ValidateField(string value)
    {
        if (value.Length == 0 || value.Any(char.IsControl) || value.Trim() != value)
            throw new ProvisioningException("Bootstrap returned or received a value unsuitable for .env.");
    }
}
