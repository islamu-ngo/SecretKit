using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class AuthInputLifetimeTests
{
    private const string Identity = "11111111-1111-4111-8111-111111111111";
    private const string Material = "owned-auth-input-canary";

    [Test]
    public async Task DisposedKubernetesInputCannotReenterAttachmentValidation()
    {
        using var input = new KubernetesAuthConfigurationInput();
        input.Dispose();

        await Assert.That(() => WorkloadIdentityAuthenticationOperations.KubernetesAuthConfigurationTarget(
            "org", Identity, input)).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("kubernetes")]
    [Arguments("ldap")]
    [Arguments("spiffe-write")]
    [Arguments("spiffe-copy")]
    [Arguments("tls")]
    public async Task ConcurrentRequestConstructionAndDisposalNeverPublishesPartialMaterial(string kind)
    {
        // Stress coverage of permitted public outcomes, not proof of a particular midpoint schedule.
        for (int iteration = 0; iteration < 16; iteration++)
        {
            using var material = SecretMaterial.FromText(Material);
            using var bundle = SpiffeTrustBundleInput.Static(material);
            var (input, serialize) = Create(kind, material, bundle);
            using (input)
            {
                await Validate(serialize(), kind);
                var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                Task<byte[]?> first = Attempt();
                Task<byte[]?> second = Attempt();
                Task disposed = Task.Run(async () => { await start.Task; input.Dispose(); });
                start.SetResult();
                await Task.WhenAll(first, second, disposed).WaitAsync(TimeSpan.FromSeconds(10));
                if (first.Result is { } firstBody) await Validate(firstBody, kind);
                if (second.Result is { } secondBody) await Validate(secondBody, kind);
                await Assert.That(() => serialize()).Throws<ObjectDisposedException>();

                Task<byte[]?> Attempt() => Task.Run(async () =>
                {
                    await start.Task;
                    try { return serialize(); }
                    catch (ObjectDisposedException) { return null; }
                });
            }
        }
    }

    private static (IDisposable Input, Func<byte[]> Serialize) Create(string kind,
        SecretMaterial material, SpiffeTrustBundleInput bundle)
    {
        switch (kind)
        {
            case "kubernetes":
                var kubernetes = new KubernetesAuthConfigurationInput("service", "namespace", tokenReviewerJwt: material);
                return (kubernetes, () => Copy(WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth("org", Identity, kubernetes)));
            case "ldap":
                var ldap = LdapAuthConfigurationInput.FromConnection("ldaps://directory.test", "bind", material, "root", material);
                return (ldap, () => Copy(ExternalIdentityAuthenticationOperations.AttachLdapAuth("org", Identity, ldap)));
            case "spiffe-write":
                var spiffe = new SpiffeAuthConfigurationInput("example.test", "spiffe://example.test/service", "audience", bundle);
                return (spiffe, () => Copy(ExternalIdentityAuthenticationOperations.AttachSpiffeAuth("org", Identity, spiffe)));
            case "spiffe-copy":
                return (bundle, () =>
                {
                    using var copy = new SpiffeAuthConfigurationInput("example.test", "spiffe://example.test/service", "audience", bundle);
                    return Copy(ExternalIdentityAuthenticationOperations.AttachSpiffeAuth("org", Identity, copy));
                });
            case "tls":
                var tls = new TlsCertAuthConfigurationInput(material);
                return (tls, () => Copy(ExternalIdentityAuthenticationOperations.AttachTlsCertAuth("org", Identity, tls)));
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }
    }

    private static byte[] Copy<T>(ManagementRequest<T> request) where T : notnull
    {
        using (request) return request.CopyBody() ?? throw new InvalidOperationException("Expected an owned request body.");
    }

    private static async Task Validate(byte[] body, string kind)
    {
        try
        {
            using var json = JsonDocument.Parse(body);
            var root = json.RootElement;
            string? value = kind switch
            {
                "kubernetes" => root.GetProperty("tokenReviewerJwt").GetString(),
                "ldap" => root.GetProperty("bindPass").GetString(),
                "tls" => root.GetProperty("caCertificate").GetString(),
                _ => root.GetProperty("trustBundleDistribution").GetProperty("bundle").GetString()
            };
            await Assert.That(value).IsEqualTo(Material);
            if (kind == "ldap")
                await Assert.That(root.GetProperty("ldapCaCertificate").GetString()).IsEqualTo(Material);
        }
        finally { CryptographicOperations.ZeroMemory(body); }
    }
}
