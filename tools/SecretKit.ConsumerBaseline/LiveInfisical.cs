using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;

namespace SecretKit.ConsumerBaseline;

/// <summary>Explicit, owned-sandbox verification. No ambient identity, hidden provisioning or cleanup.</summary>
internal static class LiveInfisical
{
    internal static async Task RunAsync()
    {
        var origin = new Uri(Required("SECRETKIT_LIVE_ORIGIN"));
        if (!origin.IsLoopback) throw new InvalidOperationException("This provisioning mode requires an owned loopback sandbox.");
        string organization = Required("SECRETKIT_LIVE_ORGANIZATION");
        var tokens = new SelectedToken(Required("SECRETKIT_LIVE_ADMIN_TOKEN"));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        using var transport = new ManagementTransport(origin, new() { AllowLoopbackDevelopmentHttp = true });
        var administration = new ManagementClient(transport);
        var authority = new ManagementAuthority(administration.Authority, tokens, organization);
        string slug = "sdk-live-" + Guid.NewGuid().ToString("N")[..12];
        using var create = ProjectOperations.CreateProject(organization, "SDK live verification", slug);
        var projectReceipt = administration.CreateReceipt(create);
        var projectResult = await administration.ExecuteAsync(create, authority,
            authority.IssueGrant(create.OperationId, ProjectOperations.ProjectCreateTarget(organization, "SDK live verification", slug)),
            projectReceipt, deadline.Token);
        Require(projectResult.Status, "project-create", projectReceipt.Evidence);
        string project = projectResult.Value.Id;

        // This first slice measures the explicitly injected provisioning identity, not a runtime-only actor.
        await using var client = new InfisicalClient(origin, tokens,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        var target = new SecretReference(client.Authority, new InfisicalSecretAddress(project, "dev", "/", "SDK_LIVE_VALUE"));
        using var material = SecretMaterial.FromText(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        var writeReceipt = new MutationReceipt(target);
        var written = await client.CreateAsync(target, material, writeReceipt, deadline.Token);
        Require(written.Status, "secret-create", writeReceipt.Evidence);
        var observed = await client.ReadAsync(target, deadline.Token);
        Require(observed.Status, "fresh-read", DispatchEvidence.NotDispatched);
        using SecretRead read = observed.Value;
        if (read.Material.Reveal() != material.Reveal())
            throw new InvalidOperationException("Fresh native value did not match the owned fixture.");
        Console.WriteLine("LIVE_INFISICAL_PROJECT_WRITE_FRESH_READ_PASSED");
        Console.WriteLine("LIVE_INFISICAL_RUNTIME_IDENTITY_SEPARATION_UNVERIFIED");
    }

    private static string Required(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
            ? value : throw new InvalidOperationException("Missing explicit live verification injection.");

    private static void Require(SecretStatus status, string step, DispatchEvidence evidence)
    {
        if (status != SecretStatus.Success)
            throw new InvalidOperationException($"Live verification {step}: {status}; evidence: {evidence}.");
    }

    private sealed class SelectedToken(string selected) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(selected))));
        }
        public override string ToString() => "[SelectedLiveToken]";
    }
}
