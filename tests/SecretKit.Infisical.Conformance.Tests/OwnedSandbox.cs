using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

/// <summary>Test-only ownership boundary; it never provisions or retries a resource.</summary>
internal sealed class OwnedSandbox : IDisposable
{
    internal const string AppDigest = "sha256:c063089e4525b033fe6ab9e6858c3afb395ad38d363dcbfa6cbb6122a99a4eea";
    private readonly SecretMaterial _setupToken;

    internal OwnedSandbox(Uri origin, string owner, string organizationId, SecretMaterial setupToken)
    {
        if (origin.Scheme != "http" || origin.Host != "127.0.0.1" || origin.IsDefaultPort ||
            origin.AbsolutePath != "/" || origin.Query.Length != 0 || origin.Fragment.Length != 0 ||
            origin.UserInfo.Length != 0)
            throw new InvalidOperationException("An explicit owned IPv4 loopback origin is required.");
        if (!owner.StartsWith("secretkit-sdk-", StringComparison.Ordinal) ||
            owner.Length != "secretkit-sdk-".Length + 8 ||
            owner["secretkit-sdk-".Length..].Any(character => !char.IsAsciiHexDigit(character)))
            throw new InvalidOperationException("An exact owned sandbox identifier is required.");
        if (!Guid.TryParseExact(organizationId, "D", out _))
            throw new InvalidOperationException("An explicit generated organization is required.");
        Origin = origin;
        Owner = owner;
        OrganizationId = organizationId;
        _setupToken = setupToken.Copy();
    }

    [JsonIgnore] internal Uri Origin { get; }
    [JsonIgnore] internal string Owner { get; }
    [JsonIgnore] internal string OrganizationId { get; }
    internal SecretMaterial CopySetupToken() => _setupToken.Copy();

    internal async Task VerifyAsync(string workingDirectory, CancellationToken cancellationToken)
    {
        var pod = await OwnedProcess.RunAsync("podman",
            ["pod", "inspect", Owner, "--format", "{{json .Labels}}"], workingDirectory, cancellationToken: cancellationToken);
        using var labels = JsonDocument.Parse(pod.Output);
        if (pod.ExitCode != 0 || !labels.RootElement.TryGetProperty("secretkit-sdk-owned", out var owned) ||
            owned.GetString() != "true")
            throw new InvalidOperationException("Sandbox ownership was not established.");
        var image = await OwnedProcess.RunAsync("podman", ["inspect", Owner + "-app", "--format", "{{.ImageDigest}}"],
            workingDirectory, cancellationToken: cancellationToken);
        var ports = await OwnedProcess.RunAsync("podman", ["port", Owner + "-app"],
            workingDirectory, cancellationToken: cancellationToken);
        if (image.ExitCode != 0 || image.Output.Trim() != AppDigest || ports.ExitCode != 0 ||
            ports.Output.Trim() != $"8080/tcp -> 127.0.0.1:{Origin.Port}")
            throw new InvalidOperationException("The pinned sandbox image or loopback ingress did not match.");
    }

    public void Dispose() => _setupToken.Dispose();
    public override string ToString() => "[OwnedSandbox]";
}
