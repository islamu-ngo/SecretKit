using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

/// <summary>Test-only ownership boundary; it never provisions or retries a resource.</summary>
internal sealed partial class OwnedSandbox : IDisposable
{
    // Docker Hub linux/amd64 image manifest, not the multi-platform index.
    internal const string AppDigest = "sha256:44cf26b0b556bc340fd6f86c17404a2ae9ed73e783d3dcd3a53977c54c9c5e83";
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
    [JsonIgnore] internal bool Verified { get; private set; }
    internal SecretMaterial CopySetupToken() => _setupToken.Copy();

    internal async Task VerifyAsync(string workingDirectory, CancellationToken cancellationToken)
    {
        Verified = false;
        nativeInspection = null;
        var pod = await OwnedProcess.RunAsync("podman",
            ["pod", "inspect", Owner, "--format", "{{json .Labels}}"], workingDirectory, cancellationToken: cancellationToken);
        var image = await OwnedProcess.RunAsync("podman", ["container", "inspect", Owner + "-app", "--format", "{{.ImageDigest}}"],
            workingDirectory, cancellationToken: cancellationToken);
        var ports = await OwnedProcess.RunAsync("podman", ["port", Owner + "-app"],
            workingDirectory, cancellationToken: cancellationToken);
        if (pod.ExitCode != 0 || image.ExitCode != 0 || ports.ExitCode != 0)
            throw new InvalidOperationException("The pinned sandbox image or loopback ingress did not match.");
        ObserveInspection(pod.Output, image.Output, ports.Output);
        RecordNativeInspection(pod.Output, image.Output, ports.Output);
    }

    internal void ObserveInspection(string podLabels, string digest, string ingress)
    {
        Verified = false;
        if (!HasOwnershipLabel(podLabels) ||
            digest.Trim() != AppDigest || ingress.Trim() != $"8080/tcp -> 127.0.0.1:{Origin.Port}")
        {
            nativeInspection = null;
            throw new InvalidOperationException("Sandbox ownership was not established.");
        }
        Verified = true;
    }

    private static bool HasOwnershipLabel(string podLabels)
    {
        try
        {
            using var labels = JsonDocument.Parse(podLabels);
            if (labels.RootElement.ValueKind != JsonValueKind.Object)
                return false;

            var owned = false;
            foreach (var label in labels.RootElement.EnumerateObject())
            {
                if (!label.NameEquals("secretkit-sdk-owned"))
                    continue;
                if (owned || label.Value.ValueKind != JsonValueKind.String || label.Value.GetString() != "true")
                    return false;
                owned = true;
            }
            return owned;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public void Dispose() => _setupToken.Dispose();
    public override string ToString() => "[OwnedSandbox]";
}
