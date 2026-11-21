using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.LiveProvisioner;

internal sealed class NativeLiveInputs(NativeHostInputs request, byte[] requestBytes, JsonDocument template) : IDisposable
{
    private const int MaximumInputBytes = 1024 * 1024;
    internal NativeHostInputs Request { get; } = request;

    internal static async Task<NativeLiveInputs> LoadAsync(string root, string? requestPath, string? settingsPath, CancellationToken token)
    {
        if (requestPath is null || settingsPath is null)
            throw new ProvisioningException("Native conformance requires an explicit request and settings template.");
        byte[]? requestBytes = null;
        byte[]? settingsBytes = null;
        JsonDocument? template = null;
        bool accepted = false;
        try
        {
            requestBytes = await ReadAsync(Path.GetFullPath(requestPath, root), token);
            NativeHostInputs request = NativeRunProtocol.Parse<NativeHostInputs>(requestBytes);
            if (request.Provider != "Infisical")
                throw new InvalidOperationException();
            settingsBytes = await ReadAsync(Path.GetFullPath(settingsPath, root), token, privateInput: true);
            // Parse from a stream so the document does not reference the input buffer cleared in finally.
            using var stream = new MemoryStream(settingsBytes, writable: false);
            template = await JsonDocument.ParseAsync(stream, new() { MaxDepth = 32 }, token);
            NativeRunProtocol.RejectDuplicates(template.RootElement);
            if (template.RootElement.ValueKind != JsonValueKind.Object ||
                !template.RootElement.TryGetProperty("families", out JsonElement families) ||
                families.ValueKind != JsonValueKind.Object || !families.EnumerateObject().Any() ||
                families.EnumerateObject().Any(f => f.Value.ValueKind != JsonValueKind.Object))
                throw new InvalidOperationException();
            var inputs = new NativeLiveInputs(request, requestBytes, template);
            accepted = true;
            return inputs;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            throw new ProvisioningException("Native request or settings template was rejected.");
        }
        finally
        {
            if (settingsBytes is not null) CryptographicOperations.ZeroMemory(settingsBytes);
            if (!accepted)
            {
                template?.Dispose();
                if (requestBytes is not null) CryptographicOperations.ZeroMemory(requestBytes);
            }
        }
    }

    internal async Task<int> RunAsync(LiveEnvConfig config, PackageCandidate candidate, LiveTokens tokens, CancellationToken token)
    {
        string root = config.RepositoryRoot;
        string output = LiveProcess.PrivateDirectory(LiveProcess.ArtifactDirectory(root), "native-");
        string selectedRequest = Path.Combine(output, "request.json");
        try
        {
            await using (FileStream file = LiveProcess.OpenPrivate(selectedRequest))
                await file.WriteAsync(requestBytes, token);
            var start = LiveProcess.Command(root, "flock", ["-o", "/tmp/secretkit-provider-engineering-build.lock", "dotnet",
                .. LiveRunner.TestArguments("NativeInfrastructureTests/InstalledNativeCasesRequireOwnedGateInputs")]);
            return await LiveProcess.RunAsync(root, new(start, new Dictionary<string, string>
            {
                ["SECRETKIT_NATIVE_REQUEST"] = selectedRequest,
                ["SECRETKIT_NATIVE_REPORT"] = Path.Combine(output, "native-report.json"),
                ["SECRETKIT_CANDIDATE_DIRECTORY"] = candidate.Directory,
                ["SECRETKIT_CANDIDATE_VERSION"] = candidate.Version
            }, writer => WriteSettings(writer, config.Origin, tokens)), token);
        }
        finally
        {
            File.Delete(selectedRequest);
        }
    }

    private void WriteSettings(Utf8JsonWriter writer, Uri origin, LiveTokens tokens)
    {
        writer.WriteStartObject();
        foreach (JsonProperty property in template.RootElement.EnumerateObject())
        {
            if (property.Name is not ("origin" or "allowLoopbackDevelopmentHttp" or
                "setup" or "runtime" or "denied" or "administrative" or "observer"))
                property.WriteTo(writer);
        }
        writer.WriteString("origin", origin.AbsoluteUri);
        writer.WriteBoolean("allowLoopbackDevelopmentHttp", origin.Scheme == Uri.UriSchemeHttp && origin.IsLoopback);
        foreach (LiveRole role in Enum.GetValues<LiveRole>())
            writer.WriteString(role.ToString().ToLowerInvariant(), tokens.Reveal(role));
        writer.WriteEndObject();
    }

    internal static void RequireUnlinked(string path)
    {
        for (string? component = Path.TrimEndingDirectorySeparator(path); component is not null;
            component = Path.GetDirectoryName(component))
            if ((File.GetAttributes(component) & FileAttributes.ReparsePoint) != 0)
                throw new ProvisioningException("The selected live path cannot contain links.");
    }

    private static async Task<byte[]> ReadAsync(string path, CancellationToken token, bool privateInput = false)
    {
        RequireUnlinked(path);
        var info = new FileInfo(path);
        if (!info.Exists || (info.Attributes & (FileAttributes.Directory | FileAttributes.Device)) != 0 ||
            info.Length is <= 0 or > MaximumInputBytes)
            throw new InvalidOperationException();
        if (privateInput && OperatingSystem.IsLinux() &&
            (File.GetUnixFileMode(path) & ~(UnixFileMode.UserRead | UnixFileMode.UserWrite)) != 0)
            throw new InvalidOperationException();
        await using FileStream file = File.OpenRead(path);
        byte[] bytes = new byte[info.Length];
        try
        {
            await file.ReadExactlyAsync(bytes, token);
            if (file.ReadByte() != -1) throw new InvalidOperationException();
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(requestBytes);
        template.Dispose();
    }
}
