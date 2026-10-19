using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.TestFixtures;

internal enum NativeIdentityRole { Setup, Runtime, Denied, Administrative, Observer }

internal sealed record NativeProviderScope(string Label, string Provider, string Deployment, string ApiVersion,
    string RuntimeIdentity, string ObserverIdentity, string SetupIdentity, string DeniedIdentity,
    string AdministrativeIdentity);

internal sealed record NativePrerequisiteKey(string Provider, string Scope, string Prerequisite);
internal sealed record NativePrerequisiteResult(string Provider, string Scope, string Prerequisite, bool Confirmed);

internal sealed record NativeRunRequest(string Purpose, string Provider, string Kind, string Platform,
    string Version, string SourceCommit, string ScopeSha256, long RunId, int RunAttempt, long JobId,
    NativeProviderScope[] Scopes, NativeCaseDefinition[] Expected, NativePrerequisiteKey[] Prerequisites)
{
    [JsonIgnore] public JsonElement FixtureSettings { get; init; }
    public override string ToString() => "[NativeRunRequest]";

    public void Validate()
    {
        if (Purpose is not ("development-observation" or "release-observation") ||
            Provider is not ("Infisical" or "AzureKeyVault") ||
            Kind is not ("native-operations" or "live-conformance") ||
            Platform is not ("linux-x64-net10.0" or "windows-x64-net10.0") ||
            string.IsNullOrWhiteSpace(Version) || !Hash(SourceCommit, 40) || !Hash(ScopeSha256, 64) ||
            (Purpose == "release-observation" ? RunId <= 0 || RunAttempt <= 0 || JobId <= 0
                : RunId != 0 || RunAttempt != 0 || JobId != 0) ||
            Scopes.Length is 0 or > 64 || Expected.Length is 0 or > 65536 ||
            Scopes.Any(s => s.Provider != Provider || !ValidScope(s)) ||
            Scopes.Select(s => s.Label).Distinct(StringComparer.Ordinal).Count() != Scopes.Length ||
            Expected.Any(d => d.Key.Provider != Provider || !Scopes.Any(s => s.Label == d.Key.Scope) ||
                string.IsNullOrWhiteSpace(d.Member) || d.Member.Length > 4096 ||
                !Label(d.Key.Operation) || string.IsNullOrWhiteSpace(d.Key.Variant) ||
                d.Key.Variant.Length > 4096 || !Label(d.Key.Case)) ||
            Expected.Select(d => d.Key).Distinct().Count() != Expected.Length ||
            Prerequisites.Length > 65536 ||
            Prerequisites.Any(p => p.Provider != Provider || !Scopes.Any(s => s.Label == p.Scope) ||
                !Label(p.Prerequisite)) || Prerequisites.Distinct().Count() != Prerequisites.Length)
            throw new InvalidOperationException("native-request-contract");
    }

    internal static bool ValidScope(NativeProviderScope s)
    {
        string[] identities = [s.SetupIdentity, s.RuntimeIdentity, s.DeniedIdentity,
            s.AdministrativeIdentity, s.ObserverIdentity];
        return Label(s.Label) && Label(s.Deployment) && Label(s.ApiVersion) &&
            identities.All(Label) && identities.Distinct(StringComparer.Ordinal).Count() == 5;
    }

    internal static bool Label(string value) => value is { Length: > 0 and <= 128 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_');
    private static bool Hash(string value, int length) => value is not null && value.Length == length &&
        value.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f');
}

internal sealed record NativeInstallationResult(string OperatingSystem, string Architecture, string Framework);
internal sealed record NativeRunResult(string Provider, string Kind, string Platform, string Version,
    string SourceCommit, string ScopeSha256, DateTimeOffset StartedAt, DateTimeOffset CompletedAt,
    NativeCaseResult[] Cases, NativePrerequisiteResult[] Prerequisites, NativeInstallationResult Installation);

internal sealed record NativeRunEnvelope(NativeRunRequest Request, JsonElement FixtureSettings)
{
    public override string ToString() => "[NativeRunEnvelope]";
}

internal static class NativeRunProtocol
{
    internal const int MaximumBytes = 32 * 1024 * 1024;
    internal const int ResultBytes = 16 * 1024 * 1024;
    internal static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        IgnoreReadOnlyProperties = true,
        MaxDepth = 32
    };

    internal static async Task<byte[]> ReadBoundedAsync(Stream stream, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(chunk, token).ConfigureAwait(false)) != 0)
        {
            if (buffer.Length + count > MaximumBytes) throw new InvalidOperationException("native-input-size");
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }

    internal static T Parse<T>(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaximumBytes) throw new InvalidOperationException("native-input-size");
        using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        RejectDuplicates(document.RootElement);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions) ?? throw new InvalidOperationException("native-input-contract");
    }

    internal static void RejectDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidOperationException("native-input-duplicate");
                RejectDuplicates(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (JsonElement item in element.EnumerateArray()) RejectDuplicates(item);
    }
}

internal sealed class NativePrerequisiteObservations
{
    private readonly Dictionary<NativePrerequisiteKey, bool> observed = [];
    public void Confirm(string provider, string scope, string prerequisite, NativeObservation observation)
    {
        if (!NativeRunRequest.Label(scope) || !NativeRunRequest.Label(prerequisite))
            throw new InvalidOperationException("native-prerequisite-contract");
        lock (observed)
        {
            var key = new NativePrerequisiteKey(provider, scope, prerequisite);
            bool matched = observation == NativeObservation.Matched;
            observed[key] = observed.TryGetValue(key, out bool previous) ? previous && matched : matched;
        }
    }

    public NativePrerequisiteResult[] Results(IReadOnlyList<NativePrerequisiteKey> expected)
    {
        lock (observed)
            return expected.Select(p => new NativePrerequisiteResult(p.Provider, p.Scope, p.Prerequisite,
                observed.GetValueOrDefault(p))).ToArray();
    }
}
