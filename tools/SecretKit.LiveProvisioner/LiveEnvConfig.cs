using SecretKit.Core;

namespace SecretKit.LiveProvisioner;

internal enum LiveTarget { Local, Remote }

internal sealed class ProvisioningException(string message) : Exception(message);

internal sealed class LiveEnvConfig : IDisposable
{
    internal LiveTarget Target { get; }
    internal Uri Origin { get; }
    internal string RepositoryRoot { get; }
    internal string OrganizationId { get; }
    internal string? Owner { get; }
    internal string AutomationClientId { get; }
    internal SecretMaterial AutomationClientSecret { get; }
    private readonly Dictionary<string, string> _pins;
    private EnvEnrollment? _enrollment;
    private string Prefix => Target == LiveTarget.Local ? "INFISICAL_LOCAL_" : "INFISICAL_REMOTE_";

    private LiveEnvConfig(Dictionary<string, string> values, string root, LiveTarget target)
    {
        Target = target;
        string prefix = Prefix;
        string? Optional(string key) => values.TryGetValue(prefix + key, out string? value) && value.Length > 0 ? value : null;
        string Required(string key) => Optional(key) ?? throw new ProvisioningException($"Missing required .env key: {prefix}{key}.");
        Origin = ValidateOrigin(Required("ORIGIN"), target);
        RepositoryRoot = root;
        OrganizationId = Required("ORGANIZATION_ID");
        Owner = target == LiveTarget.Local ? Required("OWNER") : null;
        AutomationClientId = Required("AUTOMATION_CLIENT_ID");
        _pins = new(StringComparer.Ordinal);
        foreach (string slot in EnvEnrollment.Slots)
        {
            if (Optional(slot) is not { } id) continue;
            if (!Guid.TryParseExact(id, "D", out var parsed) || parsed == Guid.Empty || id != parsed.ToString("D"))
                throw new ProvisioningException("Fixture pins must be canonical non-empty UUIDs.");
            if (_pins.ContainsValue(id))
                throw new ProvisioningException("Fixture pins must identify distinct resources.");
            _pins.Add(slot, id);
        }
        string? enrolledOrigin = Optional("ENROLLMENT_ORIGIN");
        string? enrolledOrganization = Optional("ENROLLMENT_ORGANIZATION_ID");
        if ((_pins.Count > 0 || enrolledOrigin is not null || enrolledOrganization is not null) &&
            (enrolledOrigin != Origin.AbsoluteUri || enrolledOrganization != OrganizationId))
            throw new ProvisioningException("Fixture enrollment scope does not match the selected origin and organization.");
        AutomationClientSecret = SecretMaterial.FromText(Required("AUTOMATION_CLIENT_SECRET"));
    }

    internal static LiveEnvConfig Load(string workingDirectory, LiveTarget? target = null)
    {
        string root = RepositoryEnvironment.FindRoot(workingDirectory);
        string path = RepositoryEnvironment.Guard(root, workingDirectory);
        string text = EnvEnrollment.Read(path);
        var config = Parse(text, root, target);
        config._enrollment = new EnvEnrollment(root, workingDirectory, text);
        return config;
    }

    internal string? Pin(string slot) => _pins.GetValueOrDefault(slot);

    internal IDisposable BeginMutation() => (_enrollment ??
        throw new ProvisioningException("Fixture mutation requires a checked clone-root .env.")).BeginMutation();

    internal void VerifyEnrollment() => _enrollment!.Verify();

    internal void Enroll(string slot, string id)
    {
        if (!Guid.TryParseExact(id, "D", out var parsed) || parsed == Guid.Empty || id != parsed.ToString("D") ||
            _pins.ContainsKey(slot) || _pins.ContainsValue(id))
            throw new ProvisioningException("Provider returned an invalid or overlapping fixture ID; inspect the dispatched operation.");
        _enrollment!.Change((Prefix + slot, id),
            (Prefix + "ENROLLMENT_ORIGIN", Origin.AbsoluteUri),
            (Prefix + "ENROLLMENT_ORGANIZATION_ID", OrganizationId));
        _pins.Add(slot, id);
    }

    internal void ClearProjectPin(string id)
    {
        foreach (string slot in EnvEnrollment.Slots.Take(3))
        {
            if (Pin(slot) != id) continue;
            _enrollment!.Change((Prefix + slot, ""));
            _pins.Remove(slot);
        }
    }

    internal static LiveEnvConfig Parse(string text, string repositoryRoot, LiveTarget? target = null)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        using var reader = new StringReader(text);
        while (reader.ReadLine() is { } line)
        {
            line = line.Trim();
            if (line.Length == 0 || line[0] == '#')
                continue;
            int separator = line.IndexOf('=');
            if (separator <= 0)
                throw new ProvisioningException("Invalid .env assignment.");
            string name = line[..separator];
            string value = line[(separator + 1)..];
            if (!name.StartsWith("INFISICAL_", StringComparison.Ordinal) ||
                name.Any(c => c is not (>= 'A' and <= 'Z' or >= '0' and <= '9' or '_')) ||
                value.Any(char.IsControl) || !values.TryAdd(name, value))
                throw new ProvisioningException("Invalid or duplicate .env assignment.");
        }
        LiveTarget selected = values.GetValueOrDefault("INFISICAL_MODE") switch
        {
            "local" => LiveTarget.Local,
            "remote" => LiveTarget.Remote,
            _ => throw new ProvisioningException("INFISICAL_MODE must be local or remote.")
        };
        return new(values, repositoryRoot, target ?? selected);
    }

    internal static Uri ValidateOrigin(string value, LiveTarget target)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var origin) ||
            origin.UserInfo.Length != 0 || origin.Query.Length != 0 || origin.Fragment.Length != 0 ||
            origin.AbsolutePath != "/" || value.Contains('\\') ||
            (target == LiveTarget.Remote ? origin.Scheme != Uri.UriSchemeHttps :
                !origin.IsLoopback || (origin.Scheme != Uri.UriSchemeHttp && origin.Scheme != Uri.UriSchemeHttps)))
            throw new ProvisioningException("Invalid Infisical origin for the selected mode.");
        return origin;
    }

    public void Dispose() => AutomationClientSecret.Dispose();
    public override string ToString() => "[LiveEnvConfig]";
}
