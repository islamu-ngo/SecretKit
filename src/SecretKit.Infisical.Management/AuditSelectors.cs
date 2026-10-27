using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

/// <summary>Closed scalar or copied-array audit selection; array values use the native catalog.</summary>
public sealed class AuditEventFilter
{
    private readonly string[] _values;
    private AuditEventFilter(string parameter, string[] values, bool array)
    {
        Parameter = parameter;
        _values = values;
        IsArray = array;
    }
    internal string Parameter { get; }
    internal bool IsArray { get; }
    /// <summary>Selects one bounded native event-class string without expanding it into an array.</summary>
    public static AuditEventFilter Class(string value) =>
        new("eventClass", [Text(value, 51)], false);
    /// <summary>Selects one bounded native event-type string without requiring catalog membership.</summary>
    public static AuditEventFilter Type(string value) =>
        new("eventType", [Text(value, 17467)], false);
    /// <summary>Copies up to four known event classes for repeated native query selectors.</summary>
    public static AuditEventFilter Classes(IReadOnlyList<AuditEventClass> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        string[] copy = values.Take(5).Select(value => value switch
        {
            AuditEventClass.Management => "management",
            AuditEventClass.Authentication => "authentication",
            AuditEventClass.Authorization => "authorization",
            AuditEventClass.DataAccess => "data-access",
            _ => throw new ArgumentOutOfRangeException(nameof(values))
        }).ToArray();
        if (copy.Length > 4) throw new ArgumentException("At most four event classes are supported.");
        return new("eventClass", copy, true);
    }
    /// <summary>Copies at most 691 catalog-recognized event types; unknown entries are rejected.</summary>
    public static AuditEventFilter Types(IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        string[] copy = values.Take(692).ToArray();
        if (copy.Length > 691 || copy.Any(value => value is null || !AuditEventTypeNames.Contains(value)))
            throw new ArgumentException("Invalid native event type selection.");
        return new("eventType", copy, true);
    }
    internal string Query() => string.Concat(_values.Select(value => "&" + Parameter + "=" + Uri.EscapeDataString(value)));
    internal static string Text(string value, int maximum = 1024)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > maximum || value.Any(char.IsControl))
            throw new ArgumentException("Invalid protected audit filter.");
        return value;
    }
    /// <summary>Returns a marker without exposing filter values.</summary>
    public override string ToString() => "[AuditEventFilter]";
}

/// <summary>Protected fixed native audit fields, not arbitrary query parameters or permission evidence.</summary>
public sealed class AuditSelectors
{
    private static readonly HashSet<string> ActorTypes = new(StringComparer.Ordinal)
    {
        "platform", "kmipClient", "user", "service", "identity", "scimClient",
        "acmeProfile", "acmeAccount", "estAccount", "scepAccount", "unknownUser",
        "gateway", "relay", "kmipServer", "agentVaultProxy"
    };
    private static readonly HashSet<string> AgentTypes = new(StringComparer.Ordinal)
    {
        "web", "cli", "k8-operator", "terraform", "other", "InfisicalPythonSDK", "InfisicalNodeSDK"
    };
    /// <summary>Captures fixed audit filters; null omits a selector and empty strings remain explicit selections.</summary>
    public AuditSelectors(string? actor = null, string? actorType = null, string? environment = null,
        AuditEventFilter? eventClass = null, string? eventMetadata = null,
        AuditEventFilter? eventType = null, string? secretKey = null, string? secretPath = null,
        string? userAgentType = null)
    {
        if (actorType is not null && !ActorTypes.Contains(actorType) ||
            userAgentType is not null && !AgentTypes.Contains(userAgentType) ||
            eventClass is not null && eventClass.Parameter != "eventClass" ||
            eventType is not null && eventType.Parameter != "eventType")
            throw new ArgumentException("Invalid native audit discriminator.");
        Actor = actor is null ? null : AuditEventFilter.Text(actor);
        ActorType = actorType;
        Environment = environment is null ? null : AuditEventFilter.Text(environment);
        EventClass = eventClass;
        EventMetadata = eventMetadata is null ? null : AuditEventFilter.Text(eventMetadata);
        EventType = eventType;
        SecretKey = secretKey is null ? null : AuditEventFilter.Text(secretKey);
        SecretPath = secretPath is null ? null : AuditEventFilter.Text(secretPath);
        UserAgentType = userAgentType;
    }
    /// <summary>Gets the selected actor coordinate, or null to omit actor filtering.</summary>
    [JsonIgnore] public string? Actor { get; }
    /// <summary>Gets the native actor discriminator, or null to omit it.</summary>
    [JsonIgnore] public string? ActorType { get; }
    /// <summary>Gets the environment selector, or null to omit it.</summary>
    [JsonIgnore] public string? Environment { get; }
    /// <summary>Gets the scalar or repeated event-class selection, or null when omitted.</summary>
    [JsonIgnore] public AuditEventFilter? EventClass { get; }
    /// <summary>Gets the protected event-metadata selector, or null when omitted.</summary>
    [JsonIgnore] public string? EventMetadata { get; }
    /// <summary>Gets the scalar or repeated event-type selection, or null when omitted.</summary>
    [JsonIgnore] public AuditEventFilter? EventType { get; }
    /// <summary>Gets the protected secret-key selector, or null when omitted.</summary>
    [JsonIgnore] public string? SecretKey { get; }
    /// <summary>Gets the protected secret-path selector, or null when omitted.</summary>
    [JsonIgnore] public string? SecretPath { get; }
    /// <summary>Gets the native user-agent discriminator, or null to omit it.</summary>
    [JsonIgnore] public string? UserAgentType { get; }
    internal string Query()
    {
        string query = "";
        foreach ((string name, string? value) in new[]
        {
            ("actor", Actor), ("actorType", ActorType), ("environment", Environment),
            ("eventMetadata", EventMetadata), ("secretKey", SecretKey), ("secretPath", SecretPath),
            ("userAgentType", UserAgentType)
        })
            if (value is not null) query += "&" + name + "=" + Uri.EscapeDataString(value);
        return query + EventClass?.Query() + EventType?.Query();
    }
    /// <summary>Returns a marker without revealing audit selectors.</summary>
    public override string ToString() => "[AuditSelectors]";
}
