using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native proxy credential placement strategy.</summary>
public enum ProxiedServiceCredentialRole { /** <summary>Rewrites a selected outgoing header.</summary> */ HeaderRewrite, /** <summary>Substitutes selected credential placeholders.</summary> */ CredentialSubstitution }
/// <summary>Native purpose of a rewritten credential header.</summary>
public enum ProxiedServiceHeaderPurpose { /** <summary>Places the username component.</summary> */ Username, /** <summary>Places the password component.</summary> */ Password }
/// <summary>Explicit request surfaces admitted for native substitution.</summary>
public enum ProxiedServiceSubstitutionSurface { /** <summary>Substitutes within request headers.</summary> */ Header, /** <summary>Substitutes within the URL path.</summary> */ Path, /** <summary>Substitutes within URL query fields.</summary> */ Query, /** <summary>Substitutes within the request body.</summary> */ Body }

/// <summary>Immutable copied protected credential selectors; no secret retrieval or principal acquisition.</summary>
public sealed class ProxiedServiceCredentialInput : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _body;
    /// <summary>Copies bounded credential selectors and optional placeholder material into an owned body; acquires no secret.</summary>
    public ProxiedServiceCredentialInput(ProxiedServiceCredentialRole role, string? dynamicSecretField = null,
        string? dynamicSecretName = null, string? headerName = null, string? headerPrefix = null,
        ProxiedServiceHeaderPurpose? headerPurpose = null, string? placeholderKey = null,
        SecretMaterial? placeholderValue = null, string? secretKey = null,
        IEnumerable<ProxiedServiceSubstitutionSurface>? substitutionSurfaces = null)
    {
        string wireRole = role switch
        {
            ProxiedServiceCredentialRole.HeaderRewrite => "header-rewrite",
            ProxiedServiceCredentialRole.CredentialSubstitution => "credential-substitution",
            _ => throw new ArgumentException("Invalid proxied service credential role.")
        };
        foreach (string? value in new[] { dynamicSecretField, dynamicSecretName, headerName, placeholderKey, secretKey })
            GatewayJson.InputText(value, 255, 1);
        GatewayJson.InputText(headerPrefix, 255);
        string? purpose = headerPurpose switch
        {
            null => null,
            ProxiedServiceHeaderPurpose.Username => "username",
            ProxiedServiceHeaderPurpose.Password => "password",
            _ => throw new ArgumentException("Invalid proxied service header purpose.")
        };
        string[]? surfaces = substitutionSurfaces?.Take(1001).Select(value => value switch
        {
            ProxiedServiceSubstitutionSurface.Header => "header",
            ProxiedServiceSubstitutionSurface.Path => "path",
            ProxiedServiceSubstitutionSurface.Query => "query",
            ProxiedServiceSubstitutionSurface.Body => "body",
            _ => throw new ArgumentException("Invalid proxied service substitution surface.")
        }).ToArray();
        if (surfaces?.Length is 0 or > 1000) throw new ArgumentException("Invalid proxied service substitution count.");
        char[]? placeholder = placeholderValue?.ExportCharacters();
        try
        {
            if (placeholder?.Length is 0 or > 255) throw new ArgumentException("Invalid proxied service placeholder budget.");
            _body = GatewayJson.Serialize(writer =>
            {
                writer.WriteStartObject();
                writer.WriteString("role", wireRole);
                if (dynamicSecretField is not null) writer.WriteString("dynamicSecretField", dynamicSecretField);
                if (dynamicSecretName is not null) writer.WriteString("dynamicSecretName", dynamicSecretName);
                if (headerName is not null) writer.WriteString("headerName", headerName);
                if (headerPrefix is not null) writer.WriteString("headerPrefix", headerPrefix);
                if (purpose is not null) writer.WriteString("headerPurpose", purpose);
                if (placeholderKey is not null) writer.WriteString("placeholderKey", placeholderKey);
                if (placeholder is not null) writer.WriteString("placeholderValue", placeholder.AsSpan());
                if (secretKey is not null) writer.WriteString("secretKey", secretKey);
                if (surfaces is not null)
                {
                    writer.WriteStartArray("substitutionSurfaces");
                    foreach (string surface in surfaces) writer.WriteStringValue(surface);
                    writer.WriteEndArray();
                }
                writer.WriteEndObject();
            });
        }
        finally { if (placeholder is not null) Array.Clear(placeholder); }
    }
    internal void Write(Utf8JsonWriter writer)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_body is null, this);
            writer.WriteRawValue(_body);
        }
    }
    /// <summary>Clears the owned serialized selector/material body and prevents further serialization.</summary>
    public void Dispose() { lock (_gate) { if (_body is not null) Array.Clear(_body); _body = null; } }
    /// <summary>Returns a marker without credential selectors or placeholder material.</summary>
    public override string ToString() => "[ProxiedServiceCredentialInput]";
}

/// <summary>Owns an immutable credential/body copy; disposal performs no remote cleanup.</summary>
public sealed class ProxiedServiceCreation : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _body;
    /// <summary>Gets the selected proxy service name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the selected project identifier.</summary>
    [JsonIgnore] public string ProjectId { get; }
    /// <summary>Copies one to 1000 credential inputs into its independent body; caller retains ownership of inputs.</summary>
    public ProxiedServiceCreation(string projectId, string environment, string name, string hostPattern,
        IEnumerable<ProxiedServiceCredentialInput> credentials, string? secretPath = null, bool? isEnabled = null)
    {
        ManagementJson.Text(projectId);
        ManagementJson.Text(environment);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(hostPattern);
        GatewayJson.InputText(name, 64, 1);
        GatewayJson.InputText(hostPattern, 255, 1);
        GatewayJson.InputText(secretPath, 16384);
        Name = name;
        ProjectId = projectId;
        ProxiedServiceCredentialInput[] copy = ProxiedServiceInput.Copy(credentials);
        _body = GatewayJson.Serialize(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("projectId", projectId);
            writer.WriteString("environment", environment);
            writer.WriteString("name", name);
            writer.WriteString("hostPattern", hostPattern);
            ProxiedServiceInput.WriteCredentials(writer, copy);
            if (secretPath is not null) writer.WriteString("secretPath", secretPath);
            if (isEnabled is { } enabled) writer.WriteBoolean("isEnabled", enabled);
            writer.WriteEndObject();
        });
    }
    internal void Write(Utf8JsonWriter writer)
    {
        lock (_gate) { ObjectDisposedException.ThrowIf(_body is null, this); writer.WriteRawValue(_body); }
    }
    /// <summary>Clears the owned creation body without deleting provider configuration.</summary>
    public void Dispose() { lock (_gate) { if (_body is not null) Array.Clear(_body); _body = null; } }
    /// <summary>Returns a marker without creation settings or credential selectors.</summary>
    public override string ToString() => "[ProxiedServiceCreation]";
}

/// <summary>Owned optional proxy patch body; null fields remain omitted rather than cleared.</summary>
public sealed class ProxiedServiceUpdate : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _body;
    /// <summary>Copies optional credential inputs into an owned body; null credentials omit the field and explicit arrays must be nonempty.</summary>
    public ProxiedServiceUpdate(string? name = null, string? hostPattern = null, bool? isEnabled = null,
        IEnumerable<ProxiedServiceCredentialInput>? credentials = null)
    {
        GatewayJson.InputText(name, 64, 1);
        GatewayJson.InputText(hostPattern, 255, 1);
        ProxiedServiceCredentialInput[]? copy = credentials is null ? null : ProxiedServiceInput.Copy(credentials);
        _body = GatewayJson.Serialize(writer =>
        {
            writer.WriteStartObject();
            if (name is not null) writer.WriteString("name", name);
            if (hostPattern is not null) writer.WriteString("hostPattern", hostPattern);
            if (isEnabled is { } enabled) writer.WriteBoolean("isEnabled", enabled);
            if (copy is not null) ProxiedServiceInput.WriteCredentials(writer, copy);
            writer.WriteEndObject();
        });
    }
    internal void Write(Utf8JsonWriter writer)
    {
        lock (_gate) { ObjectDisposedException.ThrowIf(_body is null, this); writer.WriteRawValue(_body); }
    }
    /// <summary>Clears the owned patch body and prevents further serialization.</summary>
    public void Dispose() { lock (_gate) { if (_body is not null) Array.Clear(_body); _body = null; } }
    /// <summary>Returns a marker without patch contents.</summary>
    public override string ToString() => "[ProxiedServiceUpdate]";
}

internal static class ProxiedServiceInput
{
    internal static ProxiedServiceCredentialInput[] Copy(IEnumerable<ProxiedServiceCredentialInput> credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        var copy = credentials.Take(1001).ToArray();
        if (copy.Length is 0 or > 1000 || copy.Any(value => value is null))
            throw new ArgumentException("Invalid proxied service credential count.");
        return copy;
    }
    internal static void WriteCredentials(Utf8JsonWriter writer, ProxiedServiceCredentialInput[] credentials)
    {
        writer.WriteStartArray("credentials");
        foreach (var credential in credentials) credential.Write(writer);
        writer.WriteEndArray();
    }
}

/// <summary>Native credential metadata; open response role/purpose/surface strings are not restricted to input enums.</summary>
public sealed class ProxiedServiceCredentialSummary : IDisposable
{
    internal ProxiedServiceCredentialSummary(JsonElement value, string serviceId, bool access)
    {
        Id = GatewayJson.Uuid(value, "id");
        ServiceId = GatewayJson.Uuid(value, "serviceId");
        ManagementJson.RequireEqual(value, "serviceId", serviceId);
        Role = ManagementJson.Required(value, "role");
        HasCallerCanLease = access && value.TryGetProperty("callerCanLease", out _);
        if (HasCallerCanLease) CallerCanLease = ManagementJson.Boolean(value, "callerCanLease");
        HasDynamicSecretField = value.TryGetProperty("dynamicSecretField", out _);
        DynamicSecretField = GatewayJson.Text(value, "dynamicSecretField");
        HasDynamicSecretName = value.TryGetProperty("dynamicSecretName", out _);
        DynamicSecretName = GatewayJson.Text(value, "dynamicSecretName");
        HasHeaderName = value.TryGetProperty("headerName", out _);
        HeaderName = GatewayJson.Text(value, "headerName");
        HasHeaderPrefix = value.TryGetProperty("headerPrefix", out _);
        HeaderPrefix = GatewayJson.Text(value, "headerPrefix");
        HasHeaderPurpose = value.TryGetProperty("headerPurpose", out _);
        HeaderPurpose = GatewayJson.Text(value, "headerPurpose");
        HasPlaceholderKey = value.TryGetProperty("placeholderKey", out _);
        PlaceholderKey = GatewayJson.Text(value, "placeholderKey");
        HasSecretKey = value.TryGetProperty("secretKey", out _);
        SecretKey = GatewayJson.Text(value, "secretKey");
        HasSubstitutionSurfaces = value.TryGetProperty("substitutionSurfaces", out var surfaces);
        if (HasSubstitutionSurfaces && surfaces.ValueKind != JsonValueKind.Null)
        {
            var strings = ManagementJson.Array(surfaces).Select(item =>
            {
                if (item.ValueKind != JsonValueKind.String || item.GetString()!.Length > 16384)
                    throw new ManagementContractException(SecretStatus.Unknown);
                return item.GetString()!;
            }).ToArray();
            SubstitutionSurfaces = Array.AsReadOnly(strings);
        }
        HasPlaceholderValue = value.TryGetProperty("placeholderValue", out _);
        string? placeholder = GatewayJson.Text(value, "placeholderValue");
        if (placeholder is not null) PlaceholderValue = SecretMaterial.FromText(placeholder);
    }
    /// <summary>Gets the returned credential configuration UUID.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the owning service UUID verified against the returned service.</summary>
    [JsonIgnore] public string ServiceId { get; }
    /// <summary>Gets the open native placement-role string without constraining it to input enums.</summary>
    [JsonIgnore] public string Role { get; }
    /// <summary>Gets whether a read response included the provider lease affordance.</summary>
    [JsonIgnore] public bool HasCallerCanLease { get; }
    /// <summary>Gets the provider-authored lease flag, or null when absent; not independently verified capability.</summary>
    [JsonIgnore] public bool? CallerCanLease { get; }
    /// <summary>Gets whether the dynamic-secret field selector was returned, including null.</summary>
    [JsonIgnore] public bool HasDynamicSecretField { get; }
    /// <summary>Gets the dynamic-secret field selector; use its Has flag to distinguish omission.</summary>
    [JsonIgnore] public string? DynamicSecretField { get; }
    /// <summary>Gets whether a dynamic-secret name was returned, including null.</summary>
    [JsonIgnore] public bool HasDynamicSecretName { get; }
    /// <summary>Gets the dynamic-secret name; use its Has flag to distinguish omission.</summary>
    [JsonIgnore] public string? DynamicSecretName { get; }
    /// <summary>Gets whether a header name was returned, including null.</summary>
    [JsonIgnore] public bool HasHeaderName { get; }
    /// <summary>Gets the header name; use its Has flag to distinguish omission.</summary>
    [JsonIgnore] public string? HeaderName { get; }
    /// <summary>Gets whether a header prefix was returned, including null.</summary>
    [JsonIgnore] public bool HasHeaderPrefix { get; }
    /// <summary>Gets the header prefix; empty remains distinct from null.</summary>
    [JsonIgnore] public string? HeaderPrefix { get; }
    /// <summary>Gets whether header purpose was returned, including null.</summary>
    [JsonIgnore] public bool HasHeaderPurpose { get; }
    /// <summary>Gets open native header-purpose text; use its Has flag to distinguish omission.</summary>
    [JsonIgnore] public string? HeaderPurpose { get; }
    /// <summary>Gets whether a placeholder key was returned, including null.</summary>
    [JsonIgnore] public bool HasPlaceholderKey { get; }
    /// <summary>Gets the placeholder key; use its Has flag to distinguish omission.</summary>
    [JsonIgnore] public string? PlaceholderKey { get; }
    /// <summary>Gets whether placeholder material was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasPlaceholderValue { get; }
    /// <summary>Gets owned placeholder material, or null when absent or null; dispose this summary after use.</summary>
    [JsonIgnore] public SecretMaterial? PlaceholderValue { get; }
    /// <summary>Gets whether a secret key selector was returned, including null.</summary>
    [JsonIgnore] public bool HasSecretKey { get; }
    /// <summary>Gets the secret key selector, not a secret value.</summary>
    [JsonIgnore] public string? SecretKey { get; }
    /// <summary>Gets whether substitution surfaces were returned, including null.</summary>
    [JsonIgnore] public bool HasSubstitutionSurfaces { get; }
    /// <summary>Gets open native surface strings; null differs from an explicit empty collection.</summary>
    [JsonIgnore] public IReadOnlyList<string>? SubstitutionSurfaces { get; }
    /// <summary>Disposes owned placeholder material without changing proxy configuration.</summary>
    public void Dispose() => PlaceholderValue?.Dispose();
    /// <summary>Returns a marker without placeholder material or credential selectors.</summary>
    public override string ToString() => "[ProxiedServiceCredentialSummary]";
}

/// <summary>Owned proxy metadata and credential projections; dispose to release every placeholder buffer.</summary>
public sealed class ProxiedServiceSummary : IDisposable
{
    internal ProxiedServiceSummary(JsonElement value, bool credentials, bool access, string? id = null, string? name = null)
    {
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (name is not null) ManagementJson.RequireEqual(value, "name", name);
        Id = GatewayJson.Uuid(value, "id");
        Name = ManagementJson.Required(value, "name");
        FolderId = GatewayJson.Uuid(value, "folderId");
        HostPattern = ManagementJson.Required(value, "hostPattern");
        CreatedAt = GatewayJson.Timestamp(value, "createdAt")!;
        UpdatedAt = GatewayJson.Timestamp(value, "updatedAt")!;
        HasIsEnabled = value.TryGetProperty("isEnabled", out _);
        if (HasIsEnabled) IsEnabled = ManagementJson.Boolean(value, "isEnabled");
        HasLastUsedAt = value.TryGetProperty("lastUsedAt", out _);
        LastUsedAt = GatewayJson.Timestamp(value, "lastUsedAt", false, true);
        if (access) CanProxy = ManagementJson.Boolean(value, "canProxy");
        HasCredentials = credentials;
        var copy = new List<ProxiedServiceCredentialSummary>();
        try
        {
            if (credentials)
                foreach (var credential in ManagementJson.Array(value, "credentials"))
                    copy.Add(new(credential, Id, access));
            Credentials = Array.AsReadOnly(copy.ToArray());
        }
        catch { foreach (var credential in copy) credential.Dispose(); throw; }
    }
    /// <summary>Gets the returned service UUID.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned service name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the returned folder UUID without inventing broader scope attestation.</summary>
    [JsonIgnore] public string FolderId { get; }
    /// <summary>Gets the protected backend host pattern, not an active backend connection.</summary>
    [JsonIgnore] public string HostPattern { get; }
    /// <summary>Gets the returned creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets whether the enabled flag was returned.</summary>
    [JsonIgnore] public bool HasIsEnabled { get; }
    /// <summary>Gets the returned enabled switch, or null when omitted.</summary>
    [JsonIgnore] public bool? IsEnabled { get; }
    /// <summary>Gets whether last-use time was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasLastUsedAt { get; }
    /// <summary>Gets the reported last-use timestamp; use HasLastUsedAt to distinguish absence.</summary>
    [JsonIgnore] public string? LastUsedAt { get; }
    /// <summary>Gets the provider-authored proxy affordance for read results; mutation results leave it null.</summary>
    [JsonIgnore] public bool? CanProxy { get; }
    /// <summary>Gets whether this projection includes credential rows; deletion results do not.</summary>
    [JsonIgnore] public bool HasCredentials { get; }
    /// <summary>Gets owned credential summaries; empty does not imply omission when HasCredentials is true.</summary>
    [JsonIgnore] public IReadOnlyList<ProxiedServiceCredentialSummary> Credentials { get; }
    /// <summary>Disposes all owned credential placeholder material without remote cleanup.</summary>
    public void Dispose() { foreach (var credential in Credentials) credential.Dispose(); }
    /// <summary>Returns a marker without proxy configuration or credentials.</summary>
    public override string ToString() => "[ProxiedServiceSummary]";
}

/// <summary>Owned proxy-service inventory response with protected project-slug metadata.</summary>
public sealed class ProxiedServiceList : IDisposable
{
    internal ProxiedServiceList(JsonElement value)
    {
        ProjectSlug = ManagementJson.Required(value, "projectSlug");
        var copy = new List<ProxiedServiceSummary>();
        try
        {
            foreach (var service in ManagementJson.Array(value, "services")) copy.Add(new(service, true, true));
            Services = Array.AsReadOnly(copy.ToArray());
        }
        catch { foreach (var service in copy) service.Dispose(); throw; }
    }
    /// <summary>Gets the native returned project slug.</summary>
    [JsonIgnore] public string ProjectSlug { get; }
    /// <summary>Gets owned returned service summaries; dispose the list after inspection.</summary>
    [JsonIgnore] public IReadOnlyList<ProxiedServiceSummary> Services { get; }
    /// <summary>Disposes every owned returned service summary.</summary>
    public void Dispose() { foreach (var service in Services) service.Dispose(); }
    /// <summary>Returns a marker without service inventory contents.</summary>
    public override string ToString() => "[ProxiedServiceList]";
}
