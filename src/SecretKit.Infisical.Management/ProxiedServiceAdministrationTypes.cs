using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

public enum ProxiedServiceCredentialRole { HeaderRewrite, CredentialSubstitution }
public enum ProxiedServiceHeaderPurpose { Username, Password }
public enum ProxiedServiceSubstitutionSurface { Header, Path, Query, Body }

/// <summary>Immutable copied protected credential selectors; no secret retrieval or principal acquisition.</summary>
public sealed class ProxiedServiceCredentialInput : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _body;
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
    public void Dispose() { lock (_gate) { if (_body is not null) Array.Clear(_body); _body = null; } }
    public override string ToString() => "[ProxiedServiceCredentialInput]";
}

/// <summary>Owns an immutable credential/body copy; disposal performs no remote cleanup.</summary>
public sealed class ProxiedServiceCreation : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _body;
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string ProjectId { get; }
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
    public void Dispose() { lock (_gate) { if (_body is not null) Array.Clear(_body); _body = null; } }
    public override string ToString() => "[ProxiedServiceCreation]";
}

public sealed class ProxiedServiceUpdate : IDisposable
{
    private readonly object _gate = new();
    private byte[]? _body;
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
    public void Dispose() { lock (_gate) { if (_body is not null) Array.Clear(_body); _body = null; } }
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
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string ServiceId { get; }
    [JsonIgnore] public string Role { get; }
    [JsonIgnore] public bool HasCallerCanLease { get; }
    [JsonIgnore] public bool? CallerCanLease { get; }
    [JsonIgnore] public bool HasDynamicSecretField { get; }
    [JsonIgnore] public string? DynamicSecretField { get; }
    [JsonIgnore] public bool HasDynamicSecretName { get; }
    [JsonIgnore] public string? DynamicSecretName { get; }
    [JsonIgnore] public bool HasHeaderName { get; }
    [JsonIgnore] public string? HeaderName { get; }
    [JsonIgnore] public bool HasHeaderPrefix { get; }
    [JsonIgnore] public string? HeaderPrefix { get; }
    [JsonIgnore] public bool HasHeaderPurpose { get; }
    [JsonIgnore] public string? HeaderPurpose { get; }
    [JsonIgnore] public bool HasPlaceholderKey { get; }
    [JsonIgnore] public string? PlaceholderKey { get; }
    [JsonIgnore] public bool HasPlaceholderValue { get; }
    [JsonIgnore] public SecretMaterial? PlaceholderValue { get; }
    [JsonIgnore] public bool HasSecretKey { get; }
    [JsonIgnore] public string? SecretKey { get; }
    [JsonIgnore] public bool HasSubstitutionSurfaces { get; }
    [JsonIgnore] public IReadOnlyList<string>? SubstitutionSurfaces { get; }
    public void Dispose() => PlaceholderValue?.Dispose();
    public override string ToString() => "[ProxiedServiceCredentialSummary]";
}

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
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string FolderId { get; }
    [JsonIgnore] public string HostPattern { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public bool HasIsEnabled { get; }
    [JsonIgnore] public bool? IsEnabled { get; }
    [JsonIgnore] public bool HasLastUsedAt { get; }
    [JsonIgnore] public string? LastUsedAt { get; }
    [JsonIgnore] public bool? CanProxy { get; }
    [JsonIgnore] public bool HasCredentials { get; }
    [JsonIgnore] public IReadOnlyList<ProxiedServiceCredentialSummary> Credentials { get; }
    public void Dispose() { foreach (var credential in Credentials) credential.Dispose(); }
    public override string ToString() => "[ProxiedServiceSummary]";
}

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
    [JsonIgnore] public string ProjectSlug { get; }
    [JsonIgnore] public IReadOnlyList<ProxiedServiceSummary> Services { get; }
    public void Dispose() { foreach (var service in Services) service.Dispose(); }
    public override string ToString() => "[ProxiedServiceList]";
}
