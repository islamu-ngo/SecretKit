using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native configuration only. Statement material is copied, never executed by the SDK.</summary>
public sealed class MySqlRotationParameters : IDisposable
{
    private readonly Lock _gate = new();
    private bool _disposed;
    private SecretMaterial? _statement;
    /// <summary>Captures alternating usernames and copies optional statement material; caller retains the original material.</summary>
    public MySqlRotationParameters(string username1, string username2,
        SqlRotationPasswordRequirements? passwordRequirements = null, SecretMaterial? rotationStatement = null)
    {
        ManagementJson.Text(username1, 16384);
        ManagementJson.Text(username2, 16384);
        Username1 = username1;
        Username2 = username2;
        PasswordRequirements = passwordRequirements;
        if (rotationStatement is not null)
        {
            SecretMaterial copy = rotationStatement.Copy();
            try
            {
                copy.Use(static characters =>
                {
                    if (characters.Length is 0 or > 16384) throw new ArgumentException("Invalid rotation statement budget.");
                });
                _statement = copy;
            }
            catch
            {
                copy.Dispose();
                throw;
            }
        }
    }
    internal MySqlRotationParameters(JsonElement value)
    {
        Username1 = ManagementJson.Nonempty(value, "username1");
        Username2 = ManagementJson.Nonempty(value, "username2");
        if (value.TryGetProperty("passwordRequirements", out _))
            PasswordRequirements = new(ManagementJson.Object(value, "passwordRequirements"));
        string? statement = ManagementJson.Optional(value, "rotationStatement", nullable: false);
        if (statement is not null)
        {
            if (statement.Length == 0) throw new ManagementContractException(SecretStatus.Unknown);
            _statement = SecretMaterial.FromText(statement);
        }
    }
    /// <summary>Gets the first configured rotation username, not a generated credential.</summary>
    [JsonIgnore] public string Username1 { get; }
    /// <summary>Gets the second configured rotation username, not a generated credential.</summary>
    [JsonIgnore] public string Username2 { get; }
    /// <summary>Gets optional password-generation requirements, or null when omitted.</summary>
    [JsonIgnore] public SqlRotationPasswordRequirements? PasswordRequirements { get; }
    /// <summary>Gets the owned statement copy, or null when omitted; access after disposal throws and the SDK never executes it.</summary>
    [JsonIgnore]
    public SecretMaterial? RotationStatement
    {
        get { lock (_gate) { ObjectDisposedException.ThrowIf(_disposed, this); return _statement; } }
    }
    internal void Write(Utf8JsonWriter writer)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            writer.WriteStartObject("parameters");
            writer.WriteString("username1", Username1);
            writer.WriteString("username2", Username2);
            PasswordRequirements?.Write(writer);
            _statement?.Use(writer, static (characters, w) => w.WriteString("rotationStatement", characters));
            writer.WriteEndObject();
        }
    }
    /// <summary>Disposes the owned statement copy and prevents further serialization.</summary>
    public void Dispose()
    {
        lock (_gate) { _disposed = true; _statement?.Dispose(); _statement = null; }
    }
    /// <summary>Returns a marker without usernames or statement text.</summary>
    public override string ToString() => "[MySqlRotationParameters]";
}

/// <summary>Native rotation creation settings; referenced parameter material remains caller-owned until request serialization.</summary>
public sealed class MySqlSecretRotationCreation
{
    /// <summary>Captures exact creation fields; null optional fields omit them and parameters are not cloned by this container.</summary>
    public MySqlSecretRotationCreation(string name, string projectId, string environment, string secretPath,
        string connectionId, double rotationInterval, MySqlRotationParameters parameters,
        SqlRotationSecretsMapping secretsMapping, SqlRotationTime? rotateAtUtc = null,
        SqlRotationNullableText? description = null, bool? isAutoRotationEnabled = null)
    {
        ManagementJson.Text(name, 64);
        ManagementJson.Text(projectId);
        ManagementJson.Text(environment, 64);
        ManagementJson.Text(secretPath);
        MySqlSecretRotationOperations.InputUuid(connectionId);
        MySqlSecretRotationOperations.InputNumber(rotationInterval, 1);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(secretsMapping);
        if (description?.Value?.Length > 256) throw new ArgumentException("Invalid rotation description budget.");
        Name = name;
        ProjectId = projectId;
        Environment = environment;
        SecretPath = secretPath;
        ConnectionId = connectionId;
        RotationInterval = rotationInterval;
        Parameters = parameters;
        SecretsMapping = secretsMapping;
        RotateAtUtc = rotateAtUtc;
        Description = description;
        IsAutoRotationEnabled = isAutoRotationEnabled;
    }
    /// <summary>Gets the selected rotation name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the selected project identifier.</summary>
    [JsonIgnore] public string ProjectId { get; }
    /// <summary>Gets the selected native environment slug.</summary>
    [JsonIgnore] public string Environment { get; }
    /// <summary>Gets the selected secret folder path.</summary>
    [JsonIgnore] public string SecretPath { get; }
    /// <summary>Gets the selected native connection UUID; the SDK opens no database connection.</summary>
    [JsonIgnore] public string ConnectionId { get; }
    /// <summary>Gets the native rotation interval value without converting it into an SDK timer.</summary>
    [JsonIgnore] public double RotationInterval { get; }
    /// <summary>Gets caller-owned parameters; keep them alive until request and grant construction are complete.</summary>
    [JsonIgnore] public MySqlRotationParameters Parameters { get; }
    /// <summary>Gets destination secret key mappings, not credential values.</summary>
    [JsonIgnore] public SqlRotationSecretsMapping SecretsMapping { get; }
    /// <summary>Gets explicit UTC time selection, or null when omitted.</summary>
    [JsonIgnore] public SqlRotationTime? RotateAtUtc { get; }
    /// <summary>Gets description intent; no wrapper omits the field and a null wrapper value clears it.</summary>
    [JsonIgnore] public SqlRotationNullableText? Description { get; }
    /// <summary>Gets automatic-rotation intent, or null when omitted.</summary>
    [JsonIgnore] public bool? IsAutoRotationEnabled { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("name", Name);
        writer.WriteString("projectId", ProjectId);
        writer.WriteString("environment", Environment);
        writer.WriteString("secretPath", SecretPath);
        writer.WriteString("connectionId", ConnectionId);
        writer.WriteNumber("rotationInterval", RotationInterval);
        Parameters.Write(writer);
        SecretsMapping.Write(writer);
        RotateAtUtc?.Write(writer);
        if (Description is not null) writer.WriteString("description", Description.Value);
        if (IsAutoRotationEnabled is { } enabled) writer.WriteBoolean("isAutoRotationEnabled", enabled);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without creation settings.</summary>
    public override string ToString() => "[MySqlSecretRotationCreation]";
}

/// <summary>Empty PATCH and omitted members are preserved. Nested persistence is not asserted.</summary>
public sealed class MySqlSecretRotationUpdate
{
    private readonly string? _name;
    private readonly SqlRotationNullableText? _description;
    private readonly bool? _enabled;
    private readonly double? _interval;
    private readonly MySqlRotationParameters? _parameters;
    private readonly SqlRotationSecretsMapping? _mapping;
    private readonly SqlRotationTime? _time;
    /// <summary>Captures optional patch fields; null omits, a nullable description can explicitly clear, and referenced material remains caller-owned.</summary>
    public MySqlSecretRotationUpdate(string? name = null, SqlRotationNullableText? description = null,
        bool? isAutoRotationEnabled = null, double? rotationInterval = null,
        MySqlRotationParameters? parameters = null, SqlRotationSecretsMapping? secretsMapping = null,
        SqlRotationTime? rotateAtUtc = null)
    {
        if (name is not null) ManagementJson.Text(name, 64);
        if (description?.Value?.Length > 256) throw new ArgumentException("Invalid rotation description budget.");
        if (rotationInterval is { } interval) MySqlSecretRotationOperations.InputNumber(interval, 1);
        _name = name;
        _description = description;
        _enabled = isAutoRotationEnabled;
        _interval = rotationInterval;
        _parameters = parameters;
        _mapping = secretsMapping;
        _time = rotateAtUtc;
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        if (_name is not null) writer.WriteString("name", _name);
        if (_description is not null) writer.WriteString("description", _description.Value);
        if (_enabled is { } enabled) writer.WriteBoolean("isAutoRotationEnabled", enabled);
        if (_interval is { } interval) writer.WriteNumber("rotationInterval", interval);
        _parameters?.Write(writer);
        _mapping?.Write(writer);
        _time?.Write(writer);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without update fields.</summary>
    public override string ToString() => "[MySqlSecretRotationUpdate]";
}

/// <summary>Explicit native destination and optional overwrite intent for a rotation move.</summary>
public sealed class MySqlSecretRotationMove
{
    /// <summary>Captures destination environment/path and nullable overwrite selection.</summary>
    public MySqlSecretRotationMove(string destinationEnvironment, string destinationSecretPath,
        bool? overwriteDestination = null)
    {
        ManagementJson.Text(destinationEnvironment);
        ManagementJson.Text(destinationSecretPath);
        DestinationEnvironment = destinationEnvironment;
        DestinationSecretPath = destinationSecretPath;
        OverwriteDestination = overwriteDestination;
    }
    /// <summary>Gets the selected destination environment slug.</summary>
    [JsonIgnore] public string DestinationEnvironment { get; }
    /// <summary>Gets the selected destination folder path.</summary>
    [JsonIgnore] public string DestinationSecretPath { get; }
    /// <summary>Gets overwrite intent; null omits the field and differs from false.</summary>
    [JsonIgnore] public bool? OverwriteDestination { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("destinationEnvironment", DestinationEnvironment);
        writer.WriteString("destinationSecretPath", DestinationSecretPath);
        if (OverwriteDestination is { } overwrite) writer.WriteBoolean("overwriteDestination", overwrite);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without destination coordinates.</summary>
    public override string ToString() => "[MySqlSecretRotationMove]";
}

/// <summary>Server-authored metadata. Status is open; timestamps/job IDs do not attribute a previous trigger.</summary>
public sealed class MySqlSecretRotationSummary : IDisposable
{
    internal MySqlSecretRotationSummary(JsonElement value, string projectId, string? id = null,
        string? name = null, string? environment = null, string? secretPath = null, string? connectionId = null)
    {
        ManagementJson.RequireEqual(value, "type", "mysql-credentials");
        ManagementJson.RequireEqual(value, "projectId", projectId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (name is not null) ManagementJson.RequireEqual(value, "name", name);
        Id = MySqlSecretRotationOperations.Uuid(value, "id");
        ProjectId = ManagementJson.Required(value, "projectId");
        Name = ManagementJson.Required(value, "name");
        ConnectionId = MySqlSecretRotationOperations.Uuid(value, "connectionId");
        if (connectionId is not null) ManagementJson.RequireEqual(value, "connectionId", connectionId);
        JsonElement connection = ManagementJson.Object(value, "connection");
        ManagementJson.RequireEqual(connection, "app", "mysql");
        ManagementJson.RequireEqual(connection, "id", ConnectionId);
        ConnectionName = ManagementJson.Required(connection, "name");
        JsonElement env = ManagementJson.Object(value, "environment");
        EnvironmentId = MySqlSecretRotationOperations.Uuid(env, "id");
        EnvironmentName = ManagementJson.Required(env, "name");
        Environment = ManagementJson.Required(env, "slug");
        if (environment is not null) ManagementJson.RequireEqual(env, "slug", environment);
        JsonElement folder = ManagementJson.Object(value, "folder");
        FolderId = MySqlSecretRotationOperations.Uuid(value, "folderId");
        ManagementJson.RequireEqual(folder, "id", FolderId);
        SecretPath = ManagementJson.Required(folder, "path");
        if (secretPath is not null) ManagementJson.RequireEqual(folder, "path", secretPath);
        CreatedAt = ManagementJson.Timestamp(value, "createdAt", true)!;
        UpdatedAt = ManagementJson.Timestamp(value, "updatedAt", true)!;
        LastRotatedAt = ManagementJson.Timestamp(value, "lastRotatedAt", true)!;
        LastRotationAttemptedAt = ManagementJson.Timestamp(value, "lastRotationAttemptedAt", true)!;
        RotationStatus = ManagementJson.Required(value, "rotationStatus");
        ActiveIndex = value.TryGetProperty("activeIndex", out _) ? MySqlSecretRotationOperations.Number(value, "activeIndex") : null;
        IsAutoRotationEnabled = value.TryGetProperty("isAutoRotationEnabled", out _) ? ManagementJson.Boolean(value, "isAutoRotationEnabled") : null;
        IsLastRotationManual = value.TryGetProperty("isLastRotationManual", out _) ? ManagementJson.Boolean(value, "isLastRotationManual") : null;
        HasDescription = value.TryGetProperty("description", out _);
        Description = ManagementJson.Optional(value, "description");
        HasLastRotationJobId = value.TryGetProperty("lastRotationJobId", out _);
        LastRotationJobId = ManagementJson.Optional(value, "lastRotationJobId");
        HasLastRotationMessage = value.TryGetProperty("lastRotationMessage", out _);
        LastRotationMessage = ManagementJson.Optional(value, "lastRotationMessage");
        HasNextRotationAt = value.TryGetProperty("nextRotationAt", out _);
        NextRotationAt = ManagementJson.Timestamp(value, "nextRotationAt", false);
        RotateAtUtc = new(ManagementJson.Object(value, "rotateAtUtc"));
        RotationInterval = MySqlSecretRotationOperations.Number(value, "rotationInterval");
        SecretsMapping = new(ManagementJson.Object(value, "secretsMapping"));
        // Material is allocated last so a rejected coordinate cannot leak an owned result.
        Parameters = new(ManagementJson.Object(value, "parameters"));
    }
    /// <summary>Gets the returned rotation UUID.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned project identifier verified against selection.</summary>
    [JsonIgnore] public string ProjectId { get; }
    /// <summary>Gets the returned rotation name.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Gets the returned connection UUID.</summary>
    [JsonIgnore] public string ConnectionId { get; }
    /// <summary>Gets the returned connection display name.</summary>
    [JsonIgnore] public string ConnectionName { get; }
    /// <summary>Gets the returned environment UUID.</summary>
    [JsonIgnore] public string EnvironmentId { get; }
    /// <summary>Gets the returned environment display name.</summary>
    [JsonIgnore] public string EnvironmentName { get; }
    /// <summary>Gets the returned native environment slug.</summary>
    [JsonIgnore] public string Environment { get; }
    /// <summary>Gets the returned folder UUID.</summary>
    [JsonIgnore] public string FolderId { get; }
    /// <summary>Gets the returned folder path.</summary>
    [JsonIgnore] public string SecretPath { get; }
    /// <summary>Gets the returned creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets the reported last-rotation timestamp, not proof of a caller's trigger.</summary>
    [JsonIgnore] public string LastRotatedAt { get; }
    /// <summary>Gets the reported last-attempt timestamp, not attribution to a caller's request.</summary>
    [JsonIgnore] public string LastRotationAttemptedAt { get; }
    /// <summary>Gets the native open status string without converting it into a convergence guarantee.</summary>
    [JsonIgnore] public string RotationStatus { get; }
    /// <summary>Gets the reported active slot, or null when omitted.</summary>
    [JsonIgnore] public double? ActiveIndex { get; }
    /// <summary>Gets the reported automatic-rotation switch, or null when omitted.</summary>
    [JsonIgnore] public bool? IsAutoRotationEnabled { get; }
    /// <summary>Gets the reported manual-rotation flag, or null when omitted.</summary>
    [JsonIgnore] public bool? IsLastRotationManual { get; }
    /// <summary>Gets whether description was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasDescription { get; }
    /// <summary>Gets description text; use HasDescription to distinguish omission from explicit null.</summary>
    [JsonIgnore] public string? Description { get; }
    /// <summary>Gets whether a last-job identifier was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasLastRotationJobId { get; }
    /// <summary>Gets the last-job identifier; it does not attribute a previous trigger.</summary>
    [JsonIgnore] public string? LastRotationJobId { get; }
    /// <summary>Gets whether a last-message field was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasLastRotationMessage { get; }
    /// <summary>Gets the protected native message; use HasLastRotationMessage to distinguish absence.</summary>
    [JsonIgnore] public string? LastRotationMessage { get; }
    /// <summary>Gets whether a next-rotation timestamp was returned, including explicit null.</summary>
    [JsonIgnore] public bool HasNextRotationAt { get; }
    /// <summary>Gets the reported next timestamp; use HasNextRotationAt to distinguish absence.</summary>
    [JsonIgnore] public string? NextRotationAt { get; }
    /// <summary>Gets the returned UTC schedule fields.</summary>
    [JsonIgnore] public SqlRotationTime RotateAtUtc { get; }
    /// <summary>Gets the native returned rotation interval, not an SDK schedule.</summary>
    [JsonIgnore] public double RotationInterval { get; }
    /// <summary>Gets returned secret key mappings, not generated credential values.</summary>
    [JsonIgnore] public SqlRotationSecretsMapping SecretsMapping { get; }
    /// <summary>Gets owned returned parameters; statement material is disposed with this summary.</summary>
    [JsonIgnore] public MySqlRotationParameters Parameters { get; }
    /// <summary>Disposes owned parameter statement material without changing provider configuration.</summary>
    public void Dispose() => Parameters.Dispose();
    /// <summary>Returns a marker without native status details, coordinates or statements.</summary>
    public override string ToString() => "[MySqlSecretRotationSummary]";
}

/// <summary>Disposable list owns every selected MySQL result; mixed catalogs remain explicitly partial.</summary>
public sealed class MySqlSecretRotationList : IDisposable
{
    internal MySqlSecretRotationList(IEnumerable<MySqlSecretRotationSummary> items, bool complete)
    {
        Items = Array.AsReadOnly(items.ToArray());
        IsComplete = complete;
    }
    /// <summary>Gets selected owned rotation summaries; dispose the list to release all material.</summary>
    [JsonIgnore] public IReadOnlyList<MySqlSecretRotationSummary> Items { get; }
    /// <summary>Gets whether the listing is complete; a profile subset of a mixed catalog remains incomplete.</summary>
    public bool IsComplete { get; }
    /// <summary>Disposes every owned selected rotation summary.</summary>
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    /// <summary>Returns a marker without rotation inventory contents.</summary>
    public override string ToString() => "[MySqlSecretRotationList]";
}

/// <summary>Owned generated username/password pair; dispose after use and protect any deliberate plaintext exports.</summary>
public sealed class MySqlGeneratedCredential : IDisposable
{
    internal MySqlGeneratedCredential(string username, string password)
    {
        Username = SecretMaterial.FromText(username);
        try { Password = SecretMaterial.FromText(password); }
        catch { Username.Dispose(); throw; }
    }
    /// <summary>Gets owned generated username material, not a destination key name.</summary>
    [JsonIgnore] public SecretMaterial Username { get; }
    /// <summary>Gets owned generated password material.</summary>
    [JsonIgnore] public SecretMaterial Password { get; }
    /// <summary>Disposes both credential buffers; does not revoke the database credential or erase exported strings.</summary>
    public void Dispose() { Username.Dispose(); Password.Dispose(); }
    /// <summary>Returns a marker without generated authentication material.</summary>
    public override string ToString() => "[MySqlGeneratedCredential]";
}

/// <summary>One observed material response, not proof of current database access or trigger attribution.</summary>
public sealed class MySqlGeneratedCredentials : IDisposable
{
    internal MySqlGeneratedCredentials(JsonElement value, string rotationId)
    {
        ManagementJson.RequireEqual(value, "type", "mysql-credentials");
        ManagementJson.RequireEqual(value, "rotationId", rotationId);
        RotationId = MySqlSecretRotationOperations.Uuid(value, "rotationId");
        ActiveIndex = MySqlSecretRotationOperations.Number(value, "activeIndex");
        var values = ManagementJson.Array(value, "generatedCredentials");
        var parsed = new List<MySqlGeneratedCredential>();
        try
        {
            foreach (var item in values)
            {
                if (parsed.Count == 2) throw new ManagementContractException(SecretStatus.Unknown);
                // Empty values are established here, independently of creation parameters.
                parsed.Add(new(ManagementJson.Required(item, "username"), ManagementJson.Required(item, "password")));
            }
            if (parsed.Count == 0) throw new ManagementContractException(SecretStatus.Unknown);
            Items = Array.AsReadOnly(parsed.ToArray());
        }
        catch { foreach (var item in parsed) item.Dispose(); throw; }
    }
    /// <summary>Gets the returned rotation UUID matched to the request.</summary>
    [JsonIgnore] public string RotationId { get; }
    /// <summary>Gets the native reported active slot without testing database authentication.</summary>
    [JsonIgnore] public double ActiveIndex { get; }
    /// <summary>Gets one or two owned credential pairs from this observed response.</summary>
    [JsonIgnore] public IReadOnlyList<MySqlGeneratedCredential> Items { get; }
    /// <summary>Disposes all owned generated credential pairs.</summary>
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    /// <summary>Returns a marker without generated credentials.</summary>
    public override string ToString() => "[MySqlGeneratedCredentials]";
}

/// <summary>A MySQL-only catalog option. Statements are protected template text, never executed.</summary>
public sealed class MySqlSecretRotationOption : IDisposable
{
    internal MySqlSecretRotationOption(JsonElement value)
    {
        ManagementJson.RequireEqual(value, "type", "mysql-credentials");
        ManagementJson.RequireEqual(value, "connection", "mysql");
        ManagementJson.RequireEqual(value, "name", "MySQL Credentials");
        JsonElement template = ManagementJson.Object(value, "template");
        SecretsMapping = new(ManagementJson.Object(template, "secretsMapping"), false);
        string create = ManagementJson.Required(template, "createUserStatement");
        string rotate = ManagementJson.Required(template, "rotationStatement");
        CreateUserStatement = SecretMaterial.FromText(create);
        try { RotationStatement = SecretMaterial.FromText(rotate); }
        catch { CreateUserStatement.Dispose(); throw; }
    }
    /// <summary>Gets owned create-user statement template text; the SDK does not execute it.</summary>
    [JsonIgnore] public SecretMaterial CreateUserStatement { get; }
    /// <summary>Gets owned rotation statement template text; the SDK does not execute it.</summary>
    [JsonIgnore] public SecretMaterial RotationStatement { get; }
    /// <summary>Gets template destination key mappings, not generated credentials.</summary>
    [JsonIgnore] public SqlRotationSecretsMapping SecretsMapping { get; }
    /// <summary>Disposes both owned statement templates.</summary>
    public void Dispose() { CreateUserStatement.Dispose(); RotationStatement.Dispose(); }
    /// <summary>Returns a marker without statement templates or key mappings.</summary>
    public override string ToString() => "[MySqlSecretRotationOption]";
}

/// <summary>Owned profile-only catalog projection; it never claims completeness for the mixed native catalog.</summary>
public sealed class MySqlSecretRotationOptions : IDisposable
{
    internal MySqlSecretRotationOptions(IEnumerable<MySqlSecretRotationOption> items) =>
        Items = Array.AsReadOnly(items.ToArray());
    /// <summary>Gets selected owned catalog options; dispose the collection after inspection.</summary>
    [JsonIgnore] public IReadOnlyList<MySqlSecretRotationOption> Items { get; }
    /// <summary>Always false: this collection projects only one profile from a mixed catalog.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "This result is one native profile subset, not a complete mixed provider catalog.")]
    public bool IsComplete => false;
    /// <summary>Disposes all owned option statement templates.</summary>
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    /// <summary>Returns a marker without catalog statement templates.</summary>
    public override string ToString() => "[MySqlSecretRotationOptions]";
}

/// <summary>Native 204 credential-check acknowledgement only; no material or convergence result.</summary>
public sealed class MySqlCredentialCheckAcknowledgement
{
    internal MySqlCredentialCheckAcknowledgement() { }
    /// <summary>Returns a marker without claiming database convergence or credential material.</summary>
    public override string ToString() => "[MySqlCredentialCheckAcknowledgement]";
}
