using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>A supplied nullable rotation description; no wrapper means omission.</summary>
public sealed class PostgresRotationNullableText
{
    public PostgresRotationNullableText(string? value)
    {
        if (value?.Length > 16384) throw new ArgumentException("Invalid PostgreSQL text budget.");
        Value = value;
    }
    [JsonIgnore] public string? Value { get; }
    public override string ToString() => "[PostgresRotationNullableText]";
}

/// <summary>Published numeric requirements; fractional numbers are not silently rounded.</summary>
public sealed class PostgresRotationPasswordRequirements
{
    public PostgresRotationPasswordRequirements(double length, double digits, double lowercase,
        double symbols, double uppercase, string? allowedSymbols = null)
    {
        PostgresSecretRotationOperations.InputNumber(length, 1, 250);
        foreach (double count in new[] { digits, lowercase, symbols, uppercase })
            PostgresSecretRotationOperations.InputNumber(count, 0);
        if (allowedSymbols is not null && (allowedSymbols.Length > 16384 ||
            !Regex.IsMatch(allowedSymbols, """[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?~]""",
                RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1))))
            throw new ArgumentException("Invalid rotation symbols.");
        Length = length;
        Digits = digits;
        Lowercase = lowercase;
        Symbols = symbols;
        Uppercase = uppercase;
        AllowedSymbols = allowedSymbols;
    }
    internal PostgresRotationPasswordRequirements(JsonElement value)
    {
        Length = PostgresSecretRotationOperations.Number(value, "length", 1, 250);
        JsonElement required = ManagementJson.Object(value, "required");
        Digits = PostgresSecretRotationOperations.Number(required, "digits", 0);
        Lowercase = PostgresSecretRotationOperations.Number(required, "lowercase", 0);
        Symbols = PostgresSecretRotationOperations.Number(required, "symbols", 0);
        Uppercase = PostgresSecretRotationOperations.Number(required, "uppercase", 0);
        AllowedSymbols = ManagementJson.Optional(value, "allowedSymbols", nullable: false);
        if (AllowedSymbols is not null && !Regex.IsMatch(AllowedSymbols, """[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?~]""",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)))
            throw new ManagementContractException(SecretStatus.Unknown);
    }
    [JsonIgnore] public double Length { get; }
    [JsonIgnore] public double Digits { get; }
    [JsonIgnore] public double Lowercase { get; }
    [JsonIgnore] public double Symbols { get; }
    [JsonIgnore] public double Uppercase { get; }
    [JsonIgnore] public string? AllowedSymbols { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("passwordRequirements");
        writer.WriteNumber("length", Length);
        if (AllowedSymbols is not null) writer.WriteString("allowedSymbols", AllowedSymbols);
        writer.WriteStartObject("required");
        writer.WriteNumber("digits", Digits);
        writer.WriteNumber("lowercase", Lowercase);
        writer.WriteNumber("symbols", Symbols);
        writer.WriteNumber("uppercase", Uppercase);
        writer.WriteEndObject();
        writer.WriteEndObject();
    }
    public override string ToString() => "[PostgresRotationPasswordRequirements]";
}

/// <summary>Native configuration only. Statement material is copied, never executed by the SDK.</summary>
public sealed class PostgresRotationParameters : IDisposable
{
    private readonly object _gate = new();
    private bool _disposed;
    private SecretMaterial? _statement;
    public PostgresRotationParameters(string username1, string username2,
        PostgresRotationPasswordRequirements? passwordRequirements = null, SecretMaterial? rotationStatement = null)
    {
        ManagementJson.Text(username1, 16384);
        ManagementJson.Text(username2, 16384);
        Username1 = username1;
        Username2 = username2;
        PasswordRequirements = passwordRequirements;
        if (rotationStatement is not null)
        {
            char[] copy = rotationStatement.ExportCharacters();
            try
            {
                if (copy.Length is 0 or > 16384) throw new ArgumentException("Invalid rotation statement budget.");
                _statement = SecretMaterial.FromText(copy);
            }
            finally { Array.Clear(copy); }
        }
    }
    internal PostgresRotationParameters(JsonElement value)
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
    [JsonIgnore] public string Username1 { get; }
    [JsonIgnore] public string Username2 { get; }
    [JsonIgnore] public PostgresRotationPasswordRequirements? PasswordRequirements { get; }
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
            if (_statement is not null)
            {
                char[] copy = _statement.ExportCharacters();
                try { writer.WriteString("rotationStatement", copy.AsSpan()); }
                finally { Array.Clear(copy); }
            }
            writer.WriteEndObject();
        }
    }
    public void Dispose()
    {
        lock (_gate) { _disposed = true; _statement?.Dispose(); _statement = null; }
    }
    public override string ToString() => "[PostgresRotationParameters]";
}

public sealed class PostgresRotationTime
{
    public PostgresRotationTime(double hours, double minutes)
    {
        PostgresSecretRotationOperations.InputNumber(hours, 0, 23);
        PostgresSecretRotationOperations.InputNumber(minutes, 0, 59);
        Hours = hours;
        Minutes = minutes;
    }
    internal PostgresRotationTime(JsonElement value)
    {
        Hours = PostgresSecretRotationOperations.Number(value, "hours", 0, 23);
        Minutes = PostgresSecretRotationOperations.Number(value, "minutes", 0, 59);
    }
    [JsonIgnore] public double Hours { get; }
    [JsonIgnore] public double Minutes { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("rotateAtUtc");
        writer.WriteNumber("hours", Hours);
        writer.WriteNumber("minutes", Minutes);
        writer.WriteEndObject();
    }
    public override string ToString() => "[PostgresRotationTime]";
}

/// <summary>Secret key mapping, not generated authentication material.</summary>
public sealed class PostgresRotationSecretsMapping
{
    public PostgresRotationSecretsMapping(string username, string password)
    {
        ManagementJson.Text(username, 16384);
        ManagementJson.Text(password, 16384);
        Username = username;
        Password = password;
    }
    internal PostgresRotationSecretsMapping(JsonElement value, bool nonempty = true)
    {
        Username = nonempty ? ManagementJson.Nonempty(value, "username") : ManagementJson.Required(value, "username");
        Password = nonempty ? ManagementJson.Nonempty(value, "password") : ManagementJson.Required(value, "password");
    }
    [JsonIgnore] public string Username { get; }
    [JsonIgnore] public string Password { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("secretsMapping");
        writer.WriteString("username", Username);
        writer.WriteString("password", Password);
        writer.WriteEndObject();
    }
    public override string ToString() => "[PostgresRotationSecretsMapping]";
}

public sealed class PostgresSecretRotationCreation
{
    public PostgresSecretRotationCreation(string name, string projectId, string environment, string secretPath,
        string connectionId, double rotationInterval, PostgresRotationParameters parameters,
        PostgresRotationSecretsMapping secretsMapping, PostgresRotationTime? rotateAtUtc = null,
        PostgresRotationNullableText? description = null, bool? isAutoRotationEnabled = null)
    {
        ManagementJson.Text(name, 64);
        ManagementJson.Text(projectId);
        ManagementJson.Text(environment, 64);
        ManagementJson.Text(secretPath);
        PostgresSecretRotationOperations.InputUuid(connectionId);
        PostgresSecretRotationOperations.InputNumber(rotationInterval, 1);
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
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string ProjectId { get; }
    [JsonIgnore] public string Environment { get; }
    [JsonIgnore] public string SecretPath { get; }
    [JsonIgnore] public string ConnectionId { get; }
    [JsonIgnore] public double RotationInterval { get; }
    [JsonIgnore] public PostgresRotationParameters Parameters { get; }
    [JsonIgnore] public PostgresRotationSecretsMapping SecretsMapping { get; }
    [JsonIgnore] public PostgresRotationTime? RotateAtUtc { get; }
    [JsonIgnore] public PostgresRotationNullableText? Description { get; }
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
    public override string ToString() => "[PostgresSecretRotationCreation]";
}

/// <summary>Empty PATCH and omitted members are preserved. Nested persistence is not asserted.</summary>
public sealed class PostgresSecretRotationUpdate
{
    private readonly string? _name;
    private readonly PostgresRotationNullableText? _description;
    private readonly bool? _enabled;
    private readonly double? _interval;
    private readonly PostgresRotationParameters? _parameters;
    private readonly PostgresRotationSecretsMapping? _mapping;
    private readonly PostgresRotationTime? _time;
    public PostgresSecretRotationUpdate(string? name = null, PostgresRotationNullableText? description = null,
        bool? isAutoRotationEnabled = null, double? rotationInterval = null,
        PostgresRotationParameters? parameters = null, PostgresRotationSecretsMapping? secretsMapping = null,
        PostgresRotationTime? rotateAtUtc = null)
    {
        if (name is not null) ManagementJson.Text(name, 64);
        if (description?.Value?.Length > 256) throw new ArgumentException("Invalid rotation description budget.");
        if (rotationInterval is { } interval) PostgresSecretRotationOperations.InputNumber(interval, 1);
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
    public override string ToString() => "[PostgresSecretRotationUpdate]";
}

public sealed class PostgresSecretRotationMove
{
    public PostgresSecretRotationMove(string destinationEnvironment, string destinationSecretPath,
        bool? overwriteDestination = null)
    {
        ManagementJson.Text(destinationEnvironment);
        ManagementJson.Text(destinationSecretPath);
        DestinationEnvironment = destinationEnvironment;
        DestinationSecretPath = destinationSecretPath;
        OverwriteDestination = overwriteDestination;
    }
    [JsonIgnore] public string DestinationEnvironment { get; }
    [JsonIgnore] public string DestinationSecretPath { get; }
    [JsonIgnore] public bool? OverwriteDestination { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("destinationEnvironment", DestinationEnvironment);
        writer.WriteString("destinationSecretPath", DestinationSecretPath);
        if (OverwriteDestination is { } overwrite) writer.WriteBoolean("overwriteDestination", overwrite);
        writer.WriteEndObject();
    }
    public override string ToString() => "[PostgresSecretRotationMove]";
}

/// <summary>Server-authored metadata. Status is open; timestamps/job IDs do not attribute a previous trigger.</summary>
public sealed class PostgresSecretRotationSummary : IDisposable
{
    internal PostgresSecretRotationSummary(JsonElement value, string projectId, string? id = null,
        string? name = null, string? environment = null, string? secretPath = null, string? connectionId = null)
    {
        ManagementJson.RequireEqual(value, "type", "postgres-credentials");
        ManagementJson.RequireEqual(value, "projectId", projectId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (name is not null) ManagementJson.RequireEqual(value, "name", name);
        Id = PostgresSecretRotationOperations.Uuid(value, "id");
        ProjectId = ManagementJson.Required(value, "projectId");
        Name = ManagementJson.Required(value, "name");
        ConnectionId = PostgresSecretRotationOperations.Uuid(value, "connectionId");
        if (connectionId is not null) ManagementJson.RequireEqual(value, "connectionId", connectionId);
        JsonElement connection = ManagementJson.Object(value, "connection");
        ManagementJson.RequireEqual(connection, "app", "postgres");
        ManagementJson.RequireEqual(connection, "id", ConnectionId);
        ConnectionName = ManagementJson.Required(connection, "name");
        JsonElement env = ManagementJson.Object(value, "environment");
        EnvironmentId = PostgresSecretRotationOperations.Uuid(env, "id");
        EnvironmentName = ManagementJson.Required(env, "name");
        Environment = ManagementJson.Required(env, "slug");
        if (environment is not null) ManagementJson.RequireEqual(env, "slug", environment);
        JsonElement folder = ManagementJson.Object(value, "folder");
        FolderId = PostgresSecretRotationOperations.Uuid(value, "folderId");
        ManagementJson.RequireEqual(folder, "id", FolderId);
        SecretPath = ManagementJson.Required(folder, "path");
        if (secretPath is not null) ManagementJson.RequireEqual(folder, "path", secretPath);
        CreatedAt = ManagementJson.Timestamp(value, "createdAt", true)!;
        UpdatedAt = ManagementJson.Timestamp(value, "updatedAt", true)!;
        LastRotatedAt = ManagementJson.Timestamp(value, "lastRotatedAt", true)!;
        LastRotationAttemptedAt = ManagementJson.Timestamp(value, "lastRotationAttemptedAt", true)!;
        RotationStatus = ManagementJson.Required(value, "rotationStatus");
        ActiveIndex = value.TryGetProperty("activeIndex", out _) ? PostgresSecretRotationOperations.Number(value, "activeIndex") : null;
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
        RotationInterval = PostgresSecretRotationOperations.Number(value, "rotationInterval");
        SecretsMapping = new(ManagementJson.Object(value, "secretsMapping"));
        // Material is allocated last so a rejected coordinate cannot leak an owned result.
        Parameters = new(ManagementJson.Object(value, "parameters"));
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string ProjectId { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public string ConnectionId { get; }
    [JsonIgnore] public string ConnectionName { get; }
    [JsonIgnore] public string EnvironmentId { get; }
    [JsonIgnore] public string EnvironmentName { get; }
    [JsonIgnore] public string Environment { get; }
    [JsonIgnore] public string FolderId { get; }
    [JsonIgnore] public string SecretPath { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public string LastRotatedAt { get; }
    [JsonIgnore] public string LastRotationAttemptedAt { get; }
    [JsonIgnore] public string RotationStatus { get; }
    [JsonIgnore] public double? ActiveIndex { get; }
    [JsonIgnore] public bool? IsAutoRotationEnabled { get; }
    [JsonIgnore] public bool? IsLastRotationManual { get; }
    [JsonIgnore] public bool HasDescription { get; }
    [JsonIgnore] public string? Description { get; }
    [JsonIgnore] public bool HasLastRotationJobId { get; }
    [JsonIgnore] public string? LastRotationJobId { get; }
    [JsonIgnore] public bool HasLastRotationMessage { get; }
    [JsonIgnore] public string? LastRotationMessage { get; }
    [JsonIgnore] public bool HasNextRotationAt { get; }
    [JsonIgnore] public string? NextRotationAt { get; }
    [JsonIgnore] public PostgresRotationTime RotateAtUtc { get; }
    [JsonIgnore] public double RotationInterval { get; }
    [JsonIgnore] public PostgresRotationSecretsMapping SecretsMapping { get; }
    [JsonIgnore] public PostgresRotationParameters Parameters { get; }
    public void Dispose() => Parameters.Dispose();
    public override string ToString() => "[PostgresSecretRotationSummary]";
}

/// <summary>Disposable list owns every selected PostgreSQL result; mixed catalogs remain explicitly partial.</summary>
public sealed class PostgresSecretRotationList : IDisposable
{
    internal PostgresSecretRotationList(IEnumerable<PostgresSecretRotationSummary> items, bool complete)
    {
        Items = Array.AsReadOnly(items.ToArray());
        IsComplete = complete;
    }
    [JsonIgnore] public IReadOnlyList<PostgresSecretRotationSummary> Items { get; }
    public bool IsComplete { get; }
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    public override string ToString() => "[PostgresSecretRotationList]";
}

public sealed class PostgresGeneratedCredential : IDisposable
{
    internal PostgresGeneratedCredential(string username, string password)
    {
        Username = SecretMaterial.FromText(username);
        try { Password = SecretMaterial.FromText(password); }
        catch { Username.Dispose(); throw; }
    }
    [JsonIgnore] public SecretMaterial Username { get; }
    [JsonIgnore] public SecretMaterial Password { get; }
    public void Dispose() { Username.Dispose(); Password.Dispose(); }
    public override string ToString() => "[PostgresGeneratedCredential]";
}

/// <summary>One observed material response, not proof of current database access or trigger attribution.</summary>
public sealed class PostgresGeneratedCredentials : IDisposable
{
    internal PostgresGeneratedCredentials(JsonElement value, string rotationId)
    {
        ManagementJson.RequireEqual(value, "type", "postgres-credentials");
        ManagementJson.RequireEqual(value, "rotationId", rotationId);
        RotationId = PostgresSecretRotationOperations.Uuid(value, "rotationId");
        ActiveIndex = PostgresSecretRotationOperations.Number(value, "activeIndex");
        var values = ManagementJson.Array(value, "generatedCredentials");
        var parsed = new List<PostgresGeneratedCredential>();
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
    [JsonIgnore] public string RotationId { get; }
    [JsonIgnore] public double ActiveIndex { get; }
    [JsonIgnore] public IReadOnlyList<PostgresGeneratedCredential> Items { get; }
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    public override string ToString() => "[PostgresGeneratedCredentials]";
}

/// <summary>A PostgreSQL-only catalog option. Statements are protected template text, never executed.</summary>
public sealed class PostgresSecretRotationOption : IDisposable
{
    internal PostgresSecretRotationOption(JsonElement value)
    {
        ManagementJson.RequireEqual(value, "type", "postgres-credentials");
        ManagementJson.RequireEqual(value, "connection", "postgres");
        ManagementJson.RequireEqual(value, "name", "PostgreSQL Credentials");
        JsonElement template = ManagementJson.Object(value, "template");
        SecretsMapping = new(ManagementJson.Object(template, "secretsMapping"), false);
        string create = ManagementJson.Required(template, "createUserStatement");
        string rotate = ManagementJson.Required(template, "rotationStatement");
        CreateUserStatement = SecretMaterial.FromText(create);
        try { RotationStatement = SecretMaterial.FromText(rotate); }
        catch { CreateUserStatement.Dispose(); throw; }
    }
    [JsonIgnore] public SecretMaterial CreateUserStatement { get; }
    [JsonIgnore] public SecretMaterial RotationStatement { get; }
    [JsonIgnore] public PostgresRotationSecretsMapping SecretsMapping { get; }
    public void Dispose() { CreateUserStatement.Dispose(); RotationStatement.Dispose(); }
    public override string ToString() => "[PostgresSecretRotationOption]";
}

public sealed class PostgresSecretRotationOptions : IDisposable
{
    internal PostgresSecretRotationOptions(IEnumerable<PostgresSecretRotationOption> items) =>
        Items = Array.AsReadOnly(items.ToArray());
    [JsonIgnore] public IReadOnlyList<PostgresSecretRotationOption> Items { get; }
    public bool IsComplete => false;
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    public override string ToString() => "[PostgresSecretRotationOptions]";
}

/// <summary>Native 204 credential-check acknowledgement only; no material or convergence result.</summary>
public sealed class PostgresCredentialCheckAcknowledgement
{
    internal PostgresCredentialCheckAcknowledgement() { }
    public override string ToString() => "[PostgresCredentialCheckAcknowledgement]";
}
