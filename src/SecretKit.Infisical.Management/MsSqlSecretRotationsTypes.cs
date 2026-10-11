using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>A supplied nullable rotation description; no wrapper means omission.</summary>
public sealed class MsSqlRotationNullableText
{
    public MsSqlRotationNullableText(string? value)
    {
        if (value?.Length > 16384) throw new ArgumentException("Invalid Microsoft SQL Server text budget.");
        Value = value;
    }
    [JsonIgnore] public string? Value { get; }
    public override string ToString() => "[MsSqlRotationNullableText]";
}

/// <summary>Published numeric requirements; fractional numbers are not silently rounded.</summary>
public sealed class MsSqlRotationPasswordRequirements
{
    public MsSqlRotationPasswordRequirements(double length, double digits, double lowercase,
        double symbols, double uppercase, string? allowedSymbols = null)
    {
        MsSqlSecretRotationOperations.InputNumber(length, 1, 250);
        foreach (double count in new[] { digits, lowercase, symbols, uppercase })
            MsSqlSecretRotationOperations.InputNumber(count, 0);
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
    internal MsSqlRotationPasswordRequirements(JsonElement value)
    {
        MsSqlSecretRotationOperations.Only(value, "length", "required", "allowedSymbols");
        Length = MsSqlSecretRotationOperations.Number(value, "length", 1, 250);
        JsonElement required = ManagementJson.Object(value, "required");
        MsSqlSecretRotationOperations.Only(required, "digits", "lowercase", "symbols", "uppercase");
        Digits = MsSqlSecretRotationOperations.Number(required, "digits", 0);
        Lowercase = MsSqlSecretRotationOperations.Number(required, "lowercase", 0);
        Symbols = MsSqlSecretRotationOperations.Number(required, "symbols", 0);
        Uppercase = MsSqlSecretRotationOperations.Number(required, "uppercase", 0);
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
    public override string ToString() => "[MsSqlRotationPasswordRequirements]";
}

/// <summary>Native configuration only. Statement material is copied, never executed by the SDK.</summary>
public sealed class MsSqlRotationParameters : IDisposable
{
    private readonly object _gate = new();
    private bool _disposed;
    private SecretMaterial? _statement;
    public MsSqlRotationParameters(string username1, string username2,
        MsSqlRotationPasswordRequirements? passwordRequirements = null, SecretMaterial? rotationStatement = null)
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
    internal MsSqlRotationParameters(JsonElement value)
    {
        MsSqlSecretRotationOperations.Only(value, "username1", "username2", "passwordRequirements", "rotationStatement");
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
    [JsonIgnore] public MsSqlRotationPasswordRequirements? PasswordRequirements { get; }
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
    public override string ToString() => "[MsSqlRotationParameters]";
}

public sealed class MsSqlRotationTime
{
    public MsSqlRotationTime(double hours, double minutes)
    {
        MsSqlSecretRotationOperations.InputNumber(hours, 0, 23);
        MsSqlSecretRotationOperations.InputNumber(minutes, 0, 59);
        Hours = hours;
        Minutes = minutes;
    }
    internal MsSqlRotationTime(JsonElement value)
    {
        MsSqlSecretRotationOperations.Only(value, "hours", "minutes");
        Hours = MsSqlSecretRotationOperations.Number(value, "hours", 0, 23);
        Minutes = MsSqlSecretRotationOperations.Number(value, "minutes", 0, 59);
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
    public override string ToString() => "[MsSqlRotationTime]";
}

/// <summary>Secret key mapping, not generated authentication material.</summary>
public sealed class MsSqlRotationSecretsMapping
{
    public MsSqlRotationSecretsMapping(string username, string password)
    {
        ManagementJson.Text(username, 16384);
        ManagementJson.Text(password, 16384);
        Username = username;
        Password = password;
    }
    internal MsSqlRotationSecretsMapping(JsonElement value, bool nonempty = true)
    {
        MsSqlSecretRotationOperations.Only(value, "username", "password");
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
    public override string ToString() => "[MsSqlRotationSecretsMapping]";
}

public sealed class MsSqlSecretRotationCreation
{
    public MsSqlSecretRotationCreation(string name, string projectId, string environment, string secretPath,
        string connectionId, double rotationInterval, MsSqlRotationParameters parameters,
        MsSqlRotationSecretsMapping secretsMapping, MsSqlRotationTime? rotateAtUtc = null,
        MsSqlRotationNullableText? description = null, bool? isAutoRotationEnabled = null)
    {
        ManagementJson.Text(name, 64);
        ManagementJson.Text(projectId);
        ManagementJson.Text(environment, 64);
        ManagementJson.Text(secretPath);
        MsSqlSecretRotationOperations.InputUuid(connectionId);
        MsSqlSecretRotationOperations.InputNumber(rotationInterval, 1);
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
    [JsonIgnore] public MsSqlRotationParameters Parameters { get; }
    [JsonIgnore] public MsSqlRotationSecretsMapping SecretsMapping { get; }
    [JsonIgnore] public MsSqlRotationTime? RotateAtUtc { get; }
    [JsonIgnore] public MsSqlRotationNullableText? Description { get; }
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
    public override string ToString() => "[MsSqlSecretRotationCreation]";
}

/// <summary>Empty PATCH and omitted members are preserved. Nested persistence is not asserted.</summary>
public sealed class MsSqlSecretRotationUpdate
{
    private readonly string? _name;
    private readonly MsSqlRotationNullableText? _description;
    private readonly bool? _enabled;
    private readonly double? _interval;
    private readonly MsSqlRotationParameters? _parameters;
    private readonly MsSqlRotationSecretsMapping? _mapping;
    private readonly MsSqlRotationTime? _time;
    public MsSqlSecretRotationUpdate(string? name = null, MsSqlRotationNullableText? description = null,
        bool? isAutoRotationEnabled = null, double? rotationInterval = null,
        MsSqlRotationParameters? parameters = null, MsSqlRotationSecretsMapping? secretsMapping = null,
        MsSqlRotationTime? rotateAtUtc = null)
    {
        if (name is not null) ManagementJson.Text(name, 64);
        if (description?.Value?.Length > 256) throw new ArgumentException("Invalid rotation description budget.");
        if (rotationInterval is { } interval) MsSqlSecretRotationOperations.InputNumber(interval, 1);
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
    public override string ToString() => "[MsSqlSecretRotationUpdate]";
}

public sealed class MsSqlSecretRotationMove
{
    public MsSqlSecretRotationMove(string destinationEnvironment, string destinationSecretPath,
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
    public override string ToString() => "[MsSqlSecretRotationMove]";
}

/// <summary>Server-authored metadata. Status is open; timestamps/job IDs do not attribute a previous trigger.</summary>
public sealed class MsSqlSecretRotationSummary : IDisposable
{
    internal MsSqlSecretRotationSummary(JsonElement value, string projectId, string? id = null,
        string? name = null, string? environment = null, string? secretPath = null, string? connectionId = null)
    {
        MsSqlSecretRotationOperations.Only(value, "type", "projectId", "id", "name", "connectionId", "connection",
            "environment", "folderId", "folder", "createdAt", "updatedAt", "lastRotatedAt", "lastRotationAttemptedAt",
            "rotationStatus", "activeIndex", "isAutoRotationEnabled", "isLastRotationManual", "description",
            "lastRotationJobId", "lastRotationMessage", "nextRotationAt", "rotateAtUtc", "rotationInterval",
            "secretsMapping", "parameters");
        ManagementJson.RequireEqual(value, "type", "mssql-credentials");
        ManagementJson.RequireEqual(value, "projectId", projectId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        if (name is not null) ManagementJson.RequireEqual(value, "name", name);
        Id = MsSqlSecretRotationOperations.Uuid(value, "id");
        ProjectId = ManagementJson.Required(value, "projectId");
        Name = ManagementJson.Required(value, "name");
        ConnectionId = MsSqlSecretRotationOperations.Uuid(value, "connectionId");
        if (connectionId is not null) ManagementJson.RequireEqual(value, "connectionId", connectionId);
        JsonElement connection = ManagementJson.Object(value, "connection");
        MsSqlSecretRotationOperations.Only(connection, "app", "id", "name");
        ManagementJson.RequireEqual(connection, "app", "mssql");
        ManagementJson.RequireEqual(connection, "id", ConnectionId);
        ConnectionName = ManagementJson.Required(connection, "name");
        JsonElement env = ManagementJson.Object(value, "environment");
        MsSqlSecretRotationOperations.Only(env, "id", "name", "slug");
        EnvironmentId = MsSqlSecretRotationOperations.Uuid(env, "id");
        EnvironmentName = ManagementJson.Required(env, "name");
        Environment = ManagementJson.Required(env, "slug");
        if (environment is not null) ManagementJson.RequireEqual(env, "slug", environment);
        JsonElement folder = ManagementJson.Object(value, "folder");
        MsSqlSecretRotationOperations.Only(folder, "id", "path");
        FolderId = MsSqlSecretRotationOperations.Uuid(value, "folderId");
        ManagementJson.RequireEqual(folder, "id", FolderId);
        SecretPath = ManagementJson.Required(folder, "path");
        if (secretPath is not null) ManagementJson.RequireEqual(folder, "path", secretPath);
        CreatedAt = ManagementJson.Timestamp(value, "createdAt", true)!;
        UpdatedAt = ManagementJson.Timestamp(value, "updatedAt", true)!;
        LastRotatedAt = ManagementJson.Timestamp(value, "lastRotatedAt", true)!;
        LastRotationAttemptedAt = ManagementJson.Timestamp(value, "lastRotationAttemptedAt", true)!;
        RotationStatus = ManagementJson.Required(value, "rotationStatus");
        ActiveIndex = value.TryGetProperty("activeIndex", out _) ? MsSqlSecretRotationOperations.Number(value, "activeIndex") : null;
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
        RotationInterval = MsSqlSecretRotationOperations.Number(value, "rotationInterval");
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
    [JsonIgnore] public MsSqlRotationTime RotateAtUtc { get; }
    [JsonIgnore] public double RotationInterval { get; }
    [JsonIgnore] public MsSqlRotationSecretsMapping SecretsMapping { get; }
    [JsonIgnore] public MsSqlRotationParameters Parameters { get; }
    public void Dispose() => Parameters.Dispose();
    public override string ToString() => "[MsSqlSecretRotationSummary]";
}

/// <summary>Disposable list owns every selected Microsoft SQL Server result; mixed catalogs remain explicitly partial.</summary>
public sealed class MsSqlSecretRotationList : IDisposable
{
    internal MsSqlSecretRotationList(IEnumerable<MsSqlSecretRotationSummary> items, bool complete)
    {
        Items = Array.AsReadOnly(items.ToArray());
        IsComplete = complete;
    }
    [JsonIgnore] public IReadOnlyList<MsSqlSecretRotationSummary> Items { get; }
    public bool IsComplete { get; }
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    public override string ToString() => "[MsSqlSecretRotationList]";
}

public sealed class MsSqlGeneratedCredential : IDisposable
{
    internal MsSqlGeneratedCredential(string username, string password)
    {
        Username = SecretMaterial.FromText(username);
        try { Password = SecretMaterial.FromText(password); }
        catch { Username.Dispose(); throw; }
    }
    [JsonIgnore] public SecretMaterial Username { get; }
    [JsonIgnore] public SecretMaterial Password { get; }
    public void Dispose() { Username.Dispose(); Password.Dispose(); }
    public override string ToString() => "[MsSqlGeneratedCredential]";
}

/// <summary>One observed material response, not proof of current database access or trigger attribution.</summary>
public sealed class MsSqlGeneratedCredentials : IDisposable
{
    internal MsSqlGeneratedCredentials(JsonElement value, string rotationId)
    {
        MsSqlSecretRotationOperations.Only(value, "type", "rotationId", "activeIndex", "generatedCredentials");
        ManagementJson.RequireEqual(value, "type", "mssql-credentials");
        ManagementJson.RequireEqual(value, "rotationId", rotationId);
        RotationId = MsSqlSecretRotationOperations.Uuid(value, "rotationId");
        ActiveIndex = MsSqlSecretRotationOperations.Number(value, "activeIndex");
        var values = ManagementJson.Array(value, "generatedCredentials");
        var parsed = new List<MsSqlGeneratedCredential>();
        try
        {
            foreach (var item in values)
            {
                MsSqlSecretRotationOperations.Only(item, "username", "password");
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
    [JsonIgnore] public IReadOnlyList<MsSqlGeneratedCredential> Items { get; }
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    public override string ToString() => "[MsSqlGeneratedCredentials]";
}

/// <summary>A Microsoft SQL Server-only catalog option. Statements are protected template text, never executed.</summary>
public sealed class MsSqlSecretRotationOption : IDisposable
{
    internal MsSqlSecretRotationOption(JsonElement value)
    {
        MsSqlSecretRotationOperations.Only(value, "type", "connection", "name", "template");
        ManagementJson.RequireEqual(value, "type", "mssql-credentials");
        ManagementJson.RequireEqual(value, "connection", "mssql");
        ManagementJson.RequireEqual(value, "name", "Microsoft SQL Server Credentials");
        JsonElement template = ManagementJson.Object(value, "template");
        MsSqlSecretRotationOperations.Only(template, "secretsMapping", "createUserStatement", "rotationStatement");
        SecretsMapping = new(ManagementJson.Object(template, "secretsMapping"), false);
        string create = ManagementJson.Required(template, "createUserStatement");
        string rotate = ManagementJson.Required(template, "rotationStatement");
        CreateUserStatement = SecretMaterial.FromText(create);
        try { RotationStatement = SecretMaterial.FromText(rotate); }
        catch { CreateUserStatement.Dispose(); throw; }
    }
    [JsonIgnore] public SecretMaterial CreateUserStatement { get; }
    [JsonIgnore] public SecretMaterial RotationStatement { get; }
    [JsonIgnore] public MsSqlRotationSecretsMapping SecretsMapping { get; }
    public void Dispose() { CreateUserStatement.Dispose(); RotationStatement.Dispose(); }
    public override string ToString() => "[MsSqlSecretRotationOption]";
}

public sealed class MsSqlSecretRotationOptions : IDisposable
{
    internal MsSqlSecretRotationOptions(IEnumerable<MsSqlSecretRotationOption> items) =>
        Items = Array.AsReadOnly(items.ToArray());
    [JsonIgnore] public IReadOnlyList<MsSqlSecretRotationOption> Items { get; }
    public bool IsComplete => false;
    public void Dispose() { foreach (var item in Items) item.Dispose(); }
    public override string ToString() => "[MsSqlSecretRotationOptions]";
}

/// <summary>Native 204 credential-check acknowledgement only; no material or convergence result.</summary>
public sealed class MsSqlCredentialCheckAcknowledgement
{
    internal MsSqlCredentialCheckAcknowledgement() { }
    public override string ToString() => "[MsSqlCredentialCheckAcknowledgement]";
}
