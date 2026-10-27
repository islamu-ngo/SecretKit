using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Native rule family; each family admits its own constraints and providers.</summary>
public enum InfisicalValidationKind { /** <summary>Static key/value rules.</summary> */ StaticSecrets, /** <summary>Dynamic password rules.</summary> */ DynamicSecrets, /** <summary>Rotation password rules.</summary> */ SecretRotations }
/// <summary>Closed provider selectors for supported validation-rule families.</summary>
public enum InfisicalValidationProvider
{
    /** <summary>Dynamic SQL database passwords.</summary> */
    SqlDatabase, /** <summary>Dynamic Milvus passwords.</summary> */ Milvus, /** <summary>PostgreSQL rotation credentials.</summary> */ PostgresCredentials, /** <summary>MySQL rotation credentials.</summary> */ MysqlCredentials, /** <summary>SQL Server rotation credentials.</summary> */ MssqlCredentials,
    /** <summary>Oracle rotation credentials.</summary> */
    OracleCredentials, /** <summary>Unix/Linux account rotation.</summary> */ UnixLinuxLocalAccount, /** <summary>LDAP password rotation.</summary> */ LdapPassword
}

/// <summary>Protected project/rule coordinates with explicit validation family and optional scope.</summary>
public sealed class InfisicalValidationAddress : InfisicalNativeAddress
{
    /// <summary>Selects a rule family and optional rule UUID/environment/path, without granting mutation authority.</summary>
    public InfisicalValidationAddress(string projectId, InfisicalValidationKind kind,
        string? ruleId = null, string? environment = null, string? secretPath = null)
        : base(projectId, environment, secretPath)
    {
        NativeText(projectId, 36);
        if (!Enum.IsDefined(kind) || (ruleId is not null && !Guid.TryParse(ruleId, out _)))
        {
            throw new ArgumentException("Invalid validation rule selector.");
        }
        if (environment is not null) { NativeText(environment, 64); }
        Kind = kind;
        RuleId = ruleId;
    }
    /// <summary>The explicitly selected native validation family.</summary>
    public InfisicalValidationKind Kind { get; }
    /// <summary>The native rule UUID, or null for creation/listing.</summary>
    [JsonIgnore]
    public string? RuleId { get; }
}

/// <summary>Wire constraints only. SecretKit does not execute provider regexes or enforce server policy locally.</summary>
public sealed class InfisicalTextConstraints
{
    /// <summary>Validates bounded constraint inputs; family-specific admission occurs at the operation boundary.</summary>
    public InfisicalTextConstraints(int? minimumLength = null, int? maximumLength = null,
        string? regexPattern = null, string? requiredPrefix = null, string? requiredSuffix = null,
        int? uniqueAcrossLastVersions = null, bool? uniqueWithinScope = null)
    {
        if (minimumLength is < 1 or > 65536 || maximumLength is < 1 or > 65536 ||
            (minimumLength is not null && maximumLength is not null && minimumLength > maximumLength) ||
            uniqueAcrossLastVersions is < 1 or > 25)
        {
            throw new ArgumentException("Invalid validation bounds.");
        }
        if (regexPattern is { Length: < 1 or > 4096 } ||
            requiredPrefix is { Length: < 1 or > 1024 } || requiredSuffix is { Length: < 1 or > 1024 })
        {
            throw new ArgumentException("Invalid constraint text length.");
        }
        MinimumLength = minimumLength;
        MaximumLength = maximumLength;
        RegexPattern = regexPattern;
        RequiredPrefix = requiredPrefix;
        RequiredSuffix = requiredSuffix;
        UniqueAcrossLastVersions = uniqueAcrossLastVersions;
        UniqueWithinScope = uniqueWithinScope;
    }
    /// <summary>Optional minimum native text length.</summary>
    [JsonIgnore]
    public int? MinimumLength { get; }
    /// <summary>Optional maximum native text length.</summary>
    [JsonIgnore]
    public int? MaximumLength { get; }
    /// <summary>Protected provider regex text; never executed locally.</summary>
    [JsonIgnore]
    public string? RegexPattern { get; }
    /// <summary>Optional protected required prefix.</summary>
    [JsonIgnore]
    public string? RequiredPrefix { get; }
    /// <summary>Optional protected required suffix.</summary>
    [JsonIgnore]
    public string? RequiredSuffix { get; }
    /// <summary>Optional static-value uniqueness window of 1..25 versions.</summary>
    [JsonIgnore]
    public int? UniqueAcrossLastVersions { get; }
    /// <summary>Optional static-value uniqueness within native scope.</summary>
    [JsonIgnore]
    public bool? UniqueWithinScope { get; }
    internal bool ValidFor(InfisicalValidationKind kind, bool value) =>
        (value || (UniqueAcrossLastVersions is null && UniqueWithinScope is null)) &&
        (kind == InfisicalValidationKind.StaticSecrets ||
            (MinimumLength is not > 2048 && MaximumLength is not > 2048 &&
                UniqueAcrossLastVersions is null && UniqueWithinScope is null));

    internal object Wire() => new
    {
        minLength = MinimumLength,
        maxLength = MaximumLength,
        regexPattern = RegexPattern,
        requiredPrefix = RequiredPrefix,
        requiredSuffix = RequiredSuffix,
        uniqueAcrossLastVersions = UniqueAcrossLastVersions,
        uniqueWithinScope = UniqueWithinScope
    };
    /// <summary>Returns a fixed label without protected constraint text.</summary>
    public override string ToString() => "[InfisicalTextConstraints]";
}

/// <summary>Absent fields stay unchanged. Explicit clear flags send null only where the contract accepts it.</summary>
public sealed class InfisicalValidationInput
{
    /// <summary>Freezes explicitly selected rule changes, rejecting contradictory clear/value pairs.</summary>
    public InfisicalValidationInput(string? name = null, string? description = null, bool? isActive = null,
        InfisicalTextConstraints? keyConstraints = null, InfisicalTextConstraints? valueConstraints = null,
        InfisicalTextConstraints? passwordConstraints = null, IReadOnlyList<InfisicalValidationProvider>? providers = null,
        string? environment = null, string? secretPath = null, bool clearDescription = false,
        bool clearEnvironment = false, bool clearKeyConstraints = false, bool clearValueConstraints = false)
    {
        if (name is not null) { InfisicalNativeAddress.NativeText(name, 64); }
        if (environment is not null) { InfisicalNativeAddress.NativeText(environment, 64); }
        if (secretPath is not null) { InfisicalNativeAddress.NativeFolder(secretPath); }
        if (description?.Length > 500 || (description is not null && clearDescription) ||
            (environment is not null && clearEnvironment) || (keyConstraints is not null && clearKeyConstraints) ||
            (valueConstraints is not null && clearValueConstraints) ||
            providers is { Count: < 1 or > 8 } || providers?.Any(provider => !Enum.IsDefined(provider)) == true)
        {
            throw new ArgumentException("Invalid validation input.");
        }
        Name = name;
        Description = description;
        IsActive = isActive;
        KeyConstraints = keyConstraints;
        ValueConstraints = valueConstraints;
        PasswordConstraints = passwordConstraints;
        Providers = providers is null ? null : Array.AsReadOnly(providers.ToArray());
        Environment = environment;
        SecretPath = secretPath;
        ClearDescription = clearDescription;
        ClearEnvironment = clearEnvironment;
        ClearKeyConstraints = clearKeyConstraints;
        ClearValueConstraints = clearValueConstraints;
    }
    /// <summary>Optional protected rule name.</summary>
    [JsonIgnore]
    public string? Name { get; }
    /// <summary>Optional protected description; null alone means omitted.</summary>
    [JsonIgnore]
    public string? Description { get; }
    /// <summary>Optional native activation selection.</summary>
    public bool? IsActive { get; }
    /// <summary>Optional static-key constraints.</summary>
    [JsonIgnore]
    public InfisicalTextConstraints? KeyConstraints { get; }
    /// <summary>Optional static-value constraints.</summary>
    [JsonIgnore]
    public InfisicalTextConstraints? ValueConstraints { get; }
    /// <summary>Optional dynamic/rotation password constraints.</summary>
    [JsonIgnore]
    public InfisicalTextConstraints? PasswordConstraints { get; }
    /// <summary>Frozen native provider selection for dynamic/rotation rules.</summary>
    [JsonIgnore]
    public IReadOnlyList<InfisicalValidationProvider>? Providers { get; }
    /// <summary>Optional new environment; any scope change must match explicit authority.</summary>
    [JsonIgnore]
    public string? Environment { get; }
    /// <summary>Optional new absolute secret path.</summary>
    [JsonIgnore]
    public string? SecretPath { get; }
    /// <summary>Explicitly sends null to clear the description.</summary>
    [JsonIgnore]
    public bool ClearDescription { get; }
    /// <summary>Explicitly clears the environment, requiring authority for the resulting scope.</summary>
    [JsonIgnore]
    public bool ClearEnvironment { get; }
    /// <summary>Explicitly clears static-key constraints where admitted.</summary>
    [JsonIgnore]
    public bool ClearKeyConstraints { get; }
    /// <summary>Explicitly clears static-value constraints where admitted.</summary>
    [JsonIgnore]
    public bool ClearValueConstraints { get; }
    /// <summary>Returns a fixed label without rule fields.</summary>
    public override string ToString() => "[InfisicalValidationInput]";
}

/// <summary>Validated native validation-rule projection; does not enforce policy locally or prove remote effects elsewhere.</summary>
public sealed class InfisicalValidationRule
{
    internal InfisicalValidationRule(string id, string project, InfisicalValidationKind kind,
        string name, string? description, string? environment, string path, bool? active,
        InfisicalTextConstraints? key, InfisicalTextConstraints? value, InfisicalTextConstraints? password,
        IReadOnlyList<InfisicalValidationProvider>? providers)
    {
        Id = id;
        ProjectId = project;
        Kind = kind;
        Name = name;
        Description = description;
        Environment = environment;
        SecretPath = path;
        IsActive = active;
        KeyConstraints = key;
        ValueConstraints = value;
        PasswordConstraints = password;
        Providers = providers;
    }
    /// <summary>The observed native rule UUID.</summary>
    [JsonIgnore]
    public string Id { get; }
    /// <summary>The validated project identity.</summary>
    [JsonIgnore]
    public string ProjectId { get; }
    /// <summary>The validated native rule family.</summary>
    public InfisicalValidationKind Kind { get; }
    /// <summary>The protected returned rule name.</summary>
    [JsonIgnore]
    public string Name { get; }
    /// <summary>The optional protected returned description.</summary>
    [JsonIgnore]
    public string? Description { get; }
    /// <summary>The returned environment slug, or null for unscoped environment.</summary>
    [JsonIgnore]
    public string? Environment { get; }
    /// <summary>The returned absolute rule path.</summary>
    [JsonIgnore]
    public string SecretPath { get; }
    /// <summary>Reported activation state, or null when unreported.</summary>
    public bool? IsActive { get; }
    /// <summary>The returned static-key constraints.</summary>
    [JsonIgnore]
    public InfisicalTextConstraints? KeyConstraints { get; }
    /// <summary>The returned static-value constraints.</summary>
    [JsonIgnore]
    public InfisicalTextConstraints? ValueConstraints { get; }
    /// <summary>The returned dynamic/rotation password constraints.</summary>
    [JsonIgnore]
    public InfisicalTextConstraints? PasswordConstraints { get; }
    /// <summary>The admitted provider list for the returned rule family.</summary>
    [JsonIgnore]
    public IReadOnlyList<InfisicalValidationProvider>? Providers { get; }
    /// <summary>Returns a fixed label without protected rule fields.</summary>
    public override string ToString() => "[InfisicalValidationRule]";
}

public sealed partial class InfisicalClient
{
    /// <summary>Inspects one native validation rule without executing its constraints locally.</summary>
    public ValueTask<SecretOutcome<InfisicalValidationRule>> GetValidationRuleAsync(SecretReference target,
        CancellationToken cancellationToken = default) =>
        ValidationOperationAsync(target, HttpMethod.Get, null, null, null, cancellationToken);

    /// <summary>Creates a family-valid rule under explicit native authority with caller-held dispatch evidence.</summary>
    /// <remarks>Invalid selection is rejected locally; missing or unvalidated response evidence is Unknown.
    /// Retain the receipt after cancellation or uncertainty; no mutation replay occurs.</remarks>
    public ValueTask<SecretOutcome<InfisicalValidationRule>> CreateValidationRuleAsync(SecretReference target,
        InfisicalValidationInput input, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default) =>
        ChangeValidationRuleAsync(target, input, authority, receipt, false, cancellationToken);

    /// <summary>Applies explicit rule changes and validates resulting scope against the selected authority.</summary>
    public ValueTask<SecretOutcome<InfisicalValidationRule>> UpdateValidationRuleAsync(SecretReference target,
        InfisicalValidationInput input, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default) =>
        ChangeValidationRuleAsync(target, input, authority, receipt, true, cancellationToken);

    /// <summary>Deletes the selected rule with retained receipt evidence; cancellation is not rollback.</summary>
    public ValueTask<SecretOutcome<InfisicalValidationRule>> DeleteValidationRuleAsync(SecretReference target,
        InfisicalNativeAuthority authority, MutationReceipt receipt, CancellationToken cancellationToken = default) =>
        ValidationOperationAsync(target, HttpMethod.Delete, null, authority, receipt, cancellationToken);

    private ValueTask<SecretOutcome<InfisicalValidationRule>> ChangeValidationRuleAsync(SecretReference target,
        InfisicalValidationInput input, InfisicalNativeAuthority authority, MutationReceipt receipt, bool update,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        cancellationToken.ThrowIfCancellationRequested();
        if (target.Address is not InfisicalValidationAddress address ||
            (update ? address.RuleId is null : address.RuleId is not null) ||
            (!update && (input.Name is null || address.Folder is null || input.ClearEnvironment ||
                input.ClearKeyConstraints || input.ClearValueConstraints)) ||
            !NativeTargetValid(target, authority, receipt) ||
            (input.Environment is not null && !authority.Matches(Authority,
                new InfisicalValidationAddress(address.ProjectId, address.Kind, environment: input.Environment,
                    secretPath: input.SecretPath ?? address.Folder))) ||
            (input.ClearEnvironment && !authority.Matches(Authority,
                new InfisicalValidationAddress(address.ProjectId, address.Kind, secretPath: input.SecretPath ?? address.Folder))) ||
            (input.SecretPath is not null && !authority.Matches(Authority,
                new InfisicalValidationAddress(address.ProjectId, address.Kind,
                    environment: input.Environment ?? address.Environment, secretPath: input.SecretPath))) ||
            !ValidationInputValid(input, address.Kind, update))
        {
            return ValueTask.FromResult(SecretOutcome<InfisicalValidationRule>.Failure(SecretStatus.Invalid));
        }
        var body = new Dictionary<string, object?>();
        if (!update) { body["projectId"] = address.ProjectId; body["secretPath"] = address.Folder; }
        if (!update && address.Environment is not null) { body["environment"] = address.Environment; }
        if (input.Name is not null) { body["name"] = input.Name; }
        if (input.Description is not null || input.ClearDescription) { body["description"] = input.Description; }
        if (input.Environment is not null || input.ClearEnvironment) { body["environment"] = input.Environment; }
        if (input.SecretPath is not null) { body["secretPath"] = input.SecretPath; }
        if (input.IsActive is not null) { body["isActive"] = input.IsActive; }
        if (input.KeyConstraints is not null || input.ClearKeyConstraints) { body["keyConstraints"] = input.KeyConstraints?.Wire(); }
        if (input.ValueConstraints is not null || input.ClearValueConstraints) { body["valueConstraints"] = input.ValueConstraints?.Wire(); }
        if (input.PasswordConstraints is not null) { body["passwordConstraints"] = input.PasswordConstraints.Wire(); }
        if (input.Providers is not null) { body["providers"] = input.Providers.Select(ValidationProviderWire).ToArray(); }
        // Serialize nested absent constraint fields without converting explicit top-level clears into omission.
        foreach (string key in new[] { "keyConstraints", "valueConstraints", "passwordConstraints" })
        {
            if (body.TryGetValue(key, out object? value) && value is not null)
            {
                body[key] = JsonSerializer.SerializeToElement(value, NativePayloadOptions);
            }
        }
        return ValidationOperationAsync(target, update ? HttpMethod.Patch : HttpMethod.Post,
            JsonSerializer.SerializeToUtf8Bytes(body), authority, receipt, cancellationToken);
    }

    private static bool ValidationInputValid(InfisicalValidationInput input, InfisicalValidationKind kind, bool update)
    {
        if (kind == InfisicalValidationKind.StaticSecrets)
        {
            return input.PasswordConstraints is null && input.Providers is null &&
                (input.KeyConstraints?.ValidFor(kind, false) ?? true) &&
                (input.ValueConstraints?.ValidFor(kind, true) ?? true);
        }
        return input.KeyConstraints is null && input.ValueConstraints is null &&
            !input.ClearKeyConstraints && !input.ClearValueConstraints &&
            (update || (input.PasswordConstraints is not null && input.Providers is not null)) &&
            (input.PasswordConstraints?.ValidFor(kind, false) ?? true) &&
            (input.Providers?.All(provider => ValidationProviderValid(kind, provider)) ?? true);
    }

    private async ValueTask<SecretOutcome<InfisicalValidationRule>> ValidationOperationAsync(SecretReference target,
        HttpMethod method, byte[]? payload, InfisicalNativeAuthority? authority, MutationReceipt? receipt,
        CancellationToken cancellationToken)
    {
        if (target.Address is not InfisicalValidationAddress address ||
            (method != HttpMethod.Post && address.RuleId is null))
        {
            if (payload is not null) { Array.Clear(payload); }
            return SecretOutcome<InfisicalValidationRule>.Failure(SecretStatus.Invalid);
        }
        string path = "api/v1/secret-validation-rules/" + ValidationKindWire(address.Kind) +
            (method == HttpMethod.Post ? "" : "/" + Uri.EscapeDataString(address.RuleId!));
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, path, method, payload, authority, receipt, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalValidationRule>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeObject(document.RootElement, "secretValidationRule", out JsonElement item) ||
            ParseValidationRule(item, address.ProjectId, address.Kind) is not { } rule ||
            (address.RuleId is not null && rule.Id != address.RuleId) ||
            (method != HttpMethod.Patch && ((address.Environment is not null && rule.Environment != address.Environment) ||
                (address.Folder is not null && rule.SecretPath != address.Folder))))
        {
            return SecretOutcome<InfisicalValidationRule>.Failure(SecretStatus.Unknown);
        }
        // Updated scope is checked against the explicit authority as well as the original target.
        if (authority is not null && !authority.Matches(Authority, new InfisicalValidationAddress(
            rule.ProjectId, rule.Kind, rule.Id, rule.Environment, rule.SecretPath)))
        {
            return SecretOutcome<InfisicalValidationRule>.Failure(SecretStatus.Unknown);
        }
        receipt?.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalValidationRule>.Success(rule);
    }

    /// <summary>Lists bounded project rules for the selected family, or all admitted families when explicitly requested.</summary>
    /// <remarks>Requires an unselected project-wide address; completeness is response coverage, not a transaction.</remarks>
    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalValidationRule>>> ListValidationRulesAsync(
        SecretReference target, int maximumItems = 1000, bool allKinds = false, CancellationToken cancellationToken = default)
    {
        NativeCount(maximumItems);
        if (target.Address is not InfisicalValidationAddress { RuleId: null, Environment: null, Folder: null } address)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalValidationRule>>.Failure(SecretStatus.Invalid);
        }
        string path = "api/v1/secret-validation-rules" + (allKinds ? "" : "/" + ValidationKindWire(address.Kind)) +
            "?projectId=" + Uri.EscapeDataString(address.ProjectId);
        SecretOutcome<JsonDocument> outcome = await NativeDocumentAsync(target, path, HttpMethod.Get, null, null, null, cancellationToken);
        if (!outcome.IsSuccess) { return SecretOutcome<InfisicalNativeList<InfisicalValidationRule>>.Failure(outcome.Status, outcome.RetryAfter); }
        using JsonDocument document = outcome.Value;
        if (!NativeArray(document.RootElement, "secretValidationRules", out JsonElement items))
        {
            return SecretOutcome<InfisicalNativeList<InfisicalValidationRule>>.Failure(SecretStatus.Unknown);
        }
        var rules = new List<InfisicalValidationRule>();
        foreach (JsonElement item in items.EnumerateArray().Take(maximumItems))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ParseValidationRule(item, address.ProjectId, allKinds ? null : address.Kind) is not { } rule)
            {
                return SecretOutcome<InfisicalNativeList<InfisicalValidationRule>>.Failure(SecretStatus.Unknown);
            }
            rules.Add(rule);
        }
        return SecretOutcome<InfisicalNativeList<InfisicalValidationRule>>.Success(new(rules, items.GetArrayLength() <= maximumItems));
    }

    private static InfisicalValidationRule? ParseValidationRule(JsonElement item, string project, InfisicalValidationKind? expected)
    {
        InfisicalValidationKind? kind = NativeString(item, "type") switch
        {
            "static-secrets" => InfisicalValidationKind.StaticSecrets,
            "dynamic-secrets" => InfisicalValidationKind.DynamicSecrets,
            "secret-rotations" => InfisicalValidationKind.SecretRotations,
            _ => null
        };
        if (kind is null || (expected is not null && kind != expected) ||
            !NativeGuid(item, "id", out string id) || NativeString(item, "projectId") != project ||
            NativeString(item, "name") is not { } name || NativeString(item, "secretPath") is not { } path ||
            !NativeDates(item) || !item.TryGetProperty("environment", out JsonElement environment) ||
            (environment.ValueKind != JsonValueKind.Null &&
                (!NativeGuid(environment, "id", out _) || NativeString(environment, "name") is null ||
                    NativeString(environment, "slug") is null)))
        {
            return null;
        }
        try
        {
            InfisicalNativeAddress.NativeFolder(path);
            InfisicalTextConstraints? key = ParseConstraints(item, "keyConstraints");
            InfisicalTextConstraints? value = ParseConstraints(item, "valueConstraints");
            InfisicalTextConstraints? password = ParseConstraints(item, "passwordConstraints");
            IReadOnlyList<InfisicalValidationProvider>? providers = null;
            if (kind != InfisicalValidationKind.StaticSecrets)
            {
                if (password is null || !NativeArray(item, "providers", out JsonElement array) ||
                    array.GetArrayLength() is < 1 or > 8) { return null; }
                var parsed = new List<InfisicalValidationProvider>();
                foreach (JsonElement provider in array.EnumerateArray())
                {
                    InfisicalValidationProvider? found = provider.ValueKind == JsonValueKind.String
                        ? Enum.GetValues<InfisicalValidationProvider>().Cast<InfisicalValidationProvider?>()
                            .FirstOrDefault(candidate => ValidationProviderWire(candidate!.Value) == provider.GetString())
                        : null;
                    if (found is null || !ValidationProviderValid(kind.Value, found.Value)) { return null; }
                    parsed.Add(found.Value);
                }
                providers = Array.AsReadOnly(parsed.ToArray());
            }
            var input = new InfisicalValidationInput(keyConstraints: key, valueConstraints: value,
                passwordConstraints: password, providers: providers);
            if (!ValidationInputValid(input, kind.Value, true)) { return null; }
            bool? active = NativeNullableBoolean(item, "isActive");
            return new(id, project, kind.Value, name, NativeString(item, "description"),
                NativeString(environment, "slug"), path, active, key, value, password, providers);
        }
        catch (ArgumentException) { return null; }
        catch (InvalidOperationException) { return null; }
    }

    private static InfisicalTextConstraints? ParseConstraints(JsonElement item, string property)
    {
        if (!item.TryGetProperty(property, out JsonElement value)) { return null; }
        if (value.ValueKind != JsonValueKind.Object) { throw new InvalidOperationException("Invalid constraint response."); }
        return new(NativeNullableInteger(value, "minLength"), NativeNullableInteger(value, "maxLength"),
            NativeOptionalString(value, "regexPattern"), NativeOptionalString(value, "requiredPrefix"),
            NativeOptionalString(value, "requiredSuffix"), NativeNullableInteger(value, "uniqueAcrossLastVersions"),
            NativeNullableBoolean(value, "uniqueWithinScope"));
    }

    private static string? NativeOptionalString(JsonElement item, string property)
    {
        if (!item.TryGetProperty(property, out JsonElement value) || value.ValueKind == JsonValueKind.Null) { return null; }
        return value.ValueKind == JsonValueKind.String ? value.GetString() :
            throw new InvalidOperationException("Invalid protected response field.");
    }
    private static int? NativeNullableInteger(JsonElement item, string property)
    {
        if (!item.TryGetProperty(property, out JsonElement value) || value.ValueKind == JsonValueKind.Null) { return null; }
        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number) ? number :
            throw new InvalidOperationException("Invalid numeric response field.");
    }
    private static bool? NativeNullableBoolean(JsonElement item, string property)
    {
        if (!item.TryGetProperty(property, out JsonElement value) || value.ValueKind == JsonValueKind.Null) { return null; }
        return value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() :
            throw new InvalidOperationException("Invalid boolean response field.");
    }
    private static string ValidationKindWire(InfisicalValidationKind kind) => kind switch
    {
        InfisicalValidationKind.StaticSecrets => "static-secrets",
        InfisicalValidationKind.DynamicSecrets => "dynamic-secrets",
        InfisicalValidationKind.SecretRotations => "secret-rotations",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
    private static string ValidationProviderWire(InfisicalValidationProvider provider) => provider switch
    {
        InfisicalValidationProvider.SqlDatabase => "sql-database",
        InfisicalValidationProvider.Milvus => "milvus",
        InfisicalValidationProvider.PostgresCredentials => "postgres-credentials",
        InfisicalValidationProvider.MysqlCredentials => "mysql-credentials",
        InfisicalValidationProvider.MssqlCredentials => "mssql-credentials",
        InfisicalValidationProvider.OracleCredentials => "oracledb-credentials",
        InfisicalValidationProvider.UnixLinuxLocalAccount => "unix-linux-local-account",
        InfisicalValidationProvider.LdapPassword => "ldap-password",
        _ => throw new ArgumentOutOfRangeException(nameof(provider))
    };
    private static bool ValidationProviderValid(InfisicalValidationKind kind, InfisicalValidationProvider provider) =>
        kind == InfisicalValidationKind.DynamicSecrets
            ? provider is InfisicalValidationProvider.SqlDatabase or InfisicalValidationProvider.Milvus
            : kind == InfisicalValidationKind.SecretRotations && provider is not (InfisicalValidationProvider.SqlDatabase or InfisicalValidationProvider.Milvus);
}
