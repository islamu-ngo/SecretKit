using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

public enum InfisicalValidationKind { StaticSecrets, DynamicSecrets, SecretRotations }
public enum InfisicalValidationProvider
{
    SqlDatabase, Milvus, PostgresCredentials, MysqlCredentials, MssqlCredentials,
    OracleCredentials, UnixLinuxLocalAccount, LdapPassword
}

public sealed class InfisicalValidationAddress : InfisicalNativeAddress
{
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
    public InfisicalValidationKind Kind { get; }
    [JsonIgnore]
    public string? RuleId { get; }
}

/// <summary>Wire constraints only. SecretKit does not execute provider regexes or enforce server policy locally.</summary>
public sealed class InfisicalTextConstraints
{
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
    [JsonIgnore]
    public int? MinimumLength { get; }
    [JsonIgnore]
    public int? MaximumLength { get; }
    [JsonIgnore]
    public string? RegexPattern { get; }
    [JsonIgnore]
    public string? RequiredPrefix { get; }
    [JsonIgnore]
    public string? RequiredSuffix { get; }
    [JsonIgnore]
    public int? UniqueAcrossLastVersions { get; }
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
    public override string ToString() => "[InfisicalTextConstraints]";
}

/// <summary>Absent fields stay unchanged. Explicit clear flags send null only where the contract accepts it.</summary>
public sealed class InfisicalValidationInput
{
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
    [JsonIgnore]
    public string? Name { get; }
    [JsonIgnore]
    public string? Description { get; }
    public bool? IsActive { get; }
    [JsonIgnore]
    public InfisicalTextConstraints? KeyConstraints { get; }
    [JsonIgnore]
    public InfisicalTextConstraints? ValueConstraints { get; }
    [JsonIgnore]
    public InfisicalTextConstraints? PasswordConstraints { get; }
    [JsonIgnore]
    public IReadOnlyList<InfisicalValidationProvider>? Providers { get; }
    [JsonIgnore]
    public string? Environment { get; }
    [JsonIgnore]
    public string? SecretPath { get; }
    [JsonIgnore]
    public bool ClearDescription { get; }
    [JsonIgnore]
    public bool ClearEnvironment { get; }
    [JsonIgnore]
    public bool ClearKeyConstraints { get; }
    [JsonIgnore]
    public bool ClearValueConstraints { get; }
    public override string ToString() => "[InfisicalValidationInput]";
}

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
    [JsonIgnore]
    public string Id { get; }
    [JsonIgnore]
    public string ProjectId { get; }
    public InfisicalValidationKind Kind { get; }
    [JsonIgnore]
    public string Name { get; }
    [JsonIgnore]
    public string? Description { get; }
    [JsonIgnore]
    public string? Environment { get; }
    [JsonIgnore]
    public string SecretPath { get; }
    public bool? IsActive { get; }
    [JsonIgnore]
    public InfisicalTextConstraints? KeyConstraints { get; }
    [JsonIgnore]
    public InfisicalTextConstraints? ValueConstraints { get; }
    [JsonIgnore]
    public InfisicalTextConstraints? PasswordConstraints { get; }
    [JsonIgnore]
    public IReadOnlyList<InfisicalValidationProvider>? Providers { get; }
    public override string ToString() => "[InfisicalValidationRule]";
}

public sealed partial class InfisicalClient
{
    public ValueTask<SecretOutcome<InfisicalValidationRule>> GetValidationRuleAsync(SecretReference target,
        CancellationToken cancellationToken = default) =>
        ValidationOperationAsync(target, HttpMethod.Get, null, null, null, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalValidationRule>> CreateValidationRuleAsync(SecretReference target,
        InfisicalValidationInput input, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default) =>
        ChangeValidationRuleAsync(target, input, authority, receipt, false, cancellationToken);

    public ValueTask<SecretOutcome<InfisicalValidationRule>> UpdateValidationRuleAsync(SecretReference target,
        InfisicalValidationInput input, InfisicalNativeAuthority authority, MutationReceipt receipt,
        CancellationToken cancellationToken = default) =>
        ChangeValidationRuleAsync(target, input, authority, receipt, true, cancellationToken);

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
