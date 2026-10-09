using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical;

public sealed class NativeDynamicMetadata
{
    public NativeDynamicMetadata(string key, string? value = null)
    {
        if (string.IsNullOrEmpty(key) || key.Length > 255 || value?.Length > 1020)
        {
            throw new ArgumentException("Invalid protected metadata field.");
        }
        Key = key;
        Value = value;
    }
    [JsonIgnore] public string Key { get; }
    [JsonIgnore] public string? Value { get; }
    public override string ToString() => "[NativeDynamicMetadata]";
}

/// <summary>Explicit native definition fields. No implicit provider policy or arbitrary data map.</summary>
public sealed class NativeDynamicDefinitionOptions
{
    private readonly NativeDynamicMetadata[]? _metadata;
    public NativeDynamicDefinitionOptions(string? usernameTemplate = null, IReadOnlyList<NativeDynamicMetadata>? metadata = null)
    {
        if (usernameTemplate?.Length > 255 || metadata?.Count > 128 || metadata?.Any(value => value is null) == true)
        {
            throw new ArgumentException("Invalid protected definition options.");
        }
        UsernameTemplate = usernameTemplate;
        _metadata = metadata?.ToArray();
    }
    [JsonIgnore] public string? UsernameTemplate { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        if (UsernameTemplate is not null)
        {
            writer.WriteString("usernameTemplate", UsernameTemplate);
        }
        if (_metadata is null)
        {
            return;
        }
        writer.WriteStartArray("metadata");
        foreach (NativeDynamicMetadata item in _metadata)
        {
            writer.WriteStartObject();
            writer.WriteString("key", item.Key);
            if (item.Value is not null)
            {
                writer.WriteString("value", item.Value);
            }
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }
    public override string ToString() => "[NativeDynamicDefinitionOptions]";
}

/// <summary>Omitted versus explicitly cleared native policy fields are different.</summary>
public sealed class NativeDynamicDefinitionPatch
{
    public NativeDynamicDefinitionPatch(InfisicalLeaseDuration? defaultTtl = null,
        InfisicalLeaseDuration? maximumTtl = null, bool clearMaximumTtl = false,
        InfisicalDynamicProfile? inputs = null, string? newName = null,
        NativeDynamicDefinitionOptions? options = null, bool clearUsernameTemplate = false)
    {
        if (clearMaximumTtl && maximumTtl is not null ||
            clearUsernameTemplate && options?.UsernameTemplate is not null ||
            (defaultTtl is not null && maximumTtl?.Duration < defaultTtl.Duration))
        {
            throw new ArgumentException("Contradictory native definition patch.");
        }
        if (newName is not null)
        {
            InfisicalNativeAddress.NativeText(newName, 64);
        }
        DefaultTtl = defaultTtl;
        MaximumTtl = maximumTtl;
        ClearMaximumTtl = clearMaximumTtl;
        Inputs = inputs;
        NewName = newName;
        Options = options;
        ClearUsernameTemplate = clearUsernameTemplate;
    }
    public InfisicalLeaseDuration? DefaultTtl { get; }
    public InfisicalLeaseDuration? MaximumTtl { get; }
    public bool ClearMaximumTtl { get; }
    public bool ClearUsernameTemplate { get; }
    [JsonIgnore] public InfisicalDynamicProfile? Inputs { get; }
    [JsonIgnore] public string? NewName { get; }
    [JsonIgnore] public NativeDynamicDefinitionOptions? Options { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        if (DefaultTtl is not null) { writer.WriteString("defaultTTL", DefaultTtl.Wire); }
        if (MaximumTtl is not null) { writer.WriteString("maxTTL", MaximumTtl.Wire); }
        else if (ClearMaximumTtl) { writer.WriteNull("maxTTL"); }
        if (Inputs is not null)
        {
            writer.WriteStartObject("inputs");
            Inputs.WriteInputs(writer);
            writer.WriteEndObject();
        }
        if (NewName is not null) { writer.WriteString("newName", NewName); }
        Options?.Write(writer);
        if (ClearUsernameTemplate) { writer.WriteNull("usernameTemplate"); }
    }
    public override string ToString() => "[NativeDynamicDefinitionPatch]";
}
