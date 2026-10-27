using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical;

/// <summary>Bounded protected native metadata, excluded from default JSON and formatting.</summary>
public sealed class NativeDynamicMetadata
{
    /// <summary>Selects a nonempty metadata key and optional value without provider I/O.</summary>
    public NativeDynamicMetadata(string key, string? value = null)
    {
        if (string.IsNullOrEmpty(key) || key.Length > 255 || value?.Length > 1020)
        {
            throw new ArgumentException("Invalid protected metadata field.");
        }
        Key = key;
        Value = value;
    }
    /// <summary>The protected metadata key.</summary>
    [JsonIgnore] public string Key { get; }
    /// <summary>The optional protected metadata value.</summary>
    [JsonIgnore] public string? Value { get; }
    /// <summary>Returns a fixed label without metadata text.</summary>
    public override string ToString() => "[NativeDynamicMetadata]";
}

/// <summary>Explicit native definition fields. No implicit provider policy or arbitrary data map.</summary>
public sealed class NativeDynamicDefinitionOptions
{
    private readonly NativeDynamicMetadata[]? _metadata;
    /// <summary>Freezes optional username-template and metadata inputs; omission does not select provider policy.</summary>
    public NativeDynamicDefinitionOptions(string? usernameTemplate = null, IReadOnlyList<NativeDynamicMetadata>? metadata = null)
    {
        if (usernameTemplate?.Length > 255 || metadata?.Count > 128 || metadata?.Any(value => value is null) == true)
        {
            throw new ArgumentException("Invalid protected definition options.");
        }
        UsernameTemplate = usernameTemplate;
        _metadata = metadata?.ToArray();
    }
    /// <summary>The optional protected native username template, not evaluated locally.</summary>
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
    /// <summary>Returns a fixed label without template or metadata.</summary>
    public override string ToString() => "[NativeDynamicDefinitionOptions]";
}

/// <summary>Omitted versus explicitly cleared native policy fields are different.</summary>
public sealed class NativeDynamicDefinitionPatch
{
    /// <summary>Selects explicit native changes while rejecting conflicting values and clear flags.</summary>
    /// <remarks>Inputs remain caller-owned and must stay usable until the operation serializes them before awaiting.</remarks>
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
    /// <summary>The new default duration, or null to omit it.</summary>
    public InfisicalLeaseDuration? DefaultTtl { get; }
    /// <summary>The new maximum duration, or null for omission unless explicitly cleared.</summary>
    public InfisicalLeaseDuration? MaximumTtl { get; }
    /// <summary>Explicitly sends a null maximum duration.</summary>
    public bool ClearMaximumTtl { get; }
    /// <summary>Explicitly clears the username template.</summary>
    public bool ClearUsernameTemplate { get; }
    /// <summary>Borrowed typed inputs; the operation requires the existing provider family.</summary>
    [JsonIgnore] public InfisicalDynamicProfile? Inputs { get; }
    /// <summary>The optional new protected definition name.</summary>
    [JsonIgnore] public string? NewName { get; }
    /// <summary>Optional typed definition fields; omitted fields remain unchanged.</summary>
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
    /// <summary>Returns a fixed label without native patch contents.</summary>
    public override string ToString() => "[NativeDynamicDefinitionPatch]";
}
