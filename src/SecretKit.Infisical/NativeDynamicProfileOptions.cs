using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical;

// Only fixed, handwritten option constructors supply these field names.
internal sealed class NativeProfileOptionData : IDisposable
{
    internal readonly Dictionary<string, SecretMaterial?> Text = new(StringComparer.Ordinal);
    internal readonly Dictionary<string, bool> Flags = new(StringComparer.Ordinal);
    internal readonly Dictionary<string, SecretMaterial[]> Strings = new(StringComparer.Ordinal);
    internal readonly Dictionary<string, NativeProfileOptionData[]> Objects = new(StringComparer.Ordinal);

    internal NativeProfileOptionData Copy()
    {
        var copy = new NativeProfileOptionData();
        foreach (var (key, value) in Text) copy.Text.Add(key, value?.Copy());
        foreach (var (key, value) in Flags) copy.Flags.Add(key, value);
        foreach (var (key, values) in Strings)
            copy.Strings.Add(key, values.Select(value => value.Copy()).ToArray());
        foreach (var (key, values) in Objects) copy.Objects.Add(key, values.Select(value => value.Copy()).ToArray());
        return copy;
    }

    internal void Write(Utf8JsonWriter writer)
    {
        foreach (var (key, value) in Text)
            if (value is null) writer.WriteNull(key); else writer.WriteString(key, value.Reveal());
        foreach (var (key, value) in Flags) writer.WriteBoolean(key, value);
        foreach (var (key, values) in Strings)
        {
            writer.WriteStartArray(key);
            foreach (var value in values) writer.WriteStringValue(value.Reveal());
            writer.WriteEndArray();
        }
        foreach (var (key, values) in Objects)
        {
            writer.WriteStartArray(key);
            foreach (var value in values)
            {
                writer.WriteStartObject(); value.Write(writer); writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }
    }

    public void Dispose()
    {
        foreach (var value in Text.Values) value?.Dispose();
        foreach (var values in Strings.Values) foreach (var value in values) value.Dispose();
        foreach (var values in Objects.Values) foreach (var value in values) value.Dispose();
    }
}

/// <summary>Protected, independently copied native inputs. Disposal never contacts a provider.</summary>
public abstract class NativeProfileOptions : IDisposable
{
    private readonly object _gate = new();
    private readonly NativeProfileOptionData _data = new();
    private bool _disposed;
    private protected NativeProfileOptions() { }

    private protected void Text(string field, string? value, int maximum = 65536, bool required = false)
    {
        if (value is null && !required) return;
        if (value is null || value.Length > maximum || required && value.Length == 0)
        {
            Dispose(); throw new ArgumentException("Invalid protected native option.");
        }
        _data.Text.Add(field, SecretMaterial.FromText(value));
    }
    private protected void Null(string field) => _data.Text.Add(field, null);
    private protected void Flag(string field, bool? value)
    {
        if (value is { } flag) _data.Flags.Add(field, flag);
    }
    private protected void Strings(string field, IReadOnlyList<string>? values)
    {
        if (values is null) return;
        if (values.Count > 128 || values.Any(value => value is null || value.Length is < 1 or > 4096))
        {
            Dispose(); throw new ArgumentException("Invalid protected native array.");
        }
        _data.Strings.Add(field, values.Select(value => SecretMaterial.FromText(value)).ToArray());
    }
    private protected void Objects<T>(string field, IReadOnlyList<T>? values, int maximum = 128)
        where T : NativeProfileOptions
    {
        if (values is null) return;
        if (values.Count > maximum || values.Any(value => value is null))
        {
            Dispose(); throw new ArgumentException("Invalid protected native object array.");
        }
        var copies = new List<NativeProfileOptionData>();
        try
        {
            foreach (var value in values) copies.Add(value.Copy());
            _data.Objects.Add(field, copies.ToArray());
        }
        catch
        {
            foreach (var copy in copies) copy.Dispose();
            Dispose(); throw;
        }
    }
    internal NativeProfileOptionData Copy()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _data.Copy();
        }
    }
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true; _data.Dispose();
        }
    }
    public sealed override string ToString() => "[NativeProfileOptions]";
}

public sealed class NativeGatewayOptions : NativeProfileOptions
{
    public NativeGatewayOptions(string? gatewayId = null, string? gatewayPoolId = null,
        bool clearGatewayId = false, bool clearGatewayPoolId = false)
    {
        if (clearGatewayId && gatewayId is not null || clearGatewayPoolId && gatewayPoolId is not null)
            throw new ArgumentException("Contradictory native gateway selection.");
        Text("gatewayId", gatewayId); Text("gatewayPoolId", gatewayPoolId);
        if (clearGatewayId) Null("gatewayId");
        if (clearGatewayPoolId) Null("gatewayPoolId");
    }
}

public sealed class NativeAwsTag : NativeProfileOptions
{
    public NativeAwsTag(string key, string? value = null)
    {
        Text("key", key, 255, true); Text("value", value, 1020);
    }
}

public sealed class NativeAwsIamOptions : NativeProfileOptions
{
    internal bool HasSessionPolicy { get; }
    public NativeAwsIamOptions(string? awsPath = null, string? permissionBoundaryPolicyArn = null,
        string? policyArns = null, string? policyDocument = null, string? userGroups = null,
        IReadOnlyList<NativeAwsTag>? tags = null, string? sessionPolicyArns = null,
        string? sessionPolicyDocument = null)
    {
        HasSessionPolicy = sessionPolicyArns is not null || sessionPolicyDocument is not null;
        Text("awsPath", awsPath); Text("permissionBoundaryPolicyArn", permissionBoundaryPolicyArn);
        Text("policyArns", policyArns); Text("policyDocument", policyDocument); Text("userGroups", userGroups);
        Text("sessionPolicyArns", sessionPolicyArns); Text("sessionPolicyDocument", sessionPolicyDocument);
        Objects("tags", tags);
    }
}

public sealed class NativeMilvusPrivilege : NativeProfileOptions
{
    public NativeMilvusPrivilege(string objectType, string privilege, string? objectName = null, string? dbName = null)
    {
        Text("objectType", objectType, required: true); Text("privilege", privilege, required: true);
        if (objectName is not null) Text("objectName", objectName, required: true);
        if (dbName is not null) Text("dbName", dbName, required: true);
    }
}

public sealed class NativeCouchbaseScope : NativeProfileOptions
{
    public NativeCouchbaseScope(string name, IReadOnlyList<string>? collections = null)
    {
        Text("name", name, required: true); Strings("collections", collections);
    }
}

public sealed class NativeCouchbaseBucket : NativeProfileOptions
{
    public NativeCouchbaseBucket(string name, IReadOnlyList<NativeCouchbaseScope>? scopes = null)
    {
        Text("name", name, required: true); Objects("scopes", scopes);
    }
}

public sealed class NativeCouchbaseBuckets : NativeProfileOptions
{
    private NativeCouchbaseBuckets(string value) => Text("buckets", value, required: true);
    private NativeCouchbaseBuckets(IReadOnlyList<NativeCouchbaseBucket> values)
    {
        ArgumentNullException.ThrowIfNull(values); Objects("buckets", values);
    }
    public static NativeCouchbaseBuckets FromText(string value) => new(value);
    public static NativeCouchbaseBuckets FromBuckets(IReadOnlyList<NativeCouchbaseBucket> values) => new(values);
}

public sealed class NativeOauthExtraParameter : NativeProfileOptions
{
    public NativeOauthExtraParameter(string key, string value)
    {
        Text("key", key, 128, true); Text("value", value, 2048, true);
    }
}

public sealed class NativeTailscaleOptions : NativeProfileOptions
{
    internal bool HasAuthKeyFlags { get; }
    internal bool HasAudience { get; }
    public NativeTailscaleOptions(string? tailnet = null, IReadOnlyList<string>? tags = null,
        string? description = null, string? audience = null, bool? reusable = null, bool? preauthorized = null)
    {
        HasAuthKeyFlags = reusable is not null || preauthorized is not null;
        HasAudience = audience is not null;
        if (tailnet is not null) Text("tailnet", tailnet, required: true);
        Text("description", description, 50); Text("audience", audience); Strings("tags", tags);
        Flag("reusable", reusable); Flag("preauthorized", preauthorized);
    }
}

public enum NativeSshKeyAlgorithm { Rsa2048, Rsa4096, EcPrime256v1, EcSecp384r1, Ed25519 }
public enum NativeKubernetesAuthentication { Api, Gateway }
