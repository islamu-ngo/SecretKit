using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;

namespace SecretKit.Extensions.Configuration;

/// <summary>Explicit mapping from a protected consumer key to an exported configuration key.</summary>
public sealed class SecretConfigurationMapping
{
    public SecretConfigurationMapping(string consumerKey, string configurationKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(consumerKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationKey);
        ConsumerKey = consumerKey;
        ConfigurationKey = configurationKey;
    }

    [JsonIgnore]
    public string ConsumerKey { get; }
    [JsonIgnore]
    public string ConfigurationKey { get; }
    public override string ToString() => "[SecretConfigurationMapping]";
}

/// <summary>
/// Deliberate ordinary-string export. IConfiguration enumeration, debug views, options,
/// logs and escaped strings are host-owned plaintext boundaries. Disposal does not erase
/// strings. Indexer reads across reload are not a coherent multi-key operation.
/// The source can build exactly one provider for one configuration root.
/// </summary>
public sealed class SecretConfigurationExport : IConfigurationSource, IDisposable
{
    private readonly object _gate = new();
    private readonly SecretConfigurationMapping[] _mapping;
    private readonly ExportProvider _provider = new();
    private bool _built;
    private bool _disposed;

    private SecretConfigurationExport(SecretSnapshotHandle generation, SecretConfigurationMapping[] mapping)
    {
        _mapping = mapping;
        _provider.Publish(Prepare(generation));
    }

    /// <summary>Explicitly acknowledges ordinary managed strings outside material-owner protection.</summary>
    public static SecretConfigurationExport CreateAcknowledgingManagedStrings(
        SecretSnapshotHandle generation, IEnumerable<SecretConfigurationMapping> mapping)
    {
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentNullException.ThrowIfNull(mapping);
        SecretConfigurationMapping[] entries = mapping.ToArray();
        if (entries.Length == 0) throw new ArgumentException("At least one explicit mapping is needed.");
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (SecretConfigurationMapping entry in entries)
        {
            ArgumentNullException.ThrowIfNull(entry);
            if (!keys.Add(entry.ConfigurationKey))
                throw new ArgumentException("Configuration key mapping has a case-insensitive collision.");
        }
        return new SecretConfigurationExport(generation, entries);
    }

    /// <summary>
    /// Prepares and commits a complete string dictionary, then signals reload outside state gates.
    /// Preparation failure preserves values and token. Notification failure leaves values committed.
    /// No reader I/O occurs.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Values were committed, but a reload callback failed. Callback details are not retained.
    /// </exception>
    public void ReplaceAcknowledgingManagedStrings(SecretSnapshotHandle generation)
    {
        ArgumentNullException.ThrowIfNull(generation);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _provider.Publish(Prepare(generation));
        }
        try { _provider.SignalReload(); }
        catch (AggregateException)
        {
            throw new InvalidOperationException(
                "Configuration values were committed, but reload notification failed.");
        }
    }

    /// <summary>
    /// Returns the sole provider once. A later sibling-source failure does not reopen this slot.
    /// </summary>
    /// <exception cref="InvalidOperationException">The source has already built its provider.</exception>
    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_built)
                throw new InvalidOperationException("A secret configuration export supports only one build.");
            _built = true;
            return _provider;
        }
    }

    /// <summary>Safe bounded debug summary excluding values and mapped coordinates.</summary>
    public string GetRedactedDebugView() => $"[SecretConfigurationExport:Count={_provider.Count}]";

    private Dictionary<string, string?> Prepare(SecretSnapshotHandle generation)
    {
        var strings = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (SecretConfigurationMapping entry in _mapping)
        {
            using var read = generation.Read(entry.ConsumerKey);
            strings[entry.ConfigurationKey] = read.Material.Reveal();
        }
        return strings;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _provider.Dispose();
        }
    }

    public override string ToString() => "[SecretConfigurationExport]";

    private sealed class ExportProvider : ConfigurationProvider, IDisposable
    {
        private readonly object _gate = new();
        private Dictionary<string, string?> _strings = new(StringComparer.OrdinalIgnoreCase);
        private bool _disposed;
        internal int Count => Volatile.Read(ref _strings).Count;
        // Load deliberately performs no synchronous remote I/O.
        public override void Load() { }
        internal void Publish(Dictionary<string, string?> strings)
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                Volatile.Write(ref _strings, strings);
            }
        }
        internal void SignalReload() => OnReload();
        public override bool TryGet(string key, out string? value) =>
            Volatile.Read(ref _strings).TryGetValue(key, out value);
        public override void Set(string key, string? value) =>
            throw new NotSupportedException("Secret exports are read-only.");
        public override IEnumerable<string> GetChildKeys(IEnumerable<string> earlierKeys, string? parentPath)
        {
            string prefix = parentPath is null ? "" : parentPath + ConfigurationPath.KeyDelimiter;
            return Volatile.Read(ref _strings).Keys
                .Where(key => key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .Select(key => key[prefix.Length..].Split(ConfigurationPath.KeyDelimiter)[0])
                .Concat(earlierKeys).OrderBy(key => key, ConfigurationKeyComparer.Instance).ToArray();
        }
        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed) return;
                _disposed = true;
                Volatile.Write(ref _strings, new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase));
            }
        }
        public override string ToString() => "[SecretConfigurationProvider]";
    }
}
