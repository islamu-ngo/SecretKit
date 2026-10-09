using System.Globalization;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Exact host-selected coordinates. Folder identity is required to validate returned resources.</summary>
public sealed class InfisicalDynamicScope
{
    public InfisicalDynamicScope(string projectSlug, string environmentSlug, string path, Guid folderId)
    {
        InfisicalNativeAddress.NativeText(projectSlug);
        InfisicalNativeAddress.NativeText(environmentSlug);
        InfisicalNativeAddress.NativeFolder(path);
        if (folderId == Guid.Empty)
        {
            throw new ArgumentException("A native folder identity is required.");
        }
        ProjectSlug = projectSlug;
        EnvironmentSlug = environmentSlug;
        Path = path;
        FolderId = folderId;
    }

    [JsonIgnore] public string ProjectSlug { get; }
    [JsonIgnore] public string EnvironmentSlug { get; }
    [JsonIgnore] public string Path { get; }
    [JsonIgnore] public Guid FolderId { get; }
    public override string ToString() => "[InfisicalDynamicScope]";
}

/// <summary>A bounded native duration. No application readiness or clock convergence meaning.</summary>
public sealed class InfisicalLeaseDuration
{
    public InfisicalLeaseDuration(TimeSpan duration)
    {
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromDays(365) ||
            duration.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new ArgumentException("A whole-second duration within the local one-year budget is required.");
        }
        Duration = duration;
    }

    public TimeSpan Duration { get; }
    internal string Wire => ((long)Duration.TotalSeconds).ToString(CultureInfo.InvariantCulture) + "s";
    internal static InfisicalLeaseDuration? Parse(string? wire)
    {
        if (wire is null || wire.Length is < 2 or > 32 ||
            !long.TryParse(wire.AsSpan(0, wire.Length - 1), NumberStyles.None,
                CultureInfo.InvariantCulture, out long amount) || amount <= 0)
        {
            return null;
        }
        long seconds = wire[^1] switch { 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400, _ => 0 };
        if (seconds == 0 || amount > 31536000 / seconds)
        {
            return null;
        }
        return new InfisicalLeaseDuration(TimeSpan.FromSeconds(amount * seconds));
    }
    public override string ToString() => "[InfisicalLeaseDuration]";
}

public enum InfisicalDynamicProvider
{
    SqlDatabase, Clickhouse, Cassandra, SapAse, AwsIam, Redis, SapHana, AwsElasticache,
    AwsMemorydb, MongoDbAtlas, ElasticSearch, MongoDb, RabbitMq, AzureEntraId,
    AzureSqlDatabase, Ldap, Snowflake, Totp, Kubernetes, Vertica, GcpIam, Github,
    Couchbase, Milvus, Ssh, IbmApiConnect, Tailscale, Oauth2
}

/// <summary>Bound to exactly one client and one name. Inspection never mints a lease.</summary>
public sealed class InfisicalDynamicTarget
{
    internal InfisicalDynamicTarget(InfisicalDynamicClient owner, string name)
    {
        InfisicalNativeAddress.NativeText(name, 64);
        Owner = owner;
        Name = name;
    }
    internal InfisicalDynamicClient Owner { get; }
    [JsonIgnore] public string Name { get; }
    public override string ToString() => "[InfisicalDynamicTarget]";
}

public sealed class InfisicalDynamicDefinition
{
    internal InfisicalDynamicDefinition(InfisicalDynamicTarget target, Guid id,
        InfisicalDynamicProvider provider, InfisicalLeaseDuration defaultTtl,
        InfisicalLeaseDuration? maximumTtl, decimal version, string? status)
    {
        Target = target;
        Id = id;
        Provider = provider;
        DefaultTtl = defaultTtl;
        MaximumTtl = maximumTtl;
        Version = version;
        Status = status;
    }
    [JsonIgnore] public InfisicalDynamicTarget Target { get; }
    [JsonIgnore] public Guid Id { get; }
    public InfisicalDynamicProvider Provider { get; }
    public InfisicalLeaseDuration DefaultTtl { get; }
    public InfisicalLeaseDuration? MaximumTtl { get; }
    public decimal Version { get; }
    [JsonIgnore] public string? Status { get; }
    public override string ToString() => "[InfisicalDynamicDefinition]";
}

public enum InfisicalDynamicOperation
{
    CreateDefinition, UpdateDefinition, DeleteDefinition, Acquire, Renew, Revoke
}

/// <summary>Local pre-dispatch evidence tied to an exact native operation and target, not idempotency.</summary>
public sealed class InfisicalDynamicMutationReceipt
{
    private readonly object _gate = new();
    private readonly InfisicalDynamicTarget? _definition;
    private readonly InfisicalLeaseReference? _lease;
    private DispatchEvidence _evidence;

    public InfisicalDynamicMutationReceipt(InfisicalDynamicTarget target, InfisicalDynamicOperation operation)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (operation is not (InfisicalDynamicOperation.CreateDefinition or
            InfisicalDynamicOperation.UpdateDefinition or InfisicalDynamicOperation.DeleteDefinition or
            InfisicalDynamicOperation.Acquire))
        {
            throw new ArgumentException("The operation requires a lease target.");
        }
        _definition = target;
        Operation = operation;
    }

    public InfisicalDynamicMutationReceipt(InfisicalLeaseReference target, InfisicalDynamicOperation operation)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (operation is not (InfisicalDynamicOperation.Renew or InfisicalDynamicOperation.Revoke))
        {
            throw new ArgumentException("The operation requires a definition target.");
        }
        _lease = target;
        Operation = operation;
    }
    public InfisicalDynamicOperation Operation { get; }
    public DispatchEvidence Evidence { get { lock (_gate) { return _evidence; } } }
    internal bool Matches(InfisicalDynamicTarget? definition, InfisicalLeaseReference? lease,
        InfisicalDynamicOperation operation) =>
        ReferenceEquals(_definition, definition) && ReferenceEquals(_lease, lease) &&
        Operation == operation && Evidence == DispatchEvidence.NotDispatched;
    internal bool Begin()
    {
        lock (_gate)
        {
            if (_evidence != DispatchEvidence.NotDispatched)
            {
                return false;
            }
            _evidence = DispatchEvidence.PossiblyDispatched;
            return true;
        }
    }
    internal void Record(DispatchEvidence evidence)
    {
        lock (_gate)
        {
            if (_evidence != DispatchEvidence.PossiblyDispatched)
            {
                throw new InvalidOperationException("No dispatched native effect can be recorded.");
            }
            _evidence = evidence;
        }
    }
    public override string ToString() => $"[InfisicalDynamicMutationReceipt:{Evidence}]";
}
