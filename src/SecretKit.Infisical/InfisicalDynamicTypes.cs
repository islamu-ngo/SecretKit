using System.Globalization;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Exact host-selected coordinates. Folder identity is required to validate returned resources.</summary>
public sealed class InfisicalDynamicScope
{
    /// <summary>Selects protected project/environment slugs, an absolute path and a nonempty expected folder UUID.</summary>
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

    /// <summary>The protected project slug.</summary>
    [JsonIgnore] public string ProjectSlug { get; }
    /// <summary>The protected environment slug.</summary>
    [JsonIgnore] public string EnvironmentSlug { get; }
    /// <summary>The absolute native folder path without traversal segments.</summary>
    [JsonIgnore] public string Path { get; }
    /// <summary>The expected folder identity used to validate returned definitions.</summary>
    [JsonIgnore] public Guid FolderId { get; }
    /// <summary>Returns a fixed label without scope coordinates.</summary>
    public override string ToString() => "[InfisicalDynamicScope]";
}

/// <summary>A bounded native duration. No application readiness or clock convergence meaning.</summary>
public sealed class InfisicalLeaseDuration
{
    /// <summary>Validates a positive whole-second duration no longer than 365 days.</summary>
    public InfisicalLeaseDuration(TimeSpan duration)
    {
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromDays(365) ||
            duration.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new ArgumentException("A whole-second duration within the local one-year budget is required.");
        }
        Duration = duration;
    }

    /// <summary>The admitted native duration; not proof of provider acceptance or application readiness.</summary>
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
    /// <summary>Returns a fixed label rather than wire data.</summary>
    public override string ToString() => "[InfisicalLeaseDuration]";
}

/// <summary>Closed native dynamic provider routing; metadata support does not establish credential acquisition support.</summary>
public enum InfisicalDynamicProvider
{
    /** <summary>SQL database profile.</summary> */
    SqlDatabase, /** <summary>ClickHouse profile.</summary> */ Clickhouse, /** <summary>Cassandra profile.</summary> */ Cassandra, /** <summary>SAP ASE profile.</summary> */ SapAse, /** <summary>AWS IAM profile.</summary> */ AwsIam, /** <summary>Redis profile.</summary> */ Redis, /** <summary>SAP HANA profile.</summary> */ SapHana, /** <summary>AWS ElastiCache profile.</summary> */ AwsElasticache,
    /** <summary>AWS MemoryDB profile.</summary> */
    AwsMemorydb, /** <summary>MongoDB Atlas profile.</summary> */ MongoDbAtlas, /** <summary>Elasticsearch profile.</summary> */ ElasticSearch, /** <summary>MongoDB profile.</summary> */ MongoDb, /** <summary>RabbitMQ profile.</summary> */ RabbitMq, /** <summary>Azure Entra ID profile.</summary> */ AzureEntraId,
    /** <summary>Azure SQL Database profile.</summary> */
    AzureSqlDatabase, /** <summary>LDAP profile.</summary> */ Ldap, /** <summary>Snowflake profile.</summary> */ Snowflake, /** <summary>TOTP profile.</summary> */ Totp, /** <summary>Kubernetes profile.</summary> */ Kubernetes, /** <summary>Vertica profile.</summary> */ Vertica, /** <summary>GCP IAM profile.</summary> */ GcpIam, /** <summary>GitHub profile.</summary> */ Github,
    /** <summary>Couchbase profile.</summary> */
    Couchbase, /** <summary>Milvus profile.</summary> */ Milvus, /** <summary>SSH profile.</summary> */ Ssh, /** <summary>IBM API Connect profile.</summary> */ IbmApiConnect, /** <summary>Tailscale profile.</summary> */ Tailscale, /** <summary>OAuth2 profile.</summary> */ Oauth2
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
    /// <summary>The protected definition name bound to its creating client.</summary>
    [JsonIgnore] public string Name { get; }
    /// <summary>Returns a fixed label without the definition name.</summary>
    public override string ToString() => "[InfisicalDynamicTarget]";
}

/// <summary>Validated native definition metadata; inspection does not mint credentials or a lease.</summary>
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
    /// <summary>The client-bound target validated for this definition.</summary>
    [JsonIgnore] public InfisicalDynamicTarget Target { get; }
    /// <summary>The observed native definition UUID.</summary>
    [JsonIgnore] public Guid Id { get; }
    /// <summary>The admitted native provider discriminator.</summary>
    public InfisicalDynamicProvider Provider { get; }
    /// <summary>The observed default issuance duration.</summary>
    public InfisicalLeaseDuration DefaultTtl { get; }
    /// <summary>The observed maximum duration, or null when no maximum was returned.</summary>
    public InfisicalLeaseDuration? MaximumTtl { get; }
    /// <summary>The native definition version; not a local compare-and-swap guarantee.</summary>
    public decimal Version { get; }
    /// <summary>Protected open provider status text, not a readiness assertion.</summary>
    [JsonIgnore] public string? Status { get; }
    /// <summary>Returns a fixed label without identifiers or provider text.</summary>
    public override string ToString() => "[InfisicalDynamicDefinition]";
}

/// <summary>Exact operation selection bound into native dispatch evidence.</summary>
public enum InfisicalDynamicOperation
{
    /** <summary>Create a definition.</summary> */
    CreateDefinition, /** <summary>Update a definition.</summary> */ UpdateDefinition, /** <summary>Delete a definition.</summary> */ DeleteDefinition, /** <summary>Issue credentials.</summary> */ Acquire, /** <summary>Renew a selected lease.</summary> */ Renew, /** <summary>Revoke a selected lease.</summary> */ Revoke
}

/// <summary>Local pre-dispatch evidence tied to an exact native operation and target, not idempotency.</summary>
public sealed class InfisicalDynamicMutationReceipt
{
    private readonly object _gate = new();
    private readonly InfisicalDynamicTarget? _definition;
    private readonly InfisicalLeaseReference? _lease;
    private DispatchEvidence _evidence;

    /// <summary>Binds definition create/update/delete or acquisition evidence to the exact target object.</summary>
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

    /// <summary>Binds renewal or revocation evidence to the exact retained lease reference.</summary>
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
    /// <summary>The operation this receipt permits locally; server authority remains independently required.</summary>
    public InfisicalDynamicOperation Operation { get; }
    /// <summary>Latest dispatch evidence, preserved across cancellation and uncertain responses.</summary>
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
    /// <summary>Returns evidence without target coordinates.</summary>
    public override string ToString() => $"[InfisicalDynamicMutationReceipt:{Evidence}]";
}
