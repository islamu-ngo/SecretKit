using System.Net;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical;

/// <summary>Frozen per-client networking selection and bounded operation budgets.</summary>
public sealed class InfisicalNetworkOptions
{
    /// <summary>SDK-safe by default; host-controlled pipelines require explicit selection.</summary>
    [JsonIgnore]
    public InfisicalTransportOptions Transport { get; init; } = InfisicalTransportOptions.SafeDefault;

    /// <summary>Explicitly permits loopback HTTP in safe mode for development; host-controlled mode permits HTTP independently.</summary>
    public bool AllowLoopbackDevelopmentHttp { get; init; }

    /// <summary>Maximum accepted response bytes; clients require 1 KiB through 16 MiB.</summary>
    public int MaximumResponseBytes { get; init; } = 1024 * 1024;

    /// <summary>Public shutdown deadline, greater than zero and at most one minute; timeout does not prove cleanup finished.</summary>
    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Explicit safe-mode proxy; null disables ambient proxy use. Cannot accompany host-controlled transport.</summary>
    [JsonIgnore]
    public IWebProxy? Proxy { get; init; }

    /// <summary>Returns a fixed label without proxy or pipeline details.</summary>
    public override string ToString() => "[InfisicalNetworkOptions]";
}
