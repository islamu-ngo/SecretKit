using System.Net;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical;

/// <summary>Standard TLS/trust-store networking; no certificate-validation bypass.</summary>
public sealed class InfisicalNetworkOptions
{
    public bool AllowLoopbackDevelopmentHttp { get; init; }

    public int MaximumResponseBytes { get; init; } = 1024 * 1024;

    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(10);

    [JsonIgnore]
    public IWebProxy? Proxy { get; init; }

    public override string ToString() => "[InfisicalNetworkOptions]";
}
