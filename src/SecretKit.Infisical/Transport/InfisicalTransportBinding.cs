using SecretKit.Internal;

namespace SecretKit.Infisical;

// Provider configuration is projected once; ownership and dispatch-free construction are neutral.
internal sealed class InfisicalTransportBinding(Uri origin, InfisicalNetworkOptions network,
    HttpMessageHandler? testHandler = null, bool ownsTestHandler = true)
    : HttpTransportBinding(origin, Select(network), testHandler, ownsTestHandler)
{
    internal static void ValidateOrigin(Uri origin, InfisicalNetworkOptions network) =>
        HttpTransportBinding.ValidateOrigin(origin, Select(network));

    private static HttpTransportSettings Select(InfisicalNetworkOptions network)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(network.Transport);
        return new(network.Transport.Client, network.Transport.Handler, network.Transport.CopyRoots,
            network.Proxy, network.AllowLoopbackDevelopmentHttp, network.MaximumRequestBytes, network.OperationTimeout);
    }
}
