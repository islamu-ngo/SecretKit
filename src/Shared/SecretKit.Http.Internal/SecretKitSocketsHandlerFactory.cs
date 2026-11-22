using System.Net;

namespace SecretKit.Internal;

internal static class SecretKitSocketsHandlerFactory
{
    internal static SocketsHttpHandler Create(IWebProxy? proxy = null) => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = proxy is not null,
        Proxy = proxy,
        ActivityHeadersPropagator = null,
        PooledConnectionLifetime = TimeSpan.FromMinutes(2)
    };
}
