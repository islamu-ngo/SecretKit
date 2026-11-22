using System.Net;
using System.Net.Sockets;

namespace SecretKit.Internal;

internal static class OriginPolicy
{
    internal static void ValidateProviderOrigin(Uri origin, bool hostControlled, bool allowLoopbackHttp)
    {
        ArgumentNullException.ThrowIfNull(origin);
        bool http = origin.IsAbsoluteUri && origin.Scheme == Uri.UriSchemeHttp &&
            (hostControlled || origin.IsLoopback && allowLoopbackHttp);
        if (!origin.IsAbsoluteUri || origin.Scheme != Uri.UriSchemeHttps && !http ||
            origin.UserInfo.Length != 0 || origin.AbsolutePath != "/" ||
            origin.Query.Length != 0 || origin.Fragment.Length != 0)
            throw new ArgumentException("A fixed HTTP(S) origin with an admitted transport is required.");
    }

    internal static void ValidatePublicWebhookEndpoint(Uri endpoint) => ValidateHttpsEndpoint(endpoint, false);

    internal static void ValidateDownstreamEndpoint(Uri? endpoint, Uri? trustedEndpointOrigin)
    {
        if (trustedEndpointOrigin is not null)
        {
            ValidateHttpsEndpoint(trustedEndpointOrigin, true);
            // Uri normalizes dot segments: a path such as /admin/.. is not an origin selection.
            var authorityAndPath = trustedEndpointOrigin.OriginalString.AsSpan(Uri.UriSchemeHttps.Length + 3);
            int slash = authorityAndPath.IndexOf('/');
            if (trustedEndpointOrigin.AbsolutePath != "/" || trustedEndpointOrigin.Query.Length != 0 ||
                !trustedEndpointOrigin.IsWellFormedOriginalString() || (slash >= 0 && slash != authorityAndPath.Length - 1))
                throw new ArgumentException("A bare trusted HTTPS origin is required.");
        }
        if (endpoint is not null)
        {
            bool matches = trustedEndpointOrigin is not null && endpoint.IsAbsoluteUri &&
                endpoint.IdnHost.Equals(trustedEndpointOrigin.IdnHost, StringComparison.OrdinalIgnoreCase) &&
                endpoint.Port == trustedEndpointOrigin.Port;
            ValidateHttpsEndpoint(endpoint, matches);
        }
    }

    private static void ValidateHttpsEndpoint(Uri endpoint, bool allowPrivate)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps ||
            (!allowPrivate && !endpoint.IsDefaultPort) || endpoint.UserInfo.Length != 0 || endpoint.Fragment.Length != 0 ||
            endpoint.Host.Length == 0 || endpoint.IsLoopback)
            throw new ArgumentException("An admitted HTTPS endpoint is required.");
        string host = endpoint.IdnHost.TrimEnd('.');
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("An admitted HTTPS endpoint is required.");
        // This validates literal destinations, not DNS answers. The operator
        // still owns trusted DNS, proxy selection and network egress policy.
        if (!IPAddress.TryParse(host, out IPAddress? address)) return;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        byte[] bytes = address.GetAddressBytes();
        bool local = IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any);
        if (address.AddressFamily == AddressFamily.InterNetwork)
            local |= bytes[0] is 0 or 127 || bytes[0] >= 224 ||
                bytes[0] == 169 && bytes[1] == 254 ||
                !allowPrivate && (bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
                    bytes[0] == 192 && bytes[1] == 168);
        else
            local |= address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast ||
                !allowPrivate && (bytes[0] & 0xfe) == 0xfc;
        if (local) throw new ArgumentException("An admitted HTTPS endpoint is required.");
    }
}
