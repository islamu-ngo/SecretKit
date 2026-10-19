using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Explicit local composition, not an SDK listener or provider deployment.
// The certificate and delegate are borrowed; sockets and request buffers are owned.
internal sealed class RoleFixtureObserverHost : IAsyncDisposable
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly object gate = new();
    private readonly TcpListener listener;
    private readonly X509Certificate2 certificate;
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler;
    private readonly CancellationTokenSource lifetime;
    private readonly CancellationTokenRegistration stopping;
    private readonly HashSet<TcpClient> connections = [];
    private readonly Task[] workers;
    private readonly int maximumHeaderBytes;
    private readonly int maximumBodyBytes;
    private readonly TimeSpan deadline;
    private Task? disposal;

    private RoleFixtureObserverHost(X509Certificate2 certificate, IPEndPoint address,
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler,
        CancellationToken cancellationToken, int maximumConcurrentRequests,
        int maximumHeaderBytes, int maximumBodyBytes, TimeSpan deadline)
    {
        this.certificate = certificate;
        this.handler = handler;
        this.maximumHeaderBytes = maximumHeaderBytes;
        this.maximumBodyBytes = maximumBodyBytes;
        this.deadline = deadline;
        lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        listener = new(address);
        listener.Start(maximumConcurrentRequests);
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        Origin = new UriBuilder(Uri.UriSchemeHttps, endpoint.Address.ToString(), endpoint.Port).Uri;
        stopping = lifetime.Token.Register(StopTransport);
        // Fixed workers own both acceptance and dispatch. No per-connection task fanout.
        workers = Enumerable.Range(0, maximumConcurrentRequests).Select(_ => ServeAsync()).ToArray();
    }

    internal Uri Origin { get; }

    internal static RoleFixtureObserverHost Start(X509Certificate2 serverCertificate, IPEndPoint address,
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler,
        CancellationToken cancellationToken = default, int maximumConcurrentRequests = 8,
        int maximumHeaderBytes = 16 * 1024, int maximumBodyBytes = 64 * 1024,
        TimeSpan? connectionDeadline = null)
    {
        ArgumentNullException.ThrowIfNull(serverCertificate);
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(handler);
        Require(serverCertificate.HasPrivateKey && !address.Address.Equals(IPAddress.Any) &&
            !address.Address.Equals(IPAddress.IPv6Any));
        Require(maximumConcurrentRequests is > 0 and <= 64 &&
            maximumHeaderBytes is >= 256 and <= 64 * 1024 &&
            maximumBodyBytes is > 0 and <= 1024 * 1024);
        TimeSpan timeout = connectionDeadline ?? TimeSpan.FromSeconds(30);
        Require(timeout > TimeSpan.Zero && timeout <= TimeSpan.FromMinutes(5));
        cancellationToken.ThrowIfCancellationRequested();
        return new(serverCertificate, address, handler, cancellationToken, maximumConcurrentRequests,
            maximumHeaderBytes, maximumBodyBytes, timeout);
    }

    public override string ToString() => "RoleFixtureObserverHost([redacted])";

    private void StopTransport()
    {
        listener.Stop();
        lock (gate)
            foreach (var connection in connections) connection.Dispose();
    }

    public ValueTask DisposeAsync()
    {
        lock (gate) return new(disposal ??= DrainAsync());
    }

    private async Task DrainAsync()
    {
        lifetime.Cancel();
        await Task.WhenAll(workers).ConfigureAwait(false);
        stopping.Dispose();
        lifetime.Dispose();
    }

    private async Task ServeAsync()
    {
        while (!lifetime.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(lifetime.Token).ConfigureAwait(false); }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                break;
            }
            lock (gate)
            {
                if (lifetime.IsCancellationRequested)
                {
                    client.Dispose();
                    break;
                }
                connections.Add(client);
            }
            try { await DispatchAsync(client).ConfigureAwait(false); }
            // No exception text, request coordinates, credentials or body are emitted.
            catch (Exception) { }
            finally
            {
                lock (gate) connections.Remove(client);
                client.Dispose();
            }
        }
    }

    private async Task DispatchAsync(TcpClient client)
    {
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        operation.CancelAfter(deadline);
        using var close = operation.Token.Register(client.Dispose);
        using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
        await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ApplicationProtocols = [SslApplicationProtocol.Http11],
            AllowRenegotiation = false,
            ClientCertificateRequired = false
        }, operation.Token).ConfigureAwait(false);
        Require(tls.NegotiatedApplicationProtocol == default ||
            tls.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11);
        byte[] headers = new byte[maximumHeaderBytes];
        byte[] body = new byte[maximumBodyBytes + 1];
        byte[] responseBody = new byte[maximumBodyBytes + 1];
        byte[]? responseHeaders = null;
        try
        {
            int headerLength = 0;
            while (true)
            {
                Require(headerLength < headers.Length);
                int read = await tls.ReadAsync(headers.AsMemory(headerLength, 1), operation.Token).ConfigureAwait(false);
                Require(read == 1);
                headerLength++;
                if (headerLength >= 4 && headers[headerLength - 4] == 13 &&
                    headers[headerLength - 3] == 10 && headers[headerLength - 2] == 13 &&
                    headers[headerLength - 1] == 10) break;
            }
            using var request = ParseRequest(headers.AsSpan(0, headerLength), out int bodyLength);
            await tls.ReadExactlyAsync(body.AsMemory(0, bodyLength), operation.Token).ConfigureAwait(false);
            // Observer requests are textual. Reject malformed encoding before dispatch.
            _ = StrictUtf8.GetCharCount(body, 0, bodyLength);
            request.Content = new ByteArrayContent(body, 0, bodyLength);
            // ParseRequest records content headers separately because HttpRequestHeaders
            // deliberately refuses them.
            if (request.Options.TryGetValue(ContentHeadersKey, out var contentHeaders))
                foreach (var header in contentHeaders)
                    Require(request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value));
            operation.Token.ThrowIfCancellationRequested();
            using HttpResponseMessage response = await handler(request, operation.Token).ConfigureAwait(false);
            operation.Token.ThrowIfCancellationRequested();
            int responseLength = 0;
            if (response.Content is not null)
            {
                Require(response.Content.Headers.ContentLength is null ||
                    response.Content.Headers.ContentLength <= maximumBodyBytes);
                using Stream input = await response.Content.ReadAsStreamAsync(operation.Token).ConfigureAwait(false);
                while (true)
                {
                    int read = await input.ReadAsync(responseBody.AsMemory(responseLength), operation.Token).ConfigureAwait(false);
                    if (read == 0) break;
                    responseLength += read;
                    Require(responseLength <= maximumBodyBytes);
                }
            }
            responseHeaders = EncodeResponse(response, responseLength);
            // All response validation and buffering precede the first write.
            await tls.WriteAsync(responseHeaders, operation.Token).ConfigureAwait(false);
            if (request.Method != HttpMethod.Head)
                await tls.WriteAsync(responseBody.AsMemory(0, responseLength), operation.Token).ConfigureAwait(false);
            await tls.FlushAsync(operation.Token).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(headers);
            CryptographicOperations.ZeroMemory(body);
            CryptographicOperations.ZeroMemory(responseBody);
            if (responseHeaders is not null) CryptographicOperations.ZeroMemory(responseHeaders);
        }
    }

    private static readonly HttpRequestOptionsKey<List<KeyValuePair<string, string>>> ContentHeadersKey = new("content-headers");

    private HttpRequestMessage ParseRequest(ReadOnlySpan<byte> bytes, out int bodyLength)
    {
        foreach (byte value in bytes) Require(value is >= 32 and <= 126 or 13 or 10);
        string[] lines = Encoding.ASCII.GetString(bytes).Split("\r\n", StringSplitOptions.None);
        string[] first = lines[0].Split(' ');
        Require(first.Length == 3 && first[2] == "HTTP/1.1" &&
            first[0] is "GET" or "POST" or "PUT" or "DELETE" or "PATCH" or "HEAD" or "OPTIONS");
        string target = first[1];
        Require(target.StartsWith('/') && !target.StartsWith("//", StringComparison.Ordinal) &&
            !target.Contains('\\') && !target.Contains('#') && target.All(c => c > 32 && c < 127));
        byte[] decodedTarget = new byte[target.Length];
        try
        {
            int length = 0;
            for (int index = 0; index < target.Length; index++)
            {
                byte value = (byte)target[index];
                if (target[index] == '%')
                {
                    Require(index + 2 < target.Length && Uri.IsHexDigit(target[index + 1]) && Uri.IsHexDigit(target[index + 2]));
                    value = byte.Parse(target.AsSpan(index + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    index += 2;
                }
                Require(value >= 32 && value != 127 && value != (byte)'\\');
                decodedTarget[length++] = value;
            }
            _ = StrictUtf8.GetCharCount(decodedTarget, 0, length);
        }
        finally { CryptographicOperations.ZeroMemory(decodedTarget); }
        var uri = new Uri(Origin, target);
        Require(uri.Authority == Origin.Authority && uri.PathAndQuery == target);
        var values = new List<KeyValuePair<string, string>>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? host = null;
        bodyLength = 0;
        foreach (string line in lines.Skip(1).Take(lines.Length - 3))
        {
            int colon = line.IndexOf(':');
            Require(colon > 0);
            string name = line[..colon];
            Require(name.All(IsToken) && names.Add(name)); // Reject all duplicates, including equal lengths.
            string value = line[(colon + 1)..].Trim(' ');
            Require(value.All(c => c is >= ' ' and <= '~'));
            Require(!name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) &&
                !name.Equals("Expect", StringComparison.OrdinalIgnoreCase) &&
                !name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase) &&
                !name.Equals("Trailer", StringComparison.OrdinalIgnoreCase));
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase)) host = value;
            else if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                Require(int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out bodyLength) &&
                    bodyLength >= 0 && bodyLength <= maximumBodyBytes);
            else values.Add(new(name, value));
        }
        Require(string.Equals(host, Origin.Authority, StringComparison.OrdinalIgnoreCase));
        var request = new HttpRequestMessage(new HttpMethod(first[0]), uri) { Version = HttpVersion.Version11 };
        try
        {
            var contentHeaders = new List<KeyValuePair<string, string>>();
            foreach (var value in values)
                if (value.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)) contentHeaders.Add(value);
                else Require(request.Headers.TryAddWithoutValidation(value.Key, value.Value));
            request.Headers.Host = host;
            request.Options.Set(ContentHeadersKey, contentHeaders);
            return request;
        }
        catch
        {
            request.Dispose();
            throw;
        }
    }

    private byte[] EncodeResponse(HttpResponseMessage response, int length)
    {
        int status = (int)response.StatusCode;
        Require(status is >= 200 and <= 599);
        Require((status is not (204 or 304)) || length == 0);
        var text = new StringBuilder();
        text.Append("HTTP/1.1 ").Append(status.ToString(CultureInfo.InvariantCulture)).Append(" Result\r\n");
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers = response.Headers;
        if (response.Content is not null) headers = headers.Concat(response.Content.Headers);
        foreach (var header in headers)
        {
            Require(header.Key.All(IsToken));
            Require(!header.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) &&
                !header.Key.Equals("Trailer", StringComparison.OrdinalIgnoreCase) &&
                !header.Key.Equals("Upgrade", StringComparison.OrdinalIgnoreCase));
            if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                Require(response.Content!.Headers.ContentLength == length);
                continue;
            }
            if (header.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (string value in header.Value)
            {
                Require(value.Length <= maximumHeaderBytes && value.All(c => c is >= ' ' and <= '~'));
                Require(text.Length + header.Key.Length + value.Length + 4 <= maximumHeaderBytes);
                text.Append(header.Key).Append(": ").Append(value).Append("\r\n");
            }
        }
        text.Append("Content-Length: ").Append(length.ToString(CultureInfo.InvariantCulture))
            .Append("\r\nConnection: close\r\n\r\n");
        Require(text.Length <= maximumHeaderBytes);
        return Encoding.ASCII.GetBytes(text.ToString());
    }

    private static bool IsToken(char value) => char.IsAsciiLetterOrDigit(value) ||
        "!#$%&'*+-.^_`|~".Contains(value);

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Observer transport rejected input.");
    }
}
