using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecretKit.Demo.Tests;

internal sealed class ControlledInfisicalServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _held = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Func<DemoRequest, DemoResponse> _respond;
    private readonly Task _worker;
    private readonly List<Task> _connections = [];

    internal ControlledInfisicalServer(Func<DemoRequest, DemoResponse> respond)
    {
        _respond = respond;
        _listener.Start();
        Origin = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}");
        _worker = ServeAsync();
    }

    internal Uri Origin { get; }
    internal System.Collections.Concurrent.ConcurrentQueue<DemoRequest> Requests { get; } = new();

    private async Task ServeAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient connection = await _listener.AcceptTcpClientAsync(_stop.Token);
                _connections.Add(RespondAsync(connection));
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    private async Task RespondAsync(TcpClient connection)
    {
        using (connection)
        {
            try
            {
                await using NetworkStream stream = connection.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                string start = await reader.ReadLineAsync(_stop.Token) ??
                    throw new InvalidOperationException("Missing controlled request.");
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                int headerBytes = start.Length;
                while (await reader.ReadLineAsync(_stop.Token) is { Length: > 0 } line)
                {
                    headerBytes += line.Length;
                    if (headerBytes > 65536) throw new InvalidOperationException("Controlled header budget.");
                    int colon = line.IndexOf(':');
                    headers.Add(line[..colon], line[(colon + 1)..].Trim());
                }
                int length = headers.TryGetValue("Content-Length", out string? size) ? int.Parse(size) : 0;
                if (length is < 0 or > 65536) throw new InvalidOperationException("Controlled body budget.");
                char[] body = new char[length];
                if (length > 0 && await reader.ReadBlockAsync(body.AsMemory(), _stop.Token) != length)
                    throw new EndOfStreamException("Incomplete controlled request.");
                string[] requestLine = start.Split(' ');
                var request = new DemoRequest(requestLine[0], requestLine[1], headers, new string(body));
                Requests.Enqueue(request);
                DemoResponse response = _respond(request);
                if (response.Release is { } release) await release.WaitAsync(_stop.Token);
                if (response.Drop) return;
                if (response.Hold) await _held.Task.WaitAsync(_stop.Token);
                byte[] bytes = Encoding.UTF8.GetBytes(response.Body);
                string location = response.Location is { } redirect ? $"Location: {redirect.AbsoluteUri}\r\n" : "";
                byte[] head = Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} Controlled\r\n" +
                    $"Content-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n{location}\r\n");
                await stream.WriteAsync(head, _stop.Token);
                await stream.WriteAsync(bytes, _stop.Token);
                await stream.FlushAsync(_stop.Token);
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            catch (IOException) { /* A cancelled HTTP caller may close its socket before a response. */ }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        try
        {
            await _worker;
            await Task.WhenAll(_connections);
        }
        finally { _stop.Dispose(); }
    }
}

internal sealed record DemoRequest(string Method, string Target,
    IReadOnlyDictionary<string, string> Headers, string Body);
internal sealed record DemoResponse(int Status, string Body, bool Drop = false, bool Hold = false,
    Task? Release = null, Uri? Location = null);
