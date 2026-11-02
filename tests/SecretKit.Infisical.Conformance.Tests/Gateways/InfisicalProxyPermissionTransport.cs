using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed partial class InfisicalProxyPermissionFixture
{
    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                var socket = await listener.AcceptTcpClientAsync(shutdown.Token);
                // Register under the same fence as Handle and Close. A synchronous
                // commit cannot become invisible between ServeAsync and enrollment.
                lock (gate) connections.Add(ServeAsync(socket));
            }
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }
    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            byte[] header = new byte[32768], body = [], response = [];
            Copies.Add(header);
            try
            {
                var stream = socket.GetStream(); int count = 0;
                while (count < header.Length)
                {
                    if (await stream.ReadAsync(header.AsMemory(count, 1), shutdown.Token) == 0) return;
                    count++;
                    if (count >= 4 && header.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                string[] lines = Encoding.ASCII.GetString(header, 0, count).Split("\r\n");
                string[] request = lines[0].Split(' ');
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':')[1].Trim() ?? "0");
                ProxyPermissionContract.Require(length is >= 0 and <= 131072);
                body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Body) result;
                lock (gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, document.RootElement, body);
                if (Fault == "delayed-dispatch" && request[0] == "POST" && request[1] == "/api/v1/proxied-services" && result.Status == 200)
                {
                    DispatchEntered.TrySetResult(); await DispatchRelease.Task.WaitAsync(shutdown.Token);
                }
                response = JsonSerializer.SerializeToUtf8Bytes(result.Body); Copies.Add(response);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                CryptographicOperations.ZeroMemory(header); CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(response);
            }
        }
    }
}
