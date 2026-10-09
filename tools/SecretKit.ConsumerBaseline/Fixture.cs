using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.ConsumerBaseline;

internal sealed class Fixture
{
    public static readonly Uri Vault = new("https://fixture.vault.azure.net");
    public string Scenario { get; set; } = "ready";
    public string Value { get; private set; } = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    public string Version { get; private set; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
    public int AzureRequests { get; set; }
    public void Rotate()
    {
        Value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Version = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
    }

    public int Status(string key) => key != "second" ? 200 : Scenario switch
    {
        "absent" => 404,
        "denied" => 403,
        "unavailable" => 503,
        _ => 200
    };

    public object AzureItem(string key) => new
    {
        id = $"{Vault}secrets/{key}/{Version}",
        attributes = new { enabled = true }
    };
}

internal sealed class AzureFixtureHandler(Fixture fixture) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Uri uri = request.RequestUri!;
        if (request.Method != HttpMethod.Get || uri.Scheme != Fixture.Vault.Scheme ||
            uri.Host != Fixture.Vault.Host || uri.Port != Fixture.Vault.Port ||
            !uri.Query.Contains("api-version=2025-07-01", StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected offline Azure request.");
        fixture.AzureRequests++;
        string key = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Last();
        bool inventory = uri.AbsolutePath.TrimEnd('/') == "/secrets";
        if (!inventory && key is not ("first" or "second"))
            throw new InvalidOperationException("Unexpected fixture selector.");
        int status = inventory ? 200 : fixture.Status(key);
        object body = status != 200 ? new { error = new { code = "FixtureFailure" } } :
            inventory ? new { value = new[] { fixture.AzureItem("first"), fixture.AzureItem("second") } } :
            new
            {
                value = fixture.Value,
                id = $"{Fixture.Vault}secrets/{key}/{fixture.Version}",
                attributes = new { enabled = true }
            };
        return Task.FromResult(new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        });
    }
}

internal sealed class GeneratedCredential : TokenCredential
{
    private readonly string _token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public override AccessToken GetToken(TokenRequestContext context, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return new(_token, DateTimeOffset.UtcNow.AddMinutes(5));
    }
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token) =>
        ValueTask.FromResult(GetToken(context, token));
}

internal sealed class GeneratedTokens : IInfisicalTokenSource
{
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
            new InfisicalAccessToken(SecretMaterial.FromText(
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32))))));
    }
}

// Local wire fixture only: bounded, serial, ephemeral port, no provider authority.
internal sealed class InfisicalFixtureWire : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop;
    private readonly Task _serve;
    public Uri Origin { get; }
    public int Requests { get; private set; }

    public InfisicalFixtureWire(Fixture fixture, CancellationToken deadline)
    {
        _stop = CancellationTokenSource.CreateLinkedTokenSource(deadline);
        _listener.Start();
        Origin = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}");
        _serve = ServeAsync(fixture, _stop.Token);
    }

    private async Task ServeAsync(Fixture fixture, CancellationToken token)
    {
        try
        {
            for (int i = 0; i < 4096; i++)
            {
                using TcpClient connection = await _listener.AcceptTcpClientAsync(token);
                await using NetworkStream stream = connection.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                string? request = await reader.ReadLineAsync(token);
                bool authorized = false;
                int headerCount = 0;
                while (await reader.ReadLineAsync(token) is { Length: > 0 } header)
                {
                    if (++headerCount > 64)
                        throw new InvalidOperationException("Fixture header limit exceeded.");
                    authorized |= header.StartsWith("Authorization: Bearer ", StringComparison.OrdinalIgnoreCase);
                }
                if (!authorized || request is null || !request.StartsWith("GET /api/v4/secrets", StringComparison.Ordinal))
                    throw new InvalidOperationException("Unexpected offline Infisical request.");
                var uri = new Uri(Origin, request.Split(' ')[1]);
                bool inventory = uri.AbsolutePath == "/api/v4/secrets";
                string key = uri.AbsolutePath.Split('/').Last();
                if (!inventory && key is not ("first" or "second"))
                    throw new InvalidOperationException("Unexpected fixture selector.");
                int status = inventory ? 200 : fixture.Status(key);
                object body = status != 200 ? new { message = "FixtureFailure" } :
                    inventory ? new
                    {
                        secrets = new[] {
                            new { secretKey = "first", version = 1 },
                            new { secretKey = "second", version = 1 }
                        }
                    } : new
                    {
                        secret = new { secretKey = key, secretValue = fixture.Value, secretValueHidden = false, version = 1 }
                    };
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(body);
                byte[] headers = Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(headers, token);
                await stream.WriteAsync(bytes, token);
                Requests++;
            }
            throw new InvalidOperationException("Fixture request limit exceeded.");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        await _serve;
        _stop.Dispose();
    }
}
