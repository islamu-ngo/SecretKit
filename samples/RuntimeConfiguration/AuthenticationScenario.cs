using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Samples.RuntimeConfiguration;

/// <summary>Offline, caller-driven login, renewal and explicitly authorized replacement.</summary>
public static class AuthenticationScenario
{
    public static async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var origin = new Uri($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}");
        Task exchanges = ServeAsync(listener, deadline.Token);
        try
        {
            var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
            using var authentication = new InfisicalUniversalAuthentication(origin, network);
            // The host selects one principal and supplies each independently authorized
            // bootstrap credential. No recovery callback can select another identity.
            const string selectedClientId = "offline-selected-principal";
            using var initialBootstrap = SecretMaterial.FromText("offline-initial-bootstrap");
            await using var session = await StartAsync(authentication, selectedClientId,
                initialBootstrap, network, deadline.Token);
            initialBootstrap.Dispose();
            using var initial = (await session.GetTokenAsync(deadline.Token)).Value;
            if (initial.Material.Reveal() != "offline-issued")
                throw new InvalidOperationException("The selected login was not handed off.");

            // Renewal is explicitly invoked here; construction and token reads start no worker.
            if (await session.RenewAsync(deadline.Token) != SecretStatus.Success)
                throw new InvalidOperationException("The explicit renewal failed.");
            using var renewed = (await session.GetTokenAsync(deadline.Token)).Value;
            if (renewed.Material.Reveal() != "offline-renewed")
                throw new InvalidOperationException("The renewed generation was not published.");

            // A lost/uncertain renewal is not retried, and cannot replay consumed bootstrap.
            if (await session.RenewAsync(deadline.Token) != SecretStatus.RecoveryRequired ||
                session.LastRenewal?.Evidence != InfisicalRenewalEvidence.PossiblyDispatched)
                throw new InvalidOperationException("Uncertain renewal did not require recovery.");
            await session.StopAsync().WaitAsync(deadline.Token);

            // This separate host decision supplies fresh authorized material for the SAME
            // selected principal, retires the old generation and rebuilds its consumers.
            using var replacementBootstrap = SecretMaterial.FromText("offline-authorized-replacement");
            await using var replacement = await StartAsync(authentication, selectedClientId,
                replacementBootstrap, network, deadline.Token);
            replacementBootstrap.Dispose();
            using var replacementToken = (await replacement.GetTokenAsync(deadline.Token)).Value;
            if (replacementToken.Material.Reveal() != "offline-replacement" ||
                session.State != InfisicalTokenSessionState.Stopped)
                throw new InvalidOperationException("Explicit replacement did not retire the old session.");
            await replacement.StopAsync().WaitAsync(deadline.Token);
            await exchanges;
            Console.WriteLine("AUTHENTICATION_EXPLICIT_RENEWAL_RECOVERY_REPLACEMENT");
        }
        finally
        {
            deadline.Cancel();
            listener.Stop();
            try { await exchanges; }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        }
    }

    private static async Task<InfisicalPeriodicTokenSession> StartAsync(
        InfisicalUniversalAuthentication authentication, string selectedClientId,
        SecretMaterial authorizedBootstrap, InfisicalNetworkOptions network,
        CancellationToken cancellationToken)
    {
        var receipt = authentication.CreateReceipt();
        var outcome = await authentication.LoginAsync(selectedClientId, authorizedBootstrap,
            receipt, cancellationToken: cancellationToken);
        if (!outcome.IsSuccess)
            throw new InvalidOperationException($"Explicit startup requires a host decision: {outcome.Status}/{receipt.Evidence}.");
        using var login = outcome.Value;
        // This offline deployment's finite policy is independently selected by the host.
        // RequestStartedAt is only a conservative lower bound for a fresh login, not
        // server-issued-at proof. Neither expiry nor the ceiling resets at handoff.
        var evidence = login.BindLifetimeEvidence(new InfisicalTokenLifetimeEvidence
        {
            OriginalIssuedAt = login.RequestStartedAt,
            ExpiresAt = login.Token.ExpiresAt!.Value,
            Lifetime = InfisicalTokenLifetime.Finite,
            ReportedMaximumTtl = TimeSpan.FromSeconds(login.AccessTokenMaxTTL)
        });
        return new InfisicalPeriodicTokenSession(login, evidence, TimeSpan.FromSeconds(10),
            TimeSpan.FromSeconds(5), network);
    }

    private static async Task ServeAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        string[] routes = ["/api/v1/auth/universal-auth/login", "/api/v1/auth/token/renew",
            "/api/v1/auth/token/renew", "/api/v1/auth/universal-auth/login"];
        for (int exchange = 0; exchange < routes.Length; exchange++)
        {
            using var connection = await listener.AcceptTcpClientAsync(cancellationToken);
            using NetworkStream stream = connection.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            if (await reader.ReadLineAsync(cancellationToken) != $"POST {routes[exchange]} HTTP/1.1")
                throw new InvalidOperationException("Unexpected authentication route.");
            int length = 0;
            while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 } header)
                if (header.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                    length = int.Parse(header.AsSpan("Content-Length:".Length), CultureInfo.InvariantCulture);
            if (length is < 1 or > 65536)
                throw new InvalidOperationException("Unexpected authentication body size.");
            char[] body = new char[length];
            try
            {
                int received = 0;
                while (received < body.Length)
                {
                    int count = await reader.ReadAsync(body.AsMemory(received), cancellationToken);
                    if (count == 0) throw new IOException("Incomplete authentication request.");
                    received += count;
                }
                using var json = JsonDocument.Parse(new string(body));
                bool matches = exchange switch
                {
                    0 or 3 => json.RootElement.GetProperty("clientId").GetString() == "offline-selected-principal" &&
                        json.RootElement.GetProperty("clientSecret").GetString() ==
                        (exchange == 0 ? "offline-initial-bootstrap" : "offline-authorized-replacement"),
                    1 => json.RootElement.GetProperty("accessToken").GetString() == "offline-issued",
                    _ => json.RootElement.GetProperty("accessToken").GetString() == "offline-renewed"
                };
                if (!matches) throw new InvalidOperationException("Authentication selection changed.");
            }
            finally { Array.Clear(body); }
            string token = exchange switch { 0 => "offline-issued", 1 => "offline-renewed", _ => "offline-replacement" };
            string response = exchange == 2 ? "{}" : JsonSerializer.Serialize(new
            {
                accessToken = token,
                tokenType = "Bearer",
                expiresIn = 60,
                accessTokenMaxTTL = 120
            });
            string status = exchange == 2 ? "503 Service Unavailable" : "200 OK";
            byte[] bytes = Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n{response}");
            await stream.WriteAsync(bytes, cancellationToken);
        }
    }
}
