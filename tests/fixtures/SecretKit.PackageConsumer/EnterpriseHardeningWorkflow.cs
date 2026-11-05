using System.Net;
using System.Text.Json;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;

internal static class EnterpriseHardeningWorkflow
{
    private const string Organization = "11111111-1111-4111-8111-111111111111";
    private const string Identity = "22222222-2222-4222-8222-222222222222";

    internal static async Task<int> RunAsync()
    {
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var scenarios = new List<object>();
            using var wire = new Wire();
            using var transport = new ManagementTransport(new("https://management.invalid"), new()
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                MaximumRequestBytes = 1024
            });
            var client = new ManagementClient(transport);
            var tokens = new Tokens();
            var authority = new ManagementAuthority(client.Authority, tokens, Organization);
            using (var password = SecretMaterial.FromText(new string('x', 2000)))
            using (var request = SharingOperations.AccessShare(Organization, "share", password))
            {
                var receipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                Require(result.Reason == SecretFailureReason.RequestTooLarge &&
                    receipt.Evidence == DispatchEvidence.NotDispatched && tokens.Requests == 0 && wire.Requests == 0);
            }
            Observe("S03", "management-selected-limit-before-credential-acquisition");
            foreach (string number in new[] { "9007199254740993", "0.12345678901234567890123456789", "1e999" })
            {
                wire.Body = "{\"identityTokenAuth\":{\"id\":\"" + Identity + "\",\"identityId\":\"" + Identity +
                    "\",\"createdAt\":\"2026-10-10T00:00:00Z\",\"updatedAt\":\"2026-10-10T00:00:00Z\"," +
                    "\"accessTokenNumUsesLimit\":" + number + "}}";
                using var request = IdentityAuthenticationOperations.GetTokenAuth(Organization, Identity);
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, request.Target), cancellationToken: deadline.Token);
                Require(result.IsSuccess);
                var returned = result.Value.AccessTokenNumUsesLimit!.Value;
                Require(returned.Export() == number);
                if (number == "9007199254740993")
                    Require(returned.GetInt64() == 9007199254740993 && returned.GetDecimal() == 9007199254740993m);
                else Require(!returned.TryGetInt64(out _) && !returned.TryGetDecimal(out _));
            }
            Observe("S13", "management-exact-large-integral-fraction-and-exponent-tokens");
            foreach (int status in new[] { 429, 503 })
            {
                wire.Status = status;
                wire.Advice = "999999";
                using var request = ScopedAccessOperations.CreateGroup(Organization, "created", "created");
                var receipt = client.CreateReceipt(request);
                var grant = authority.IssueGrant(request.OperationId, request.Target);
                int before = wire.Requests;
                var result = await client.ExecuteAsync(request, authority, grant, receipt, deadline.Token);
                Require(result.Status == (status == 429 ? SecretStatus.Throttled : SecretStatus.Unavailable) &&
                    result.RetryAfter == TimeSpan.FromHours(24));
                Require((await client.ExecuteAsync(request, authority, grant, receipt, deadline.Token)).Status ==
                    SecretStatus.Invalid && wire.Requests == before + 1);
            }
            Observe("S12", "management-advice-clamp-and-no-mutation-replay");
            wire.Status = 200;
            wire.Advice = null;
            wire.LoseResponse = true;
            using (var request = ScopedAccessOperations.CreateGroup(Organization, "created", "created"))
            {
                var receipt = client.CreateReceipt(request);
                var grant = authority.IssueGrant(request.OperationId, request.Target);
                int before = wire.Requests;
                var result = await client.ExecuteAsync(request, authority, grant, receipt, deadline.Token);
                Require(result.Status == SecretStatus.Unknown && receipt.Evidence == DispatchEvidence.PossiblyDispatched);
                Require((await client.ExecuteAsync(request, authority, grant, receipt, deadline.Token)).Status ==
                    SecretStatus.Invalid && wire.Requests == before + 1);
            }
            Observe("S02", "management-response-loss-retains-uncertainty-and-rejects-replay");

            using var azureWire = new Wire();
            using var http = new HttpClient(azureWire);
            using var azureTransport = new HttpClientTransport(http);
            var azure = new AzureKeyVaultClient(new("https://fixture.vault.azure.net"),
                new FixtureCredential(), azureTransport);
            var reference = new SecretReference(azure.Authority, new AzureSecretAddress("fixture"));
            azureWire.Body = """
                {"value":"azure-value-canary","id":"https://foreign.vault.azure.net/secrets/fixture/0123456789abcdef0123456789abcdef","attributes":{"enabled":true}}
                """;
            Require((await azure.ReadAsync(reference, deadline.Token)).Status == SecretStatus.Invalid);
            Observe("S10", "azure-foreign-returned-coordinate-rejects-material");
            azureWire.LoseResponse = true;
            Require((await azure.ReadAsync(reference, deadline.Token)).Status == SecretStatus.Unavailable);
            using var value = SecretMaterial.FromText("azure-value-canary");
            var azureReceipt = azure.CreateReceipt(reference);
            var lost = await azure.SetSecretAsync(new AzureSetSecretRequest(reference, value), azureReceipt, deadline.Token);
            Require(lost.Status == SecretStatus.Unknown && azureReceipt.Evidence == DispatchEvidence.PossiblyDispatched);
            Observe("S11", "azure-transport-failure-read-versus-mutation-uncertainty");
            const string statusUrl = "https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/operations/55555555-5555-5555-5555-555555555555?api-version=2026-02-01";
            int mutations = 0;
            int phase = 0;
            azureWire.LoseResponse = false;
            azureWire.Reply = request =>
            {
                if (request.Method == HttpMethod.Post)
                {
                    mutations++;
                    var response = new HttpResponseMessage(HttpStatusCode.Accepted) { Content = new StringContent("") };
                    response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", statusUrl);
                    response.Headers.TryAddWithoutValidation("Location", statusUrl);
                    return response;
                }
                Require(request.RequestUri!.AbsoluteUri == statusUrl);
                return new HttpResponseMessage(phase == 1 ? HttpStatusCode.Forbidden : HttpStatusCode.OK)
                {
                    Content = new StringContent(phase switch
                    {
                        0 => """{"status":"InProgress"}""",
                        1 => """{"error":{"code":"Denied"}}""",
                        _ => """{"status":"Succeeded"}"""
                    })
                };
            };
            var administration = new VaultAdministration(new FixtureCredential(), azureTransport);
            var scope = new DeletedVaultScope(
                new SubscriptionScope(Guid.Parse("11111111-1111-1111-1111-111111111111")), "eastus", "vault-canary");
            var purgeReceipt = administration.PrepareReceipt(scope, ManagementMutation.PurgeDeletedVault);
            var started = await administration.PurgeDeletedVaultAsync(scope, purgeReceipt, deadline.Token);
            Require(started.IsSuccess);
            var original = started.Value;
            Require(await original.CheckStatusAsync(deadline.Token) == SecretStatus.Pending);
            phase = 1;
            Require(await original.CheckStatusAsync(deadline.Token) == SecretStatus.Denied &&
                original.State == NativeProvisioningState.Pending);
            Observe("S05", "denied-status-does-not-poison-original-azure-handle");
            phase = 2;
            Require(await original.CheckStatusAsync(deadline.Token) == SecretStatus.Success &&
                original.State == NativeProvisioningState.Succeeded && mutations == 1 &&
                purgeReceipt.Evidence == DispatchEvidence.Pending);
            Observe("S06", "later-original-handle-terminal-evidence-without-new-mutation");
            transport.Dispose();
            Require(!wire.Disposed);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                profile = "enterprise-hardening",
                kind = "controlled-installed-offline",
                mode = "seven-package",
                nativeQualified = false,
                scenarios
            }));
            return 0;
            void Observe(string id, string subset) => scenarios.Add(new { id, subset, status = "passed" });
        }
        catch
        {
            Console.Error.WriteLine("Enterprise hardening workflow failed; protected diagnostics withheld.");
            return 1;
        }
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Installed enterprise assertion failed.");
    }
    private sealed class Tokens : IInfisicalTokenSource
    {
        internal int Requests { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Requests++;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("selected-admin-canary"))));
        }
    }
    private sealed class Wire : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        internal int Status { get; set; } = 200;
        internal string Body { get; set; } = "{}";
        internal string? Advice { get; set; }
        internal bool LoseResponse { get; set; }
        internal bool Disposed { get; private set; }
        internal Func<HttpRequestMessage, HttpResponseMessage>? Reply { get; set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Requests++;
            if (request.RequestUri!.Host == "fixture.vault.azure.net" && request.Headers.Authorization is null)
            {
                var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    "Bearer authorization=\"https://login.microsoftonline.com/test-tenant\", resource=\"https://vault.azure.net\"");
                return Task.FromResult(challenge);
            }
            if (LoseResponse) throw new HttpRequestException("controlled-response-loss");
            if (Reply is not null) return Task.FromResult(Reply(request));
            var response = new HttpResponseMessage((HttpStatusCode)Status) { Content = new StringContent(Body) };
            if (Advice is not null) response.Headers.TryAddWithoutValidation("Retry-After", Advice);
            return Task.FromResult(response);
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
