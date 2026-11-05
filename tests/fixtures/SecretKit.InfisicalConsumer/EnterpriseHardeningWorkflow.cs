using System.Diagnostics;
using System.Net;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;
using static InstalledWorkflow;
#if CONFIGURATION
using SecretKit.Extensions.Configuration;
#endif
#if HOSTING
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecretKit.Extensions.Hosting;
#endif

// Compiled only against selected archives; these are supplemental controlled observations.
internal static class EnterpriseHardeningWorkflow
{
    internal static async Task<int> RunAsync()
    {
        try
        {
            using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var scenarios = new List<object>();
            var clock = new Clock();
            using var wire = new Wire();
            var network = new InfisicalNetworkOptions
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                MaximumRequestBytes = 1024,
                MaximumResponseBytes = 1024
            };
            using var material = SecretMaterial.FromText(Token);
            await using var runtime = InfisicalRuntimeSession.CreateFromToken(Options(network, clock),
                material, new()
                {
                    OriginalIssuedAt = clock.GetUtcNow(),
                    ExpiresAt = clock.GetUtcNow().AddMinutes(1),
                    Lifetime = InfisicalTokenLifetime.Finite,
                    ReportedMaximumTtl = TimeSpan.FromMinutes(2)
                }).Value;
            var client = runtime.Client;
            var reference = Reference(client);
            using var large = SecretMaterial.FromText(new string('x', 2048));
            var receipt = client.CreateReceipt(reference);
            var rejected = await client.UpdateValueAsync(reference, large, receipt, bound.Token);
            Require(rejected.Reason == SecretFailureReason.RequestTooLarge &&
                receipt.Evidence == DispatchEvidence.NotDispatched && wire.Requests == 0);
            Observe("S03", "selected-request-limit-before-dispatch");

            foreach (string advice in new[] { "999999", "invalid" })
            {
                wire.Status = 429;
                wire.Advice = advice;
                int before = wire.Requests;
                var result = await client.ReadAsync(reference, bound.Token);
                Require(result.Status == SecretStatus.Throttled &&
                    result.RetryAfter == (advice == "invalid" ? null : TimeSpan.FromHours(24)) &&
                    wire.Requests == before + 1);
            }
            Observe("S12", "clamped-and-malformed-advice-without-retry");
            wire.Status = 200;
            wire.Advice = null;
            wire.Clock = clock;
            Activity? observed = null;
            using var parent = new Activity("host-parent").SetIdFormat(ActivityIdFormat.W3C).Start();
            parent.AddBaggage("private", Value);
            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == "SecretKit.Infisical",
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
                ActivityStopped = activity =>
                {
                    observed = activity;
                    clock.Advance(TimeSpan.FromSeconds(5));
                    throw new InvalidOperationException("host-observer-canary");
                }
            };
            ActivitySource.AddActivityListener(listener);
            using (var read = (await client.ReadAsync(reference, bound.Token)).Value)
                Require(read.Material.Reveal() == Value);
            Require(observed is not null && observed.Duration == TimeSpan.FromSeconds(2) &&
                observed.ParentSpanId == parent.SpanId && ReferenceEquals(Activity.Current, parent));
            Observe("S14", "completed-trace-excludes-listener-time");
            Observe("S16", "throwing-observer-preserves-result-and-ambient-parent");
            Activity captured = observed ?? throw new InvalidOperationException("Completed trace missing.");
            Require(!captured.Baggage.Any() && captured.TraceStateString is null &&
                !JsonSerializer.Serialize(captured.TagObjects.ToArray()).Contains("canary", StringComparison.Ordinal));
            Observe("S17", "sdk-tags-and-copied-context-exclude-material");
            listener.Dispose();
#if CONFIGURATION
            wire.Clock = null;
            wire.Value = new string('x', 600);
            using (var bounded = new SecretSnapshotLoader(
                [new SecretSelection("first", client, reference), new SecretSelection("second", client, reference)],
                clock, new SecretCollectionOptions(maximumConcurrency: 2, maximumSelections: 2,
                    maximumMaterialBytes: 1024, collectionTimeout: TimeSpan.FromSeconds(5))))
                Require(!(await bounded.RefreshAsync(bound.Token)).IsSuccess);
            wire.Value = Value;
            await using var coordinator = new SecretGenerationCoordinator<Consumer>(client,
                new Dictionary<string, SecretReference> { ["required"] = reference },
                (snapshot, _) =>
                {
                    using var read = snapshot.Read("required");
                    return ValueTask.FromResult(SecretOutcome<Consumer>.Success(new(read.Material.Reveal())));
                }, SecretGenerationStalePolicy.BoundedLastKnown, TimeSpan.FromSeconds(10), clock,
                new SecretCollectionOptions(maximumConcurrency: 2, maximumSelections: 1,
                    maximumMaterialBytes: 1024, collectionTimeout: TimeSpan.FromSeconds(5)));
            Require((await coordinator.EnableAsync(bound.Token)).Active);
            await using (var lease = coordinator.Acquire()!)
            {
                int before = wire.Requests;
                for (int i = 0; i < 3; i++)
                    Require(await lease.ExecuteAsync((consumer, _) => ValueTask.FromResult(consumer.Value)) == Value);
                Require(wire.Requests == before);
            }
            Observe("S25", "accepted-generation-reused-without-provider-read-per-operation");
            wire.Status = 403;
            Require((await coordinator.EnableAsync(bound.Token)).Freshness == SecretGenerationFreshness.Stale);
            clock.Advance(TimeSpan.FromSeconds(11));
            Require(coordinator.Acquire() is null);
            Observe("S07", "selected-coordinator-bounds-and-expiry");
#endif
#if HOSTING
            wire.Status = 200;
            foreach (string origin in new[] { "https://selected.invalid", "http://127.0.0.1",
                "http://selected.invalid", "https://selected.invalid/path" })
            {
                var services = new ServiceCollection();
                bool acquired = false;
                services.AddSecretKitInfisical(options =>
                {
                    options.Runtime = Options(new()
                    {
                        AllowLoopbackDevelopmentHttp = origin == "http://127.0.0.1"
                    }, clock, new(origin));
                    options.ClientSecret = _ =>
                    {
                        acquired = true;
                        return ValueTask.FromResult(SecretMaterial.FromText("unrequested"));
                    };
                });
                await using var provider = services.BuildServiceProvider();
                bool valid = true;
                try { _ = provider.GetRequiredService<IOptionsMonitor<InfisicalHostingOptions>>().CurrentValue; }
                catch (OptionsValidationException) { valid = false; }
                Require(valid == (origin is "https://selected.invalid" or "http://127.0.0.1") && !acquired);
            }
            Observe("S08", "hosting-origin-validation-without-acquisition");
            var owners = new ServiceCollection();
            owners.AddSecretKitInfisical(options =>
            {
                options.Runtime = Options(network, clock);
                options.ClientSecret = _ => ValueTask.FromResult(SecretMaterial.FromText("unrequested"));
            });
            await using var host = owners.BuildServiceProvider();
            var original = host.GetRequiredService<InfisicalRuntimeSession>();
            var mutable = host.GetRequiredService<IOptionsMonitor<InfisicalHostingOptions>>().CurrentValue;
            Require(ReferenceEquals(original, host.GetRequiredService<InfisicalRuntimeSession>()) &&
                !original.IsAuthenticated);
            mutable.Runtime = new()
            {
                Origin = new("https://replacement.invalid"), ClientId = "replacement-client",
                ProjectId = Project, Lifetime = InfisicalTokenLifetime.Finite,
                OriginalIssuedAt = clock.GetUtcNow(), TimeProvider = clock, Network = network
            };
            Require((await original.EnsureAuthenticatedAsync(bound.Token)).IsSuccess &&
                wire.LoginClient == "selected-client");
            Observe("S09", "resolved-owner-survives-options-change-without-principal-replacement");
#endif
            await runtime.StopAsync();
            Require(!wire.Disposed);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                profile = "enterprise-hardening",
                kind = "controlled-installed-offline",
                mode = Mode,
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

    private static InfisicalRuntimeOptions Options(InfisicalNetworkOptions network, Clock clock, Uri? origin = null) => new()
    {
        Origin = origin ?? new("https://selected.invalid"),
        ClientId = "selected-client",
        ProjectId = Project,
        Lifetime = InfisicalTokenLifetime.Finite,
        OriginalIssuedAt = clock.GetUtcNow(),
        RenewBefore = TimeSpan.FromSeconds(10),
        Network = network,
        TimeProvider = clock
    };

    private sealed class Wire : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        internal int Status { get; set; } = 200;
        internal string? Advice { get; set; }
        internal Clock? Clock { get; set; }
        internal bool Disposed { get; private set; }
        internal string Value { get; set; } = InstalledWorkflow.Value;
        internal string? LoginClient { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Requests++;
            Clock?.Advance(TimeSpan.FromSeconds(2));
            string body = SecretBody(value: Value);
            if (request.RequestUri!.AbsolutePath == "/api/v1/auth/universal-auth/login")
            {
                using var input = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                LoginClient = input.RootElement.GetProperty("clientId").GetString();
                body = TokenBody(Token);
            }
            var response = new HttpResponseMessage((HttpStatusCode)Status) { Content = new StringContent(body) };
            if (Advice is not null) response.Headers.TryAddWithoutValidation("Retry-After", Advice);
            return response;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
#if CONFIGURATION
    private sealed class Consumer(string value) : IAsyncDisposable
    {
        internal string Value { get; } = value;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
#endif
}
