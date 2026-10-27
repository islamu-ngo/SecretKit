using System.Text.Json;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecretKit.Core;
using SecretKit.Infisical;
using static InstalledWorkflow;
#if CONFIGURATION
using Microsoft.Extensions.Configuration;
using SecretKit.Extensions.Configuration;
#endif
#if HOSTING
using SecretKit.Extensions.Hosting;
#endif

// Package-only evidence. Native execution is a separate explicit entry point.
internal static class RuntimeHardeningWorkflow
{
    internal static Task<int> RunNativeAsync(string report)
    {
#if CONFIGURATION && HOSTING
        return NativeRuntimeHardening.RunAsync(report);
#else
        Console.Error.WriteLine("Runtime hardening native requires the full consumer.");
        return Task.FromResult(2);
#endif
    }

    internal static async Task<int> RunAsync()
    {
        try
        {
            foreach (string transport in new[] { "SafeDefault", "HostControlled" })
                await ExecuteAsync(transport);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                record = "REPORT", schemaVersion = 1, profile = "runtime-hardening",
                packageProfile = "infisical-runtime", kind = "controlled-installed-offline",
                nativeQualified = false, mode = Mode, transports = new[] { "SafeDefault", "HostControlled" }
            }));
            return 0;
        }
        catch
        {
            Console.Error.WriteLine("Runtime hardening workflow failed; protected diagnostics withheld.");
            return 1;
        }
    }

    private static async Task ExecuteAsync(string transport)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var wire = new Loopback(deadline.Token);
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, UseProxy = false, ActivityHeadersPropagator = null
        };
        var network = new InfisicalNetworkOptions
        {
            AllowLoopbackDevelopmentHttp = true,
            ShutdownTimeout = TimeSpan.FromSeconds(2),
            Transport = transport == "SafeDefault" ? InfisicalTransportOptions.SafeDefault :
                InfisicalTransportOptions.HostControlled(handler)
        };
        var clock = new Clock();
        using var authentication = new InfisicalUniversalAuthentication(wire.Origin, network, clock);
        using var credential = SecretMaterial.FromText("runtime-hardening-bootstrap-canary");
        using InfisicalUniversalLogin login = await Login(Token);
        await using var session = Session(login);
        await using var client = new InfisicalClient(wire.Origin, session, network, clock);
        SecretReference reference = Reference(client);
        using InfisicalSecretRead initial = (await Read(200, SecretBody())).Value;
        Require(initial.Material.Reveal() == Value);
        Observe("RH01");
        Require((await Read(403, "{}")).Status == SecretStatus.Denied);
        Require((await Read(200, SecretBody(project: "foreign-project-canary"))).Status == SecretStatus.Invalid);
        Observe("RH04");

#if CONFIGURATION
        using var loader = new SecretSnapshotLoader([new SecretSelection("required", client, reference)], clock);
        Require((await wire.Exchange(() => loader.RefreshAsync(deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 200, SecretBody(), Token)).IsSuccess);
        using SecretSnapshotHandle old = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(old,
            [new SecretConfigurationMapping("required", "Application:Value")]);
        IConfigurationRoot configuration = new ConfigurationBuilder().Add(export).Build();
        using var configurationOwner = (IDisposable)configuration;
        Require(old.Generation == 1 && configuration["Application:Value"] == Value);
        Observe("RH02");
        Require((await wire.Exchange(() => loader.RefreshAsync(deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 200, SecretBody(version: 2, value: "replacement-canary"),
            Token)).Value == 2);
        using SecretSnapshotHandle next = loader.Acquire();
        export.ReplaceAcknowledgingManagedStrings(next);
        using (SecretRead pinned = old.Read("required")) Require(pinned.Material.Reveal() == Value);
        Require(next.Generation == 2 && configuration["Application:Value"] == "replacement-canary");
        Require((await wire.Exchange(() => loader.RefreshAsync(deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 403, "{}", Token)).Status == SecretStatus.Denied);
        using (SecretSnapshotHandle retained = loader.Acquire()) Require(retained.Generation == 2);
        Observe("RH03");
#endif
        clock.Advance(TimeSpan.FromSeconds(20));
        Require(await wire.Exchange(() => session.RenewAsync(deadline.Token).AsTask(),
            "POST", "/api/v1/auth/token/renew", 200, TokenBody("renewed-canary"), null,
            body => body.GetProperty("accessToken").GetString() == Token) == SecretStatus.Success);
        Require(session.LastRenewal?.Evidence == InfisicalRenewalEvidence.Applied);
        using (InfisicalAccessToken renewed = (await session.GetTokenAsync(deadline.Token)).Value)
            Require(renewed.Material.Reveal() == "renewed-canary");
        Observe("RH05");
        clock.Advance(TimeSpan.FromSeconds(20));
        Require(await wire.Exchange(() => session.RenewAsync(deadline.Token).AsTask(),
            "POST", "/api/v1/auth/token/renew", 200, "{}", null,
            body => body.GetProperty("accessToken").GetString() == "renewed-canary",
            loseResponse: true) == SecretStatus.RecoveryRequired);
        Require(session.LastRenewal?.Evidence == InfisicalRenewalEvidence.PossiblyDispatched &&
            (await session.GetTokenAsync(deadline.Token)).Status == SecretStatus.RecoveryRequired);
        // Recovery is a new explicit login, never replay of the uncertain renewal.
        using InfisicalUniversalLogin recoveredLogin = await Login("recovered-canary");
        await using var recovered = Session(recoveredLogin);
        await using var recoveredClient = new InfisicalClient(wire.Origin, recovered, network, clock);
        using InfisicalSecretRead recoveredRead = (await wire.Exchange(
            () => recoveredClient.ReadNativeAsync(Reference(recoveredClient), deadline.Token).AsTask(),
            "GET", "/api/v4/secrets/" + Key, 200, SecretBody(), "recovered-canary")).Value;
        Require(recoveredRead.Material.Reveal() == Value && initial.Material.Reveal() == Value);
        Observe("RH06");
#if HOSTING
        await using var maintenance = new InfisicalAuthenticationMaintenance(recovered, TimeSpan.FromSeconds(2));
        Require(maintenance.State == AuthenticationMaintenanceState.NotStarted);
        await maintenance.StartAsync(deadline.Token);
        Require(maintenance.State == AuthenticationMaintenanceState.Ready);
        await maintenance.StopAsync(deadline.Token).WaitAsync(deadline.Token);
        Require(maintenance.State == AuthenticationMaintenanceState.Stopped);
        Observe("RH09");
#endif
        await recoveredClient.DisposeAsync().AsTask().WaitAsync(deadline.Token);
        await client.DisposeAsync().AsTask().WaitAsync(deadline.Token);
        await session.StopAsync().WaitAsync(deadline.Token);
        await recovered.StopAsync().WaitAsync(deadline.Token);
        Require(session.State == InfisicalTokenSessionState.Stopped &&
            recovered.State == InfisicalTokenSessionState.Stopped);
        await VerifyBoundedShutdown(wire.Origin, network, deadline.Token);
        Observe("RH07");
        if (transport == "HostControlled")
        {
            using var host = new HttpClient(handler, disposeHandler: false);
            using var response = await wire.Exchange(() => host.GetAsync(wire.Origin, deadline.Token),
                "GET", "/", 200, "{}", null);
            Require(response.IsSuccessStatusCode);
        }
        Observe("RH08");

        void Observe(string id) => Console.WriteLine(JsonSerializer.Serialize(new
        {
            record = "SCENARIO", schemaVersion = 1, profile = "runtime-hardening", mode = Mode,
            transport, id, status = "passed", reason = "controlled-observed", nativeQualified = false
        }));
        Task<SecretOutcome<InfisicalSecretRead>> Read(int status, string body) =>
            wire.Exchange(() => client.ReadNativeAsync(reference, deadline.Token).AsTask(),
                "GET", "/api/v4/secrets/" + Key, status, body, Token);
        async Task<InfisicalUniversalLogin> Login(string issued)
        {
            InfisicalUniversalLoginReceipt receipt = authentication.CreateReceipt();
            var outcome = await wire.Exchange(() => authentication.LoginAsync("controlled-client", credential,
                receipt, cancellationToken: deadline.Token).AsTask(),
                "POST", "/api/v1/auth/universal-auth/login", 200, TokenBody(issued), null,
                body => body.GetProperty("clientSecret").GetString() == "runtime-hardening-bootstrap-canary");
            Require(outcome.IsSuccess && receipt.Evidence == DispatchEvidence.Applied);
            return outcome.Value;
        }
        InfisicalPeriodicTokenSession Session(InfisicalUniversalLogin issued) =>
            new(issued, issued.BindLifetimeEvidence(new()
            {
                OriginalIssuedAt = clock.GetUtcNow(), ExpiresAt = issued.Token.ExpiresAt!.Value,
                Lifetime = InfisicalTokenLifetime.Finite, ReportedMaximumTtl = TimeSpan.FromSeconds(120)
            }), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), network, clock);
    }

    internal static async Task VerifyBoundedShutdown(Uri origin, InfisicalNetworkOptions network, CancellationToken token)
    {
        using var source = new HeldTokens();
        var client = new InfisicalClient(origin, source, network);
        Task<SecretOutcome<InfisicalSecretRead>> read = client.ReadNativeAsync(Reference(client)).AsTask();
        await source.Entered.Task.WaitAsync(token);
        Task stop = client.DisposeAsync().AsTask();
        try
        {
            await source.CallbackEntered.Task.WaitAsync(token);
            bool timedOut = false;
            try { await stop.WaitAsync(token); }
            catch (TimeoutException) { timedOut = true; }
            Require(timedOut);
        }
        finally
        {
            source.Release.Set();
            source.Complete.TrySetResult();
        }
        try { using var unexpected = (await read.WaitAsync(token)).Value; Require(false); }
        catch (OperationCanceledException) { }
        await source.CallbackExited.Task.WaitAsync(token);
        // The same public outcome remains timed out after retained cleanup proceeds.
        try { await client.DisposeAsync(); Require(false); }
        catch (TimeoutException) { }
    }

    private sealed class HeldTokens : IInfisicalTokenSource, IDisposable
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource CallbackEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource CallbackExited { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Complete { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ManualResetEventSlim Release { get; } = new();
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            using CancellationTokenRegistration registration = token.Register(() =>
            {
                CallbackEntered.TrySetResult();
                Release.Wait();
                CallbackExited.TrySetResult();
            });
            Entered.TrySetResult();
            await Complete.Task;
            token.ThrowIfCancellationRequested();
            return SecretOutcome<InfisicalAccessToken>.Failure(SecretStatus.Unavailable);
        }
        public void Dispose() => Release.Dispose();
    }
}

#if CONFIGURATION && HOSTING
// No setup/admin/supplied-token surface exists here. All native operations use
// the initial fresh runtime login or the separately supplied same-identity recovery.
internal sealed class NativeRuntimeHardening
{
    private static readonly string[] Ids = ["RH01", "RH02", "RH03", "RH04", "RH05", "RH06", "RH07", "RH08", "RH09"];
    private readonly NativeRuntimeInput _input;
    private readonly string _path;
    private NativeRuntimeReport _report;
    private string _current = "RH01";
    private bool _created;

    private NativeRuntimeHardening(NativeRuntimeInput input, string path)
    {
        _input = input;
        _path = path;
        _report = new(1, "REPORT", "runtime-hardening", "native-observation-not-public-approval",
            input.SelectionSha256, input.RunId, null, null, null, null, false,
            Ids.Select(id => new LocalNativeCase(id, "unavailable", "not-observed")).ToArray());
    }

    internal static async Task<int> RunAsync(string path)
    {
        NativeRuntimeHardening? run = null;
        try
        {
            Require(Path.IsPathFullyQualified(path) && !File.Exists(path) && !Directory.Exists(path));
            using var admission = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            byte[] bytes = await NativeWorkflow.ReadBoundedAsync(Console.OpenStandardInput(), admission.Token);
            NativeRuntimeInput input;
            try { input = NativeRuntimeInput.Parse(bytes); }
            finally { Array.Clear(bytes); }
            run = new(input, path);
            await run.Persist(create: true);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(input.DeadlineSeconds));
            await run.Execute(deadline.Token);
            run._report = run._report with { ExecutionCompleted = true };
            await run.Persist();
            Console.WriteLine(JsonSerializer.Serialize(run._report, NativeWorkflow.JsonOptions));
            return run._report.Cases.All(c => c.Status == "passed") &&
                input.Policy.GetProperty("evidence").GetString() == "provider-observed" ? 0 : 1;
        }
        catch
        {
            if (run is { _created: true })
            {
                try
                {
                    run._report = run._report with { ExecutionCompleted = false };
                    int index = Array.IndexOf(Ids, run._current);
                    if (run._report.Cases[index].Status != "passed")
                        run._report.Cases[index] = new(run._current, "unavailable", "observation-unavailable");
                    await run.Persist();
                    Console.WriteLine(JsonSerializer.Serialize(run._report, NativeWorkflow.JsonOptions));
                }
                catch { /* The last atomically persisted partial record remains authoritative. */ }
            }
            Console.Error.WriteLine("Runtime hardening native unqualified.");
            return 1;
        }
    }

    private async Task Execute(CancellationToken token)
    {
        using var pipeline = new NativeRuntimePipeline(_input);
        using var policyClient = new HttpClient(pipeline, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
        X509Certificate2[] roots = _input.Roots();
        try
        {
            var selected = new InfisicalNetworkOptions
            {
                MaximumResponseBytes = 131072, ShutdownTimeout = TimeSpan.FromSeconds(2),
                Proxy = _input.Mode == "HostControlled" ? null : _input.Proxy(),
                Transport = _input.Mode switch
                {
                    "SafeDefault" => InfisicalTransportOptions.SafeDefault,
                    "SafeWithPrivateTrust" => InfisicalTransportOptions.SafeWithPrivateTrust(roots),
                    _ => InfisicalTransportOptions.HostControlled(pipeline)
                }
            };
            using var auth = new InfisicalUniversalAuthentication(_input.Origin, selected);
            using InfisicalUniversalLogin login = await Login(auth, _input.Bootstrap, token);
            _report = _report with { FreshLoginRun = _input.RunId };
            await Persist();
            var observed = await ObservePolicy(policyClient, login, _input.Bootstrap, token);
            _report = _report with { ObservedPolicy = observed, PolicyObservationSha256 = NativeRuntimeInput.PolicyHash(observed) };
            await Persist();
            Require(_report.PolicyObservationSha256 == _input.Policy.GetProperty("evidenceSha256").GetString());
            await using var session = Session(login, selected);
            using (InfisicalAccessToken handed = (await session.GetTokenAsync(token)).Value)
                Require(Equal(handed.Material, login.Token.Material));
            await using var client = new InfisicalClient(_input.Origin, session, selected);
            var references = _input.Reads.Select(r => Select(client, r)).ToArray();
            using InfisicalSecretRead initial = await Read(client, references[0], token);
            _report = _report with { CausalTokenHandoffRun = _input.RunId };
            await Passed("RH01");

            _current = "RH02";
            var requiredReader = new NativeRuntimeReader(client, _input.RequestTimeout);
            using var loader = new SecretSnapshotLoader(references.Select((reference, i) =>
                new SecretSelection("required-" + i.ToString(CultureInfo.InvariantCulture), requiredReader, reference)));
            Require((await loader.RefreshAsync(token)).Value == 1);
            using var old = loader.Acquire();
            using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(old, references.Select((_, i) =>
                new SecretConfigurationMapping("required-" + i.ToString(CultureInfo.InvariantCulture),
                    "Required:" + i.ToString(CultureInfo.InvariantCulture))));
            IConfigurationRoot configuration = new ConfigurationBuilder().Add(export).Build();
            using var rootOwner = (IDisposable)configuration;
            for (int i = 0; i < references.Length; i++)
            {
                using var read = old.Read("required-" + i.ToString(CultureInfo.InvariantCulture));
                Require(configuration["Required:" + i.ToString(CultureInfo.InvariantCulture)] == read.Material.Reveal());
            }
            using var pinnedCopy = old.Read("required-0");
            await Passed("RH02");

            _current = "RH03";
            Require((await loader.RefreshAsync(token)).Value == 2);
            using var next = loader.Acquire();
            export.ReplaceAcknowledgingManagedStrings(next);
            using (var pinned = old.Read("required-0"))
                Require(old.Generation == 1 && next.Generation == 2 && Equal(pinned.Material, pinnedCopy.Material));
            for (int i = 0; i < references.Length; i++)
            {
                using var read = next.Read("required-" + i.ToString(CultureInfo.InvariantCulture));
                Require(configuration["Required:" + i.ToString(CultureInfo.InvariantCulture)] == read.Material.Reveal());
            }
            requiredReader.RefuseLocally = true;
            Require((await loader.RefreshAsync(token)).Status == SecretStatus.Unavailable);
            using (var retained = loader.Acquire()) Require(retained.Generation == 2);
            using (var retained = next.Read("required-0"))
                Require(configuration["Required:0"] == retained.Material.Reveal());
            await Passed("RH03");

            _current = "RH04";
            await Refused(client, _input.Denied, token);
            await Refused(client, _input.CrossScope, token);
            await Passed("RH04");

            _current = "RH05";
            await RenewalWindow(session, token);
            SecretStatus renewedStatus;
            try { renewedStatus = await session.RenewAsync(token); }
            finally
            {
                _report = _report with { RenewalEvidence = RenewalEvidence(session.LastRenewal) };
                await Persist();
            }
            Require(renewedStatus == SecretStatus.Success &&
                session.LastRenewal?.Evidence == InfisicalRenewalEvidence.Applied);
            using InfisicalAccessToken renewed = (await session.GetTokenAsync(token)).Value;
            Require(renewed.ExpiresAt is not null);
            using (var usable = await Read(client, references[0], token)) { }
            await Passed("RH05");

            _current = "RH06";
            // A separately acknowledged, fixed validating pipeline loses exactly
            // one real successful renewal response. Safe-mode SDK clients above
            // remain SDK-safe; this fault trial is explicitly host-controlled.
            using var lossPipeline = new NativeRuntimePipeline(_input);
            var lossNetwork = new InfisicalNetworkOptions
            {
                Transport = InfisicalTransportOptions.HostControlled(lossPipeline),
                MaximumResponseBytes = 131072, ShutdownTimeout = TimeSpan.FromSeconds(2)
            };
            await using var lossSession = new InfisicalPeriodicTokenSession(_input.Origin, renewed.Material,
                Evidence(login, renewed.ExpiresAt!.Value), _input.RenewBefore, _input.RequestTimeout, lossNetwork);
            await session.StopAsync().WaitAsync(token);
            await RenewalWindow(lossSession, token);
            lossPipeline.ArmLoss();
            SecretStatus lossStatus;
            try { lossStatus = await lossSession.RenewAsync(token); }
            finally
            {
                _report = _report with
                {
                    LossEvidence = RenewalEvidence(lossSession.LastRenewal),
                    ResponseLossObserved = lossPipeline.Dropped
                };
                await Persist();
            }
            Require(lossStatus == SecretStatus.RecoveryRequired &&
                lossPipeline.Dropped && lossSession.LastRenewal?.Evidence == InfisicalRenewalEvidence.PossiblyDispatched &&
                (await lossSession.GetTokenAsync(token)).Status == SecretStatus.RecoveryRequired);
            _report = _report with { RecoveryRequiredObserved = true };
            await Persist();
            using InfisicalUniversalLogin recovery = await Login(auth, _input.Recovery, token, recovery: true);
            var recoveryPolicy = await ObservePolicy(policyClient, recovery, _input.Recovery, token);
            Require(recoveryPolicy == observed);
            await using var recovered = Session(recovery, selected);
            using (var handoff = (await recovered.GetTokenAsync(token)).Value)
                Require(Equal(handoff.Material, recovery.Token.Material));
            await using var recoveredClient = new InfisicalClient(_input.Origin, recovered, selected);
            using (var usable = await Read(recoveredClient, Select(recoveredClient, _input.Reads[0]), token)) { }
            _report = _report with { RecoveryReadObserved = true };
            await Passed("RH06");

            _current = "RH09";
            await using var maintenance = new InfisicalAuthenticationMaintenance(recovered, TimeSpan.FromSeconds(2));
            Require(maintenance.State == AuthenticationMaintenanceState.NotStarted);
            await maintenance.StartAsync(token);
            Require(maintenance.State is AuthenticationMaintenanceState.Ready or AuthenticationMaintenanceState.RenewalDue or
                AuthenticationMaintenanceState.Renewing);
            await maintenance.StopAsync(token).WaitAsync(token);
            Require(maintenance.State == AuthenticationMaintenanceState.Stopped &&
                recovered.State == InfisicalTokenSessionState.Stopped);
            await Passed("RH09");

            _current = "RH07";
            await client.DisposeAsync().AsTask().WaitAsync(token);
            await recoveredClient.DisposeAsync().AsTask().WaitAsync(token);
            await lossSession.StopAsync().WaitAsync(token);
            Require(session.State == InfisicalTokenSessionState.Stopped &&
                lossSession.State == InfisicalTokenSessionState.Stopped);
            await RuntimeHardeningWorkflow.VerifyBoundedShutdown(_input.Origin, selected, token);
            await Passed("RH07");

            _current = "RH08";
            auth.Dispose();
            // This is the same fixed own-identity GET, not a generic health probe.
            // It proves the host-owned policy/selected pipeline survived SDK disposal.
            Require(await ObservePolicy(policyClient, recovery, _input.Recovery, token) == observed);
            using var lossHost = new HttpClient(lossPipeline, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
            Require(await ObservePolicy(lossHost, recovery, _input.Recovery, token) == observed);
            await Passed("RH08");
        }
        finally { foreach (var root in roots) root.Dispose(); }
    }

    private async Task<InfisicalUniversalLogin> Login(InfisicalUniversalAuthentication auth, JsonElement bootstrap,
        CancellationToken token, bool recovery = false)
    {
        using var material = SecretMaterial.FromText(bootstrap.GetProperty("clientSecret").GetString()!);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(_input.RequestTimeout);
        var receipt = auth.CreateReceipt();
        SecretOutcome<InfisicalUniversalLogin> result;
        InfisicalUniversalLogin? acquired = null;
        try
        {
            result = await auth.LoginAsync(bootstrap.GetProperty("clientId").GetString()!, material, receipt,
                cancellationToken: deadline.Token);
            if (result.IsSuccess) acquired = result.Value;
        }
        finally
        {
            string evidence = receipt.Evidence switch
            {
                DispatchEvidence.NotDispatched => "not-dispatched", DispatchEvidence.Applied => "applied",
                DispatchEvidence.Rejected => "rejected", _ => "possibly-dispatched"
            };
            _report = recovery ? _report with { RecoveryLoginEvidence = evidence } : _report with { LoginEvidence = evidence };
            try { await Persist(); }
            catch { acquired?.Dispose(); throw; }
        }
        Require(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied);
        var login = result.Value;
        try
        {
            Require(login.ExpiresIn == _input.Ttl && login.AccessTokenMaxTTL == _input.MaximumTtl);
            return login;
        }
        catch { login.Dispose(); throw; }
    }

    private async Task<NativeRuntimePolicy> ObservePolicy(HttpClient client, InfisicalUniversalLogin login,
        JsonElement bootstrap, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(_input.RequestTimeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, _input.PolicyUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", login.Token.Material.Reveal());
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        Require(response.StatusCode == HttpStatusCode.OK);
        using Stream stream = await response.Content.ReadAsStreamAsync(deadline.Token);
        byte[] bytes = await NativeWorkflow.ReadBoundedAsync(stream, deadline.Token);
        try
        {
            using var json = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
            NativeRuntimeInput.Unique(json.RootElement);
            var config = json.RootElement.GetProperty("identityUniversalAuth");
            Require(config.GetProperty("identityId").GetString() == bootstrap.GetProperty("identityId").GetString() &&
                config.GetProperty("clientId").GetString() == bootstrap.GetProperty("clientId").GetString());
            // Missing, fractional, string-valued or contradictory fields never
            // become inferred zeroes, host declarations, or a supplied digest.
            var policy = new NativeRuntimePolicy(config.GetProperty("accessTokenTTL").GetInt32(),
                config.GetProperty("accessTokenMaxTTL").GetInt32(), config.GetProperty("accessTokenNumUsesLimit").GetInt32(),
                config.GetProperty("accessTokenPeriod").GetInt32());
            Require(policy.TtlSeconds == _input.Ttl && policy.MaximumTtlSeconds == _input.MaximumTtl &&
                policy.UseLimit == 0 && policy.PeriodSeconds == _input.Period);
            return policy;
        }
        finally { Array.Clear(bytes); }
    }

    private InfisicalTokenLifetimeEvidence Evidence(InfisicalUniversalLogin login, DateTimeOffset expiry) => new()
    {
        OriginalIssuedAt = login.RequestStartedAt, ExpiresAt = expiry,
        Lifetime = _input.Period == 0 ? InfisicalTokenLifetime.Finite : InfisicalTokenLifetime.Periodic,
        Period = _input.Period == 0 ? null : TimeSpan.FromSeconds(_input.Period),
        ReportedMaximumTtl = TimeSpan.FromSeconds(_input.MaximumTtl)
    };
    private InfisicalPeriodicTokenSession Session(InfisicalUniversalLogin login, InfisicalNetworkOptions network) =>
        new(login, login.BindLifetimeEvidence(Evidence(login, login.Token.ExpiresAt!.Value)),
            _input.RenewBefore, _input.RequestTimeout, network);
    private static async Task RenewalWindow(InfisicalPeriodicTokenSession session, CancellationToken token)
    {
        TimeSpan remaining = session.RenewalDueAt - DateTimeOffset.UtcNow;
        // Round up rather than truncating a sub-millisecond remainder before
        // the actual due time. This is the native renewal window, not a test sleep.
        if (remaining > TimeSpan.Zero)
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Ceiling(remaining.TotalMilliseconds)), TimeProvider.System, token);
        Require(session.State == InfisicalTokenSessionState.RenewalDue);
    }
    private static string RenewalEvidence(InfisicalTokenRenewal? receipt) => receipt?.Evidence switch
    {
        null or InfisicalRenewalEvidence.NotDispatched => "not-dispatched",
        InfisicalRenewalEvidence.Applied => "applied",
        InfisicalRenewalEvidence.Rejected => "rejected",
        _ => "possibly-dispatched"
    };
    private async Task<InfisicalSecretRead> Read(InfisicalClient client, SecretReference reference, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(_input.RequestTimeout);
        var outcome = await client.ReadNativeAsync(reference, deadline.Token);
        Require(outcome.IsSuccess);
        return outcome.Value;
    }
    private async Task Refused(InfisicalClient client, JsonElement coordinate, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(_input.RequestTimeout);
        var outcome = await client.ReadNativeAsync(Select(client, coordinate), deadline.Token);
        if (outcome.IsSuccess) outcome.Value.Dispose();
        Require(outcome.Status == SecretStatus.Denied);
    }
    private static SecretReference Select(InfisicalClient client, JsonElement coordinate) =>
        new(client.Authority, new InfisicalSecretAddress(coordinate.GetProperty("projectId").GetString()!,
            coordinate.GetProperty("environment").GetString()!, coordinate.GetProperty("folder").GetString()!,
            coordinate.GetProperty("key").GetString()!));
    private static bool Equal(SecretMaterial left, SecretMaterial right)
    {
        char[] first = left.ExportCharacters(), second = right.ExportCharacters();
        try { return first.AsSpan().SequenceEqual(second); }
        finally { Array.Clear(first); Array.Clear(second); }
    }
    private async Task Passed(string id)
    {
        _report.Cases[Array.IndexOf(Ids, id)] = new(id, "passed", "observed");
        await Persist();
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            schemaVersion = 1, record = "SCENARIO", profile = "runtime-hardening",
            runId = _input.RunId, id, status = "passed", reason = "observed"
        }));
    }
    private async Task Persist(bool create = false)
    {
        string destination = create ? _path : _path + ".tmp";
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.Read
        };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using (var stream = new FileStream(destination, options))
            await JsonSerializer.SerializeAsync(stream, _report, NativeWorkflow.JsonOptions);
        if (!create) File.Move(destination, _path, overwrite: true);
        else _created = true;
    }
    public override string ToString() => "[NativeRuntimeHardening]";
}

internal sealed class NativeRuntimeReader(InfisicalClient client, TimeSpan requestTimeout) : ISecretReader
{
    internal bool RefuseLocally { get; set; }
    public SecretAuthority Authority => client.Authority;
    public async ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (RefuseLocally) return SecretOutcome<SecretRead>.Failure(SecretStatus.Unavailable);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(requestTimeout);
        return await client.ReadAsync(reference, deadline.Token);
    }
    public override string ToString() => "[NativeRuntimeReader]";
}

internal sealed record NativeRuntimePolicy(int TtlSeconds, int MaximumTtlSeconds, int UseLimit, int PeriodSeconds)
{
    public override string ToString() => "[NativeRuntimePolicy]";
}
internal sealed record NativeRuntimeReport(int SchemaVersion, string Record, string Profile, string Kind,
    string SelectionSha256, string RunId, string? FreshLoginRun, string? CausalTokenHandoffRun,
    string? PolicyObservationSha256, NativeRuntimePolicy? ObservedPolicy, bool ExecutionCompleted, LocalNativeCase[] Cases)
{
    [System.Text.Json.Serialization.JsonRequired] public string LoginEvidence { get; init; } = "not-dispatched";
    [System.Text.Json.Serialization.JsonRequired] public string RenewalEvidence { get; init; } = "not-dispatched";
    [System.Text.Json.Serialization.JsonRequired] public string LossEvidence { get; init; } = "not-dispatched";
    [System.Text.Json.Serialization.JsonRequired] public bool ResponseLossObserved { get; init; }
    [System.Text.Json.Serialization.JsonRequired] public bool RecoveryRequiredObserved { get; init; }
    [System.Text.Json.Serialization.JsonRequired] public string RecoveryLoginEvidence { get; init; } = "not-dispatched";
    [System.Text.Json.Serialization.JsonRequired] public bool RecoveryReadObserved { get; init; }
    public override string ToString() => "[NativeRuntimeReport]";
}

// This file is compiled in the isolated four-package consumer, not linked to the
// conformance host. Re-admit the protected process boundary without a fifth package.
internal sealed class NativeRuntimeInput
{
    internal required JsonElement Selection { get; init; }
    internal required JsonElement Input { get; init; }
    internal required string RunId { get; init; }
    internal string SelectionSha256 => Input.GetProperty("selectionSha256").GetString()!;
    internal JsonElement Policy => Selection.GetProperty("policy");
    internal JsonElement Network => Selection.GetProperty("network");
    internal JsonElement Bootstrap => Input.GetProperty("bootstrap");
    internal JsonElement Recovery => Input.GetProperty("recoveryBootstrap");
    internal JsonElement[] Reads => Input.GetProperty("allowedReads").EnumerateArray().ToArray();
    internal JsonElement Denied => Input.GetProperty("deniedRead");
    internal JsonElement CrossScope => Input.GetProperty("crossScopeRead");
    internal Uri Origin => new(Network.GetProperty("origin").GetString()!);
    internal Uri PolicyUri => new(Origin, "/api/v1/auth/universal-auth/identities/" +
        Uri.EscapeDataString(Bootstrap.GetProperty("identityId").GetString()!));
    internal string Mode => Network.GetProperty("mode").GetString()!;
    internal int Ttl => Policy.GetProperty("ttlSeconds").GetInt32();
    internal int MaximumTtl => Policy.GetProperty("maximumTtlSeconds").GetInt32();
    internal int Period => Policy.GetProperty("periodSeconds").ValueKind == JsonValueKind.Null ? 0 :
        Policy.GetProperty("periodSeconds").GetInt32();
    internal int DeadlineSeconds => Input.GetProperty("deadlineSeconds").GetInt32();
    internal TimeSpan RenewBefore => TimeSpan.FromSeconds(Policy.GetProperty("renewBeforeSeconds").GetInt32());
    internal TimeSpan RequestTimeout => TimeSpan.FromSeconds(Policy.GetProperty("requestTimeoutSeconds").GetInt32());
    internal IWebProxy? Proxy() => Input.GetProperty("proxyUri").ValueKind == JsonValueKind.Null ? null :
        new WebProxy(new Uri(Input.GetProperty("proxyUri").GetString()!)) { BypassProxyOnLocal = false };
    internal X509Certificate2[] Roots() => Input.GetProperty("publicRootsDer").EnumerateArray()
        .Select(r => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(r.GetString()!))).ToArray();

    internal static NativeRuntimeInput Parse(byte[] bytes)
    {
        Require(bytes.Length is > 0 and <= 131072);
        using var json = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
        Unique(json.RootElement);
        Closed(json.RootElement, "schemaVersion", "profile", "runId", "selection", "input");
        Require(json.RootElement.GetProperty("schemaVersion").GetInt32() == 1 &&
            json.RootElement.GetProperty("profile").GetString() == "runtime-hardening");
        var result = new NativeRuntimeInput
        {
            Selection = json.RootElement.GetProperty("selection").Clone(),
            Input = json.RootElement.GetProperty("input").Clone(),
            RunId = json.RootElement.GetProperty("runId").GetString()!
        };
        result.Validate();
        return result;
    }

    private void Validate()
    {
        Closed(Selection, "schemaVersion", "profile", "packageProfile", "authority", "binding", "provider", "policy", "network");
        Closed(Input, "schemaVersion", "profile", "selectionSha256", "authority", "readAuthority", "bootstrap",
            "recoveryBootstrap", "allowedReads", "deniedRead", "crossScopeRead", "acknowledgeManagedStringExport",
            "acknowledgeResponseLoss", "publicRootsDer", "proxyUri", "responseLossPipelineSha256", "deadlineSeconds");
        Require(Guid.TryParseExact(RunId, "N", out _) && Selection.GetProperty("schemaVersion").GetInt32() == 1 &&
            Selection.GetProperty("profile").GetString() == "runtime-hardening" &&
            Selection.GetProperty("packageProfile").GetString() == "infisical-runtime" &&
            Selection.GetProperty("authority").GetString() == "selected-runtime-read-login-renew" &&
            Input.GetProperty("schemaVersion").GetInt32() == 1 && Input.GetProperty("profile").GetString() == "runtime-hardening" &&
            Input.GetProperty("authority").GetString() == "selected-runtime-read-login-renew" &&
            Input.GetProperty("readAuthority").GetString() == "owned-read-fixtures" &&
            Input.GetProperty("acknowledgeManagedStringExport").GetBoolean() &&
            Input.GetProperty("acknowledgeResponseLoss").GetBoolean() &&
            Hash(JsonSerializer.SerializeToUtf8Bytes(Selection, NativeWorkflow.JsonOptions)) == SelectionSha256);
        JsonElement binding = Selection.GetProperty("binding");
        Closed(binding, "archives", "sourceRevision", "sdk", "runtime", "platform");
        NativeWorkflow.ValidateBinding(binding.GetProperty("archives").Deserialize<LocalNativeBinding>(NativeWorkflow.JsonOptions)!);
        Require(Hex(binding.GetProperty("sourceRevision").GetString(), 40) &&
            Version.TryParse(binding.GetProperty("sdk").GetString(), out var sdk) && sdk.Major == 10 && sdk.Build >= 0 &&
            binding.GetProperty("runtime").GetString() == Environment.Version.ToString() && Environment.Version.Major == 10 &&
            binding.GetProperty("platform").GetString() == "linux-x64" && OperatingSystem.IsLinux() &&
            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64);
        var provider = Selection.GetProperty("provider");
        Closed(provider, "deployment", "version", "edition");
        Require(Text(provider.GetProperty("deployment").GetString(), 256) &&
            Version.TryParse(provider.GetProperty("version").GetString(), out _) &&
            provider.GetProperty("edition").GetString() is "oss" or "enterprise" or "cloud");
        Closed(Policy, "lifetime", "ttlSeconds", "maximumTtlSeconds", "periodSeconds", "useLimit",
            "renewBeforeSeconds", "requestTimeoutSeconds", "evidence", "evidenceSha256");
        Require(Ttl > 10 && MaximumTtl >= 0 && Policy.GetProperty("useLimit").GetInt32() == 0 &&
            RequestTimeout.TotalSeconds is > 0 and <= 60 && RenewBefore > TimeSpan.Zero &&
            RenewBefore.TotalSeconds < Ttl && Ttl > 4 * RequestTimeout.TotalSeconds &&
            DeadlineSeconds is >= 60 and <= 1800 && DeadlineSeconds >= 2L * Ttl + 60 &&
            Hex(Policy.GetProperty("evidenceSha256").GetString(), 64) &&
            Policy.GetProperty("evidence").GetString() is "declared" or "provider-observed" &&
            (Policy.GetProperty("lifetime").GetString() == "finite" &&
                Policy.GetProperty("periodSeconds").ValueKind == JsonValueKind.Null && MaximumTtl >= Ttl ||
             Policy.GetProperty("lifetime").GetString() == "periodic" && Period == Ttl));
        Closed(Network, "origin", "mode", "tls", "proxy", "proxyEvidenceSha256", "privateRootsSha256", "hostPipelineSha256");
        Require(Origin.IsAbsoluteUri && Origin.Scheme == "https" && Origin.UserInfo.Length == 0 &&
            Origin.AbsolutePath == "/" && Origin.Query.Length == 0 && Origin.Fragment.Length == 0 &&
            Mode is "SafeDefault" or "SafeWithPrivateTrust" or "HostControlled" &&
            Network.GetProperty("tls").GetString() == "hostname-validity-chain" &&
            Network.GetProperty("proxy").GetString() is "none" or "explicit");
        string? proxyHash = Network.GetProperty("proxyEvidenceSha256").GetString();
        string? rootsHash = Network.GetProperty("privateRootsSha256").GetString();
        if (Network.GetProperty("proxy").GetString() == "explicit")
        {
            var proxy = new Uri(Input.GetProperty("proxyUri").GetString()!, UriKind.Absolute);
            Require(proxy.Scheme is "http" or "https" && proxy.UserInfo.Length == 0 && proxy.AbsolutePath == "/" &&
                proxy.Query.Length == 0 && proxy.Fragment.Length == 0 &&
                proxyHash == Hash(Encoding.UTF8.GetBytes("runtime-hardening-proxy-v1\n" + proxy.AbsoluteUri + "\n")));
        }
        else Require(proxyHash is null && Input.GetProperty("proxyUri").ValueKind == JsonValueKind.Null);
        var roots = Input.GetProperty("publicRootsDer").EnumerateArray().ToArray();
        if (Mode == "SafeWithPrivateTrust")
        {
            Require(roots.Length is >= 1 and <= 16);
            var hashes = new List<string>();
            foreach (var root in roots)
            {
                byte[] der = Convert.FromBase64String(root.GetString()!);
                Require(der.Length is > 0 and <= 16384);
                using var certificate = X509CertificateLoader.LoadCertificate(der);
                Require(!certificate.HasPrivateKey && certificate.RawData.AsSpan().SequenceEqual(der));
                hashes.Add(Hash(der));
            }
            Require(hashes.Distinct(StringComparer.Ordinal).Count() == hashes.Count &&
                rootsHash == Hash(Encoding.UTF8.GetBytes("runtime-hardening-roots-v1\n" +
                    string.Join("\n", hashes.Order(StringComparer.Ordinal)) + "\n")));
        }
        else Require(roots.Length == 0 && rootsHash is null);
        string pipelineHash = Hash(Encoding.UTF8.GetBytes(
            "runtime-hardening-validating-pipeline-v1\n" + Origin.AbsoluteUri + "\n" +
            (proxyHash ?? "none") + "\n" + (rootsHash ?? "system") + "\n" +
            Policy.GetProperty("requestTimeoutSeconds").GetInt32().ToString(CultureInfo.InvariantCulture) + "\n" +
            "no-redirects;no-cookies;no-ambient-proxy;no-propagation;no-retry;pool-120;chain-hostname-validity;revocation-nocheck;fixed-routes;drop-one-successful-renewal\n" +
            Bootstrap.GetProperty("identityId").GetString() + "\n" +
            string.Join("\n", Reads.Concat([Denied, CrossScope]).Select(Coordinate)) + "\n"));
        Require(Input.GetProperty("responseLossPipelineSha256").GetString() == pipelineHash &&
            (Mode == "HostControlled" ? Network.GetProperty("hostPipelineSha256").GetString() == pipelineHash :
                Network.GetProperty("hostPipelineSha256").ValueKind == JsonValueKind.Null));
        foreach (var bootstrap in new[] { Bootstrap, Recovery })
        {
            Closed(bootstrap, "identityId", "clientId", "clientSecret");
            Require(Guid.TryParseExact(bootstrap.GetProperty("identityId").GetString(), "D", out _) &&
                Credential(bootstrap.GetProperty("clientId").GetString(), 1024) &&
                Credential(bootstrap.GetProperty("clientSecret").GetString(), 16384));
        }
        Require(Bootstrap.GetProperty("identityId").GetString() == Recovery.GetProperty("identityId").GetString() &&
            Bootstrap.GetProperty("clientId").GetString() == Recovery.GetProperty("clientId").GetString() &&
            Bootstrap.GetProperty("clientSecret").GetString() != Recovery.GetProperty("clientSecret").GetString());
        Require(Reads.Length is >= 2 and <= 8 && Reads.Select(Coordinate).Distinct(StringComparer.Ordinal).Count() == Reads.Length);
        foreach (var coordinate in Reads.Concat([Denied, CrossScope]))
        {
            Closed(coordinate, "projectId", "environment", "folder", "key");
            string folder = coordinate.GetProperty("folder").GetString()!;
            Require(Guid.TryParseExact(coordinate.GetProperty("projectId").GetString(), "D", out _) &&
                Segment(coordinate.GetProperty("environment").GetString()) && Segment(coordinate.GetProperty("key").GetString()) &&
                folder.StartsWith('/') && folder.Length <= 512 && (folder == "/" || folder[1..].Split('/').All(Segment)));
        }
        Require(!Reads.Any(r => Coordinate(r) == Coordinate(Denied)) && Coordinate(Denied) != Coordinate(CrossScope) &&
            Reads.All(r => r.GetProperty("projectId").GetString() != CrossScope.GetProperty("projectId").GetString() ||
                r.GetProperty("environment").GetString() != CrossScope.GetProperty("environment").GetString() ||
                r.GetProperty("folder").GetString() != CrossScope.GetProperty("folder").GetString()));
    }

    internal static string PolicyHash(NativeRuntimePolicy p) => Hash(Encoding.UTF8.GetBytes(
        FormattableString.Invariant($"runtime-hardening-universal-policy-v1\n{p.TtlSeconds}\n{p.MaximumTtlSeconds}\n{p.UseLimit}\n{p.PeriodSeconds}\n")));
    private static string Coordinate(JsonElement c) => string.Join("\n", new[] { "projectId", "environment", "folder", "key" }
        .Select(key => c.GetProperty(key).GetString()));
    private static bool Text(string? value, int maximum) => value is { Length: > 0 } &&
        value.Length <= maximum && !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    private static bool Credential(string? value, int maximum) => Text(value, maximum) && value!.All(c => c > ' ' && c < 127);
    private static bool Segment(string? value) => value is { Length: > 0 and <= 128 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');
    private static bool Hex(string? value, int length) => value is not null && value.Length == length &&
        value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static void Closed(JsonElement element, params string[] fields) =>
        Require(element.ValueKind == JsonValueKind.Object &&
            element.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).SequenceEqual(fields.Order(StringComparer.Ordinal)));
    internal static void Unique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject()) { Require(names.Add(property.Name)); Unique(property.Value); }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) Unique(item);
    }
    public override string ToString() => "[NativeRuntimeInput]";
}

internal sealed class NativeRuntimePipeline : DelegatingHandler
{
    private readonly NativeRuntimeInput _input;
    private readonly X509Certificate2[] _roots;
    private int _lose;
    internal bool Dropped { get; private set; }
    internal NativeRuntimePipeline(NativeRuntimeInput input)
    {
        _input = input;
        _roots = input.Roots();
        var sockets = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, UseProxy = input.Proxy() is not null,
            Proxy = input.Proxy(), ActivityHeadersPropagator = null, PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectTimeout = input.RequestTimeout
        };
        if (_roots.Length != 0)
        {
            var chain = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck
            };
            chain.CustomTrustStore.AddRange(_roots);
            sockets.SslOptions.CertificateChainPolicy = chain;
        }
        InnerHandler = sockets;
    }
    internal void ArmLoss()
    {
        Require(!Dropped && Interlocked.CompareExchange(ref _lose, 1, 0) == 0);
    }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Uri uri = request.RequestUri!;
        Require(uri is { IsAbsoluteUri: true } && uri.Scheme == _input.Origin.Scheme &&
            uri.Host == _input.Origin.Host && uri.Port == _input.Origin.Port &&
            uri.UserInfo.Length == 0 && uri.Fragment.Length == 0);
        bool renew = request.Method == HttpMethod.Post && uri.AbsolutePath == "/api/v1/auth/token/renew" && uri.Query.Length == 0;
        bool login = request.Method == HttpMethod.Post && uri.AbsolutePath == "/api/v1/auth/universal-auth/login" && uri.Query.Length == 0;
        bool policy = request.Method == HttpMethod.Get && uri == _input.PolicyUri;
        bool read = request.Method == HttpMethod.Get && AllowedRead(uri);
        Require(renew || login || policy || read);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_input.RequestTimeout);
        HttpResponseMessage response = await base.SendAsync(request, deadline.Token);
        if (!renew || Interlocked.Exchange(ref _lose, 0) == 0) return response;
        using (response)
        {
            Require(response.StatusCode == HttpStatusCode.OK);
            using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
            byte[] bytes = await NativeWorkflow.ReadBoundedAsync(stream, deadline.Token);
            try
            {
                using var json = JsonDocument.Parse(bytes);
                NativeRuntimeInput.Unique(json.RootElement);
                Require(json.RootElement.GetProperty("tokenType").GetString() == "Bearer" &&
                    json.RootElement.GetProperty("accessToken").GetString() is { Length: > 0 and <= 16384 } &&
                    json.RootElement.GetProperty("expiresIn").GetDouble() > _input.RenewBefore.TotalSeconds &&
                    json.RootElement.GetProperty("accessTokenMaxTTL").GetDouble() == _input.MaximumTtl);
                Dropped = true;
            }
            finally { Array.Clear(bytes); }
        }
        throw new HttpRequestException("runtime-hardening-controlled-response-loss");
    }
    private bool AllowedRead(Uri uri)
    {
        var query = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string pair in uri.Query.TrimStart('?').Split('&'))
        {
            string[] parts = pair.Split('=', 2);
            if (parts.Length != 2 || !query.TryAdd(Uri.UnescapeDataString(parts[0]), Uri.UnescapeDataString(parts[1])))
                return false;
        }
        return query.Count == 7 && query.GetValueOrDefault("viewSecretValue") == "true" &&
            query.GetValueOrDefault("type") == "shared" && query.GetValueOrDefault("expandSecretReferences") == "false" &&
            query.GetValueOrDefault("includeImports") == "false" &&
            _input.Reads.Concat([_input.Denied, _input.CrossScope]).Any(c =>
                uri.AbsolutePath == "/api/v4/secrets/" + Uri.EscapeDataString(c.GetProperty("key").GetString()!) &&
                query.GetValueOrDefault("projectId") == c.GetProperty("projectId").GetString() &&
                query.GetValueOrDefault("environment") == c.GetProperty("environment").GetString() &&
                query.GetValueOrDefault("secretPath") == c.GetProperty("folder").GetString());
    }
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) foreach (var root in _roots) root.Dispose();
    }
    public override string ToString() => "[NativeRuntimePipeline]";
}
#endif
