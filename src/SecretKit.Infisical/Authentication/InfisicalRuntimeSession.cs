using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Explicit owner of one native client and token session, without bootstrap retention or automatic maintenance.</summary>
public sealed class InfisicalRuntimeSession : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly TimeSpan _shutdownTimeout;
    private readonly TimeProvider _time;
    private readonly InfisicalRuntimeOptions _options;
    private readonly CancellationTokenSource _openingCancellation = new();
    private Func<CancellationToken, ValueTask<SecretMaterial>>? _bootstrap;
    private InfisicalPeriodicTokenSession? _tokenSession;
    private Task<SecretOutcome<InfisicalRuntimeSession>>? _authentication;
    private Task? _stopTask;

    private InfisicalRuntimeSession(InfisicalClient client, InfisicalPeriodicTokenSession session,
        InfisicalRuntimeOptions options)
    {
        Client = client;
        _tokenSession = session;
        _options = options;
        _shutdownTimeout = options.Network.ShutdownTimeout;
        _time = options.TimeProvider;
    }

    private InfisicalRuntimeSession(InfisicalRuntimeOptions options,
        Func<CancellationToken, ValueTask<SecretMaterial>> bootstrap)
    {
        _options = options;
        _bootstrap = bootstrap;
        _shutdownTimeout = options.Network.ShutdownTimeout;
        _time = options.TimeProvider;
        Client = new(options.Origin, new DeferredTokenSource(this), options.Network, options.TimeProvider);
    }

    /// <summary>Creates an owned runtime without acquiring credentials or performing network I/O.</summary>
    /// <remarks>The factory transfers one fresh material instance on first explicit authentication or read.
    /// Admission is single-attempt: failure and dispatch uncertainty are retained, never implicitly replayed.
    /// The cooperative operation deadline covers credential acquisition through token publication.
    /// Supplied pipelines remain host-owned. Dispose the runtime even if authentication never starts.</remarks>
    public static InfisicalRuntimeSession CreateDeferred(InfisicalRuntimeOptions options,
        Func<CancellationToken, ValueTask<SecretMaterial>> clientSecret)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clientSecret);
        options.ValidateForBootstrap();
        return new(options, clientSecret);
    }

    /// <summary>Retains the single bootstrap attempt and its dispatch evidence for explicit recovery decisions.</summary>
    [JsonIgnore]
    public InfisicalRuntimeOpenAttempt OpeningAttempt { get; private set; } = new();

    /// <summary>Reports whether authentication published a token session, without acquiring credentials.</summary>
    public bool IsAuthenticated { get { lock (_gate) return _tokenSession is not null && _stopTask is null; } }

    /// <summary>Joins the one authentication attempt without retrying login or changing principal.</summary>
    /// <remarks>Cancellation ends this caller's wait. Runtime disposal cancels and drains the shared operation.
    /// A failed or canceled shared attempt remains latched; recovery requires an explicitly new runtime.</remarks>
    public async ValueTask<SecretOutcome<InfisicalRuntimeSession>> EnsureAuthenticatedAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TaskCompletionSource<SecretOutcome<InfisicalRuntimeSession>>? completion = null;
        Task<SecretOutcome<InfisicalRuntimeSession>> pending;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_stopTask is not null, this);
            if (_tokenSession is not null) return SecretOutcome<InfisicalRuntimeSession>.Success(this);
            if (_authentication is null)
            {
                completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
                _authentication = completion.Task;
            }
            pending = _authentication;
        }
        if (completion is not null) _ = AuthenticateAsync(completion);
        return await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task AuthenticateAsync(TaskCompletionSource<SecretOutcome<InfisicalRuntimeSession>> completion)
    {
        using var diagnostics = InfisicalDiagnostics.Defer();
        try { completion.TrySetResult(await AuthenticateCoreAsync().ConfigureAwait(false)); }
        catch (OperationCanceledException) { completion.TrySetCanceled(_openingCancellation.Token); }
        catch (Exception) { completion.TrySetResult(SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.Unavailable)); }
    }

    private async Task<SecretOutcome<InfisicalRuntimeSession>> AuthenticateCoreAsync()
    {
        using var budget = new InfisicalOperationBudget(_options.Network.OperationTimeout, _time,
            CancellationToken.None, _openingCancellation.Token);
        InfisicalPeriodicTokenSession? candidate = null;
        try
        {
            budget.Check();
            var bootstrap = Interlocked.Exchange(ref _bootstrap, null)!;
            if (!AdmitsOpeningPolicy(_options))
            {
                return SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.RecoveryRequired);
            }
            using SecretMaterial secret = await bootstrap(budget.Token).ConfigureAwait(false);
            budget.Check();
            if (!OpeningAttempt.TryBegin()) throw new InvalidOperationException();
            var result = await LoginOnceAsync(_options, secret, OpeningAttempt, budget.Token)
                .ConfigureAwait(false);
            if (!result.IsSuccess)
            {
                return SecretOutcome<InfisicalRuntimeSession>.Failure(result.Status, result.RetryAfter, result.Reason);
            }
            using InfisicalUniversalLogin login = result.Value;
            budget.Check();
            var evidence = login.BindLifetimeEvidence(new()
            {
                OriginalIssuedAt = _options.OriginalIssuedAt!.Value,
                ExpiresAt = login.Token.ExpiresAt!.Value,
                Lifetime = _options.Lifetime,
                ReportedMaximumTtl = login.AccessTokenMaxTtl,
                Period = _options.Period,
                AbsoluteLifetimeLimit = _options.AbsoluteLifetimeLimit
            });
            candidate = new(_options.Origin, login.Token.Material, evidence, _options.RenewBefore,
                _options.RequestTimeout, _options.Network, _time);
            if (candidate.State is InfisicalTokenSessionState.RecoveryRequired or InfisicalTokenSessionState.Expired)
            {
                return SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.RecoveryRequired);
            }
            budget.Check();
            lock (_gate)
            {
                if (_stopTask is not null) throw new OperationCanceledException(_openingCancellation.Token);
                budget.Token.ThrowIfCancellationRequested();
                _tokenSession = candidate;
                candidate = null;
            }
            return SecretOutcome<InfisicalRuntimeSession>.Success(this);
        }
        catch (OperationCanceledException)
        {
            SecretFailureReason reason = budget.CancellationReason();
            return SecretOutcome<InfisicalRuntimeSession>.Failure(
                OpeningAttempt.LoginReceipt?.Evidence == DispatchEvidence.PossiblyDispatched
                    ? SecretStatus.Unknown : SecretStatus.Unavailable, reason: reason);
        }
        finally
        {
            if (candidate is not null)
                try { await candidate.DisposeAsync().ConfigureAwait(false); } catch (Exception) { }
        }
    }

    /// <summary>Borrowed native access; the aggregate owns disposal and the child owns operation admission.</summary>
    [JsonIgnore]
    public InfisicalClient Client { get; }

    /// <summary>Borrowed explicit maintenance access; do not independently dispose this aggregate-owned session.</summary>
    [JsonIgnore]
    public InfisicalPeriodicTokenSession TokenSession
    {
        get
        {
            lock (_gate)
                return _tokenSession ?? throw new InvalidOperationException("Runtime authentication has not completed.");
        }
    }

    /// <summary>Opens once using borrowed bootstrap material and retains actual dispatch evidence in the supplied attempt.</summary>
    /// <remarks>Independent policy is bound to the actual login, never inferred from its maximum TTL.
    /// Cancellation can leave bootstrap consumption uncertain; retain the attempt and explicitly authorize recovery.
    /// No bootstrap copy is retained for relogin. The private bootstrap helper outlives its accepted operation.</remarks>
    /// <exception cref="OperationCanceledException">The caller canceled; unpublished resources are retired.</exception>
    /// <exception cref="ArgumentException">The locally selected context or budgets are invalid.</exception>
    /// <exception cref="InvalidOperationException">Opening or cleanup failed; no underlying exception is exposed.</exception>
    public static async ValueTask<SecretOutcome<InfisicalRuntimeSession>> OpenUniversalAsync(
        InfisicalRuntimeOptions options, SecretMaterial clientSecret, InfisicalRuntimeOpenAttempt attempt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clientSecret);
        ArgumentNullException.ThrowIfNull(attempt);
        if (!attempt.TryBegin())
            return SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.Invalid);
        cancellationToken.ThrowIfCancellationRequested();
        options.ValidateForBootstrap();
        using var diagnostics = InfisicalDiagnostics.Defer();
        InfisicalUniversalLogin? login = null;
        InfisicalRuntimeSession? candidate = null;
        try
        {
            if (!AdmitsOpeningPolicy(options))
                return SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.RecoveryRequired);
            var authenticated = await LoginOnceAsync(options, clientSecret, attempt, cancellationToken)
                .ConfigureAwait(false);
            if (!authenticated.IsSuccess)
                return SecretOutcome<InfisicalRuntimeSession>.Failure(
                    authenticated.Status, authenticated.RetryAfter, authenticated.Reason);
            login = authenticated.Value;
            cancellationToken.ThrowIfCancellationRequested();
            InfisicalTokenLifetimeEvidence evidence = login.BindLifetimeEvidence(new()
            {
                OriginalIssuedAt = options.OriginalIssuedAt!.Value,
                ExpiresAt = login.Token.ExpiresAt!.Value,
                Lifetime = options.Lifetime,
                ReportedMaximumTtl = login.AccessTokenMaxTtl,
                Period = options.Period,
                AbsoluteLifetimeLimit = options.AbsoluteLifetimeLimit
            });
            var opened = CreateOwned(options, login.Token.Material, evidence);
            if (!opened.IsSuccess) return opened;
            candidate = opened.Value;
            candidate.OpeningAttempt = attempt;
            cancellationToken.ThrowIfCancellationRequested();
            var result = candidate;
            candidate = null;
            return SecretOutcome<InfisicalRuntimeSession>.Success(result);
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException("Runtime opening canceled.", cancellationToken);
        }
        catch (Exception)
        {
            if (cancellationToken.IsCancellationRequested)
                throw new OperationCanceledException("Runtime opening canceled.", cancellationToken);
            throw new InvalidOperationException("Runtime opening failed.");
        }
        finally
        {
            login?.Dispose();
            if (candidate is not null)
                try { await candidate.StopAsync().ConfigureAwait(false); }
                catch (Exception) { }
        }
    }

    /// <summary>Copies a supplied token under admitted lifetime evidence without dispatch or credential discovery.</summary>
    /// <remarks>The supplied evidence, rather than opening-only policy options, authorizes this token handoff.
    /// Unusable or missing timing returns RecoveryRequired. The caller retains its original material and pipeline.</remarks>
    /// <exception cref="ArgumentException">The locally selected context or budgets are invalid.</exception>
    /// <exception cref="InvalidOperationException">Construction failed; no underlying exception is exposed.</exception>
    public static SecretOutcome<InfisicalRuntimeSession> CreateFromToken(
        InfisicalRuntimeOptions options, SecretMaterial token,
        InfisicalTokenLifetimeEvidence? admittedEvidence)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(token);
        options.ValidateForTokenHandoff();
        if (admittedEvidence is null)
            return SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.RecoveryRequired);
        return CreateOwned(options, token, admittedEvidence);
    }

    private static SecretOutcome<InfisicalRuntimeSession> CreateOwned(InfisicalRuntimeOptions options,
        SecretMaterial token, InfisicalTokenLifetimeEvidence evidence)
    {
        InfisicalPeriodicTokenSession? session = null;
        InfisicalClient? client = null;
        try
        {
            session = new(options.Origin, token, evidence, options.RenewBefore, options.RequestTimeout,
                options.Network, options.TimeProvider);
            if (session.State is InfisicalTokenSessionState.RecoveryRequired or InfisicalTokenSessionState.Expired)
            {
                _ = RetireUnpublishedAsync(null, session);
                return SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.RecoveryRequired);
            }
            client = new(options.Origin, session, options.Network, options.TimeProvider);
            return SecretOutcome<InfisicalRuntimeSession>.Success(new(client, session, options));
        }
        catch (Exception)
        {
            _ = RetireUnpublishedAsync(client, session);
            throw new InvalidOperationException("Runtime construction failed.");
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2219", Justification = "Cleanup failure must dispose the unpublished login and prevent its return with a bounded diagnostic, including when login already failed.")]
    private static async ValueTask<SecretOutcome<InfisicalUniversalLogin>> LoginOnceAsync(
        InfisicalRuntimeOptions options, SecretMaterial bootstrap, InfisicalRuntimeOpenAttempt attempt,
        CancellationToken cancellationToken)
    {
        var authentication = new InfisicalUniversalAuthentication(
            options.Origin, options.Network, options.TimeProvider);
        InfisicalUniversalLogin? unpublished = null;
        try
        {
            var receipt = authentication.CreateReceipt();
            attempt.Record(receipt);
            var outcome = await authentication.LoginAsync(
                options.ClientId, bootstrap, receipt, options.OrganizationSlug, cancellationToken)
                .ConfigureAwait(false);
            if (outcome.IsSuccess) unpublished = outcome.Value;
            return outcome;
        }
        finally
        {
            try { authentication.Dispose(); }
            catch (Exception)
            {
                unpublished?.Dispose();
                throw new InvalidOperationException("Runtime bootstrap cleanup failed.");
            }
        }
    }

    private static bool AdmitsOpeningPolicy(InfisicalRuntimeOptions options)
    {
        if (options.OriginalIssuedAt is not { } original || original > options.TimeProvider.GetUtcNow())
            return false;
        return options.Lifetime switch
        {
            InfisicalTokenLifetime.Finite => options.Period is null && options.AbsoluteLifetimeLimit is null,
            InfisicalTokenLifetime.Periodic => options.Period is { } period && period > options.RenewBefore &&
                period <= TimeSpan.FromDays(36500) &&
                (options.AbsoluteLifetimeLimit is null || options.AbsoluteLifetimeLimit > options.TimeProvider.GetUtcNow()),
            _ => false
        };
    }

    /// <summary>Closes child admission and joins the single bounded retirement result.</summary>
    /// <remarks>Both children begin retirement before either is awaited. Their existing admission/drain contracts
    /// protect accepted work. All callers retain the original result and deadline; cleanup may continue after timeout.
    /// No external callback is invoked under the aggregate gate and no remote credential is revoked.</remarks>
    /// <exception cref="TimeoutException">The original aggregate deadline elapsed; eventual cleanup remains owned.</exception>
    /// <exception cref="InvalidOperationException">Child retirement failed, with no underlying exception exposed.</exception>
    public Task StopAsync()
    {
        TaskCompletionSource completion;
        lock (_gate)
        {
            if (_stopTask is not null) return _stopTask;
            completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _stopTask = completion.Task;
        }
        _ = CompleteStopAsync(completion);
        return completion.Task;
    }

    private async Task CompleteStopAsync(TaskCompletionSource completion)
    {
        // Register the aggregate deadline before child retirement can execute callbacks.
        var retired = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        bool retirementStarted = false;
        try
        {
            Task<bool> bounded = retired.Task.WaitAsync(_shutdownTimeout, _time);
            retirementStarted = true;
            _ = CompleteRetirementAsync(retired);
            if (await bounded.ConfigureAwait(false))
                completion.TrySetResult();
            else
                completion.TrySetException(new InvalidOperationException("Runtime shutdown failed."));
        }
        catch (TimeoutException)
        {
            completion.TrySetException(new TimeoutException("Runtime shutdown timed out."));
        }
        catch (Exception)
        {
            // Even a failing host clock cannot abandon the owned children's retirement.
            if (!retirementStarted) _ = CompleteRetirementAsync(retired);
            completion.TrySetException(new InvalidOperationException("Runtime shutdown failed."));
        }
    }

    private async Task CompleteRetirementAsync(TaskCompletionSource<bool> completion)
    {
        bool succeeded = true;
        Interlocked.Exchange(ref _bootstrap, null);
        try { await _openingCancellation.CancelAsync().ConfigureAwait(false); }
        catch (Exception) { succeeded = false; }
        if (_authentication is not null)
            try { await _authentication.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch (Exception) { succeeded = false; }
        succeeded &= await RetireUnpublishedAsync(Client, _tokenSession).ConfigureAwait(false);
        _openingCancellation.Dispose();
        completion.TrySetResult(succeeded);
    }

    private sealed class DeferredTokenSource(InfisicalRuntimeSession runtime) : IInfisicalTokenSource
    {
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            var outcome = await runtime.EnsureAuthenticatedAsync(cancellationToken).ConfigureAwait(false);
            return outcome.IsSuccess
                ? await runtime.TokenSession.GetTokenAsync(cancellationToken).ConfigureAwait(false)
                : SecretOutcome<InfisicalAccessToken>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
        }
    }

    private static async Task<bool> RetireUnpublishedAsync(
        InfisicalClient? client, InfisicalPeriodicTokenSession? session)
    {
        Task? clientStop = null;
        Task? sessionStop = null;
        bool succeeded = true;
        try { clientStop = client?.DisposeAsync().AsTask(); }
        catch (Exception) { succeeded = false; }
        try { sessionStop = session?.StopAsync(); }
        catch (Exception) { succeeded = false; }
        if (clientStop is not null)
            try { await clientStop.ConfigureAwait(false); }
            catch (Exception) { succeeded = false; }
        if (sessionStop is not null)
            try { await sessionStop.ConfigureAwait(false); }
            catch (Exception) { succeeded = false; }
        return succeeded;
    }

    /// <summary>Joins the original retirement result; timeout does not claim eventual cleanup has completed.</summary>
    public ValueTask DisposeAsync() => new(StopAsync());

    /// <summary>Returns a fixed label without credentials or selected coordinates.</summary>
    public override string ToString() => "[InfisicalRuntimeSession]";
}
