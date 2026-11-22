using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Explicit owner of one native client and token session, without bootstrap retention or automatic maintenance.</summary>
public sealed class InfisicalRuntimeSession : IAsyncDisposable
{
    private readonly Lock _gate = new();
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
        try
        {
            using var diagnostics = InfisicalDiagnostics.Defer();
            completion.TrySetResult(await AuthenticateCoreAsync().ConfigureAwait(false));
        }
        catch (OperationCanceledException) { completion.TrySetCanceled(_openingCancellation.Token); }
        catch (Exception error) when (SessionRetirement.Fatal(error) is { } fatal) { completion.TrySetException(fatal); }
        catch (Exception) { completion.TrySetResult(SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.Unavailable)); }
    }

    private async Task<SecretOutcome<InfisicalRuntimeSession>> AuthenticateCoreAsync()
    {
        InfisicalPeriodicTokenSession? candidate = null;
        try
        {
            // Keep the candidate local until the bootstrap, login and deadline are all retired.
            using (var budget = new InfisicalOperationBudget(_options.Network.OperationTimeout, _time,
                CancellationToken.None, _openingCancellation.Token))
            {
                try
                {
                    budget.Check();
                    if (!AdmitsOpeningPolicy(_options))
                    {
                        return SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.RecoveryRequired);
                    }
                    Func<CancellationToken, ValueTask<SecretMaterial>> bootstrap;
                    lock (_gate)
                    {
                        if (_stopTask is not null) throw new OperationCanceledException(_openingCancellation.Token);
                        bootstrap = _bootstrap!;
                        _bootstrap = null;
                    }
                    using SecretMaterial secret = await bootstrap(budget.Token).ConfigureAwait(false);
                    budget.Check();
                    if (!OpeningAttempt.TryBegin()) throw new InvalidOperationException();
                    var result = await LoginOnceAsync(_options, secret, OpeningAttempt, budget.Token)
                        .ConfigureAwait(false);
                    if (!result.IsSuccess)
                    {
                        return result.ConvertFailure<InfisicalRuntimeSession>();
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
                }
                catch (OperationCanceledException)
                {
                    SecretFailureReason reason = budget.CancellationReason();
                    return SecretOutcome<InfisicalRuntimeSession>.Failure(
                        OpeningAttempt.LoginReceipt?.Evidence == DispatchEvidence.PossiblyDispatched
                            ? SecretStatus.Unknown : SecretStatus.Unavailable, reason: reason);
                }
            }
            lock (_gate)
            {
                if (_stopTask is not null) throw new OperationCanceledException(_openingCancellation.Token);
                _tokenSession = candidate;
                candidate = null;
            }
            return SecretOutcome<InfisicalRuntimeSession>.Success(this);
        }
        finally
        {
            if (candidate is not null)
                try { await candidate.DisposeAsync().ConfigureAwait(false); }
                catch (Exception error) when (SessionRetirement.Fatal(error) is null) { }
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
                return authenticated.ConvertFailure<InfisicalRuntimeSession>();
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
        catch (Exception error) when (SessionRetirement.Fatal(error) is null)
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
                catch (Exception error) when (SessionRetirement.Fatal(error) is null) { }
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
        catch (Exception error)
        {
            _ = RetireUnpublishedAsync(client, session);
            if (SessionRetirement.Fatal(error) is not null) throw;
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
            catch (Exception error)
            {
                unpublished?.Dispose();
                if (SessionRetirement.Fatal(error) is not null) throw;
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
            _bootstrap = null;
        }
        _ = SessionRetirement.CompleteAsync(completion, RetireAsync, _shutdownTimeout, _time);
        return completion.Task;
    }

    private async Task<Exception?> RetireAsync()
    {
        // Close both children's admission before waiting on host-controlled bootstrap work.
        Task<Exception?> children = RetireUnpublishedAsync(Client, _tokenSession);
        Exception? failure = await SessionRetirement.JoinAsync(_openingCancellation.CancelAsync()).ConfigureAwait(false);
        failure = await SessionRetirement.JoinAsync(_authentication, failure, allowCancellation: true).ConfigureAwait(false);
        if (await children.ConfigureAwait(false) is { } childFailure)
            failure = SessionRetirement.Fatal(childFailure) ?? failure ?? childFailure;
        _openingCancellation.Dispose();
        return failure;
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

    private static async Task<Exception?> RetireUnpublishedAsync(
        InfisicalClient? client, InfisicalPeriodicTokenSession? session, Exception? failure = null)
    {
        Task? clientStop = null;
        Task? sessionStop = null;
        try { clientStop = client?.DisposeAsync().AsTask(); }
        catch (Exception error) { failure = SessionRetirement.Fatal(error) ?? failure ?? SessionRetirement.Failure(error); }
        try { sessionStop = session?.StopAsync(); }
        catch (Exception error) { failure = SessionRetirement.Fatal(error) ?? failure ?? SessionRetirement.Failure(error); }
        failure = await SessionRetirement.JoinAsync(clientStop, failure).ConfigureAwait(false);
        return await SessionRetirement.JoinAsync(sessionStop, failure).ConfigureAwait(false);
    }

    /// <summary>Joins the original retirement result; timeout does not claim eventual cleanup has completed.</summary>
    public ValueTask DisposeAsync() => new(StopAsync());

    /// <summary>Returns a fixed label without credentials or selected coordinates.</summary>
    public override string ToString() => "[InfisicalRuntimeSession]";
}

// Stop admission is latched by the session; this owner keeps draining after a public timeout.
internal static class SessionRetirement
{
    internal static Exception? Fatal(Exception error)
    {
        if (error is OutOfMemoryException or AccessViolationException or StackOverflowException) return error;
        if (error is AggregateException aggregate)
            foreach (var cause in aggregate.InnerExceptions)
                if (Fatal(cause) is { } fatal) return fatal;
        return null;
    }

    internal static Exception Failure(Exception error) => Fatal(error) ?? new InvalidOperationException("Session retirement failed.");

    internal static async Task CompleteAsync(TaskCompletionSource completion, Func<Task<Exception?>> drain,
        TimeSpan timeout, TimeProvider time)
    {
        var retired = new TaskCompletionSource<Exception?>(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task RetireAsync()
        {
            try { retired.TrySetResult(await drain().ConfigureAwait(false)); }
            catch (Exception error) { retired.TrySetResult(Failure(error)); }
        }
        Task<Exception?> bounded;
        try { bounded = retired.Task.WaitAsync(timeout, time); }
        catch (Exception error)
        {
            _ = RetireAsync();
            completion.TrySetException(Failure(error));
            return;
        }
        _ = RetireAsync();
        try
        {
            if (await bounded.ConfigureAwait(false) is { } error) completion.TrySetException(error);
            else completion.TrySetResult();
        }
        catch (TimeoutException) { completion.TrySetException(new TimeoutException("Session shutdown timed out.")); }
        catch (Exception error) { completion.TrySetException(Failure(error)); }
    }

    // Never abandon another owned child because a sibling failed.
    internal static async Task<Exception?> JoinAsync(Task? pending, Exception? previous = null, bool allowCancellation = false)
    {
        if (pending is not null)
            try { await pending.ConfigureAwait(false); }
            catch (OperationCanceledException) when (allowCancellation) { }
            catch (Exception error) { return Fatal(error) ?? previous ?? Failure(error); }
        return previous;
    }
}
