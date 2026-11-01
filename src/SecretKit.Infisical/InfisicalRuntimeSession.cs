using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Explicit owner of one native client and token session, without bootstrap retention or automatic maintenance.</summary>
public sealed class InfisicalRuntimeSession : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly TimeSpan _shutdownTimeout;
    private readonly TimeProvider _time;
    private Task? _stopTask;

    private InfisicalRuntimeSession(InfisicalClient client, InfisicalPeriodicTokenSession session,
        InfisicalRuntimeOptions options)
    {
        Client = client;
        TokenSession = session;
        _shutdownTimeout = options.Network.ShutdownTimeout;
        _time = options.TimeProvider;
    }

    /// <summary>Borrowed native access; the aggregate owns disposal and the child owns operation admission.</summary>
    [JsonIgnore]
    public InfisicalClient Client { get; }

    /// <summary>Borrowed explicit maintenance access; do not independently dispose this aggregate-owned session.</summary>
    [JsonIgnore]
    public InfisicalPeriodicTokenSession TokenSession { get; }

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
        ValidateOptions(options);
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
            if (login.AccessTokenMaxTTL > TimeSpan.FromDays(36500).TotalSeconds)
                return SecretOutcome<InfisicalRuntimeSession>.Failure(SecretStatus.RecoveryRequired);
            InfisicalTokenLifetimeEvidence evidence = login.BindLifetimeEvidence(new()
            {
                OriginalIssuedAt = options.OriginalIssuedAt!.Value,
                ExpiresAt = login.Token.ExpiresAt!.Value,
                Lifetime = options.Lifetime,
                ReportedMaximumTtl = TimeSpan.FromSeconds(login.AccessTokenMaxTTL),
                Period = options.Period,
                AbsoluteLifetimeLimit = options.AbsoluteLifetimeLimit
            });
            var opened = CreateOwned(options, login.Token.Material, evidence);
            if (!opened.IsSuccess) return opened;
            candidate = opened.Value;
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
        ValidateOptions(options, bootstrap: false);
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

    private static void ValidateOptions(InfisicalRuntimeOptions options, bool bootstrap = true)
    {
        ArgumentNullException.ThrowIfNull(options.Origin);
        ArgumentNullException.ThrowIfNull(options.Network);
        ArgumentNullException.ThrowIfNull(options.TimeProvider);
        InfisicalTransportBinding.ValidateOrigin(options.Origin, options.Network);
        if (bootstrap && (string.IsNullOrWhiteSpace(options.ClientId) || options.ClientId.Length > 1024 ||
            options.ClientId.Any(char.IsControl)) || string.IsNullOrWhiteSpace(options.ProjectId) ||
            options.ProjectId.Length > 1024 || options.ProjectId.Any(char.IsControl) ||
            options.OrganizationSlug is { } organization &&
                (organization.Length is < 1 or > 64 || organization.Any(char.IsControl)) ||
            options.RenewBefore <= TimeSpan.Zero || options.RenewBefore > TimeSpan.FromDays(1) ||
            options.RequestTimeout <= TimeSpan.Zero || options.RequestTimeout > TimeSpan.FromMinutes(1) ||
            options.Network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            options.Network.ShutdownTimeout <= TimeSpan.Zero ||
            options.Network.ShutdownTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentException("Invalid runtime context or budget.");
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
        try
        {
            Task<bool> bounded = retired.Task.WaitAsync(_shutdownTimeout, _time);
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
            _ = RetireUnpublishedAsync(Client, TokenSession);
            completion.TrySetException(new InvalidOperationException("Runtime shutdown failed."));
        }
    }

    private async Task CompleteRetirementAsync(TaskCompletionSource<bool> completion) =>
        completion.TrySetResult(await RetireUnpublishedAsync(Client, TokenSession).ConfigureAwait(false));

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
