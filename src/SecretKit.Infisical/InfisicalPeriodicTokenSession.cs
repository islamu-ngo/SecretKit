using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Refit;
using SecretKit.Core;

[assembly: InternalsVisibleTo("SecretKit.Hosting.Tests")]

namespace SecretKit.Infisical;

/// <summary>Host-verified lifetime model for the selected token and deployment.</summary>
public enum InfisicalTokenLifetime
{
    /// <summary>Policy is unestablished; a session cannot admit renewal.</summary>
    Unknown,
    /// <summary>A positive maximum TTL bounds lifetime from original issuance.</summary>
    Finite,
    /// <summary>Independently verified periodic renewal, optionally subject to an absolute ceiling.</summary>
    Periodic
}

/// <summary>
/// Host-asserted facts for this token and deployment, not defaults inferred from a login.
/// A finite ceiling is always measured from OriginalIssuedAt, including on renewal.
/// OriginalIssuedAt is verified original timing or an explicitly conservative lower bound;
/// a caller-observed request timestamp is not proof of server issuance.
/// Periodic semantics must have been independently verified; zero MaxTTL alone proves nothing.
/// </summary>
public sealed class InfisicalTokenLifetimeEvidence
{
    internal InfisicalUniversalLogin? Login { get; init; }
    /// <summary>Verified original issuance time or explicitly conservative lower bound; never reset by renewal.</summary>
    public required DateTimeOffset OriginalIssuedAt { get; init; }
    /// <summary>Expiry of the selected token, matching login evidence when bound to a login.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>The independently established finite or periodic policy.</summary>
    public required InfisicalTokenLifetime Lifetime { get; init; }
    /// <summary>Reported maximum TTL; finite policy requires a positive value.</summary>
    public required TimeSpan ReportedMaximumTtl { get; init; }
    /// <summary>Verified periodic interval, required only for periodic policy and longer than the renewal margin.</summary>
    public TimeSpan? Period { get; init; }
    /// <summary>Optional independently established absolute ceiling for periodic policy.</summary>
    public DateTimeOffset? AbsoluteLifetimeLimit { get; init; }
}

/// <summary>Local token usability and maintenance state; no remote readiness guarantee.</summary>
public enum InfisicalTokenSessionState
{
    /// <summary>The current token is locally usable before its renewal margin.</summary>
    Ready,
    /// <summary>The usable token has entered its explicit renewal margin.</summary>
    RenewalDue,
    /// <summary>One shared renewal request is in flight.</summary>
    Renewing,
    /// <summary>Observed expiry or absolute lifetime ceiling has elapsed.</summary>
    Expired,
    /// <summary>Explicitly authorized recovery is required; no fallback login occurs.</summary>
    RecoveryRequired,
    /// <summary>Admission is closed and the session's token generation has ended.</summary>
    Stopped
}

/// <summary>Evidence for one explicit renewal, independent of a waiter's cancellation.</summary>
public enum InfisicalRenewalEvidence
{
    /// <summary>No sending handoff has occurred.</summary>
    NotDispatched,
    /// <summary>Handoff occurred; the remote outcome may be unknown.</summary>
    PossiblyDispatched,
    /// <summary>A validated replacement token was published locally.</summary>
    Applied,
    /// <summary>The provider returned a recognized rejection.</summary>
    Rejected
}

/// <summary>Material-free, caller-retainable evidence; not an idempotency key.</summary>
public sealed class InfisicalTokenRenewal
{
    private int _evidence;
    /// <summary>Latest evidence retained even when a waiter cancels or shutdown begins.</summary>
    public InfisicalRenewalEvidence Evidence => (InfisicalRenewalEvidence)Volatile.Read(ref _evidence);
    internal void Record(InfisicalRenewalEvidence evidence) => Volatile.Write(ref _evidence, (int)evidence);
    /// <summary>Returns evidence without token material.</summary>
    public override string ToString() => $"[InfisicalTokenRenewal:{Evidence}]";
}

/// <summary>
/// In-memory native renewal of one explicitly supplied token. Construction and token reads
/// start no worker. Loss, expiry, consumed bootstrap credentials or uncertain renewal require
/// a new explicitly authorized token/session; there is no login, persistence or mutation replay.
/// A null existing token explicitly represents token loss and starts recovery-required.
/// </summary>
public sealed class InfisicalPeriodicTokenSession : IInfisicalTokenSource, IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly HttpClient _transport;
    private readonly IInfisicalTokenRenewalWire _wire;
    private readonly TimeProvider _time;
    private readonly InfisicalTokenLifetimeEvidence _lifetime;
    private readonly TimeSpan _renewBefore;
    private readonly TimeSpan _requestTimeout;
    private readonly TimeSpan _shutdownTimeout;
    private readonly int _responseLimit;
    private readonly CancellationTokenSource _shutdown = new();
    private SecretMaterial? _token;
    private DateTimeOffset _expiresAt;
    private InfisicalTokenSessionState _state;
    private Task<SecretStatus>? _renewalTask;
    private InfisicalTokenRenewal? _lastRenewal;
    private Task? _stopTask;

    /// <summary>
    /// Copies this login's token using evidence bound by BindLifetimeEvidence. The login
    /// and session own independent material; disposing the login does not stop the session.
    /// </summary>
    public InfisicalPeriodicTokenSession(InfisicalUniversalLogin login,
        InfisicalTokenLifetimeEvidence verifiedEvidence, TimeSpan renewBefore,
        TimeSpan requestTimeout, InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this((login ?? throw new ArgumentNullException(nameof(login))).Origin,
            login.Token.Material, ValidateLoginEvidence(login, verifiedEvidence),
            renewBefore, requestTimeout, network ?? new(), timeProvider ?? login.TimeProvider, null, true)
    {
    }

    private static InfisicalTokenLifetimeEvidence ValidateLoginEvidence(InfisicalUniversalLogin login,
        InfisicalTokenLifetimeEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!ReferenceEquals(evidence.Login, login))
            throw new ArgumentException("Lifetime evidence must be bound to this login.", nameof(evidence));
        return evidence;
    }

    /// <summary>Copies an explicit token under host-verified lifetime evidence; null represents loss and requires recovery.</summary>
    /// <remarks>Construction acquires nothing and starts no worker. The host keeps its original material and borrowed pipeline.</remarks>
    public InfisicalPeriodicTokenSession(Uri origin, SecretMaterial? existingToken,
        InfisicalTokenLifetimeEvidence verifiedEvidence, TimeSpan renewBefore,
        TimeSpan requestTimeout, InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
        : this(origin, existingToken, verifiedEvidence, renewBefore, requestTimeout,
            network ?? new(), timeProvider, null, true)
    {
    }

    internal InfisicalPeriodicTokenSession(Uri origin, SecretMaterial? existingToken,
        InfisicalTokenLifetimeEvidence verifiedEvidence, TimeSpan renewBefore,
        TimeSpan requestTimeout, InfisicalNetworkOptions network, TimeProvider? timeProvider,
        HttpMessageHandler? transport, bool ownsTransport)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(verifiedEvidence);
        ArgumentNullException.ThrowIfNull(network);
        if (verifiedEvidence.Login is { } login &&
            (!ReferenceEquals(existingToken, login.Token.Material) || origin != login.Origin))
            throw new ArgumentException("Lifetime evidence cannot authorize another token or origin.", nameof(verifiedEvidence));
        InfisicalTransportBinding.ValidateOrigin(origin, network);
        if (renewBefore <= TimeSpan.Zero || renewBefore > TimeSpan.FromDays(1) ||
            requestTimeout <= TimeSpan.Zero || requestTimeout > TimeSpan.FromMinutes(1) ||
            network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            network.ShutdownTimeout <= TimeSpan.Zero || network.ShutdownTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentException("Invalid renewal or network budget.");

        _time = timeProvider ?? TimeProvider.System;
        _lifetime = verifiedEvidence;
        _renewBefore = renewBefore;
        _requestTimeout = requestTimeout;
        _shutdownTimeout = network.ShutdownTimeout;
        _responseLimit = network.MaximumResponseBytes;
        _expiresAt = verifiedEvidence.ExpiresAt;
        _state = existingToken is not null && EstablishLifetime()
            ? InfisicalTokenSessionState.Ready : InfisicalTokenSessionState.RecoveryRequired;
        _binding = new(origin, network, transport, ownsTransport);
        try
        {
            if (_state == InfisicalTokenSessionState.Ready)
                _token = existingToken!.Copy();
            _transport = _binding.Client;
            _wire = RestService.For<IInfisicalTokenRenewalWire>(_binding.Requests);
        }
        catch
        {
            _token?.Dispose();
            _binding.Dispose();
            throw;
        }
    }

    private readonly InfisicalTransportBinding _binding;

    private DateTimeOffset? LifetimeLimit => _lifetime.Lifetime == InfisicalTokenLifetime.Finite
        ? _lifetime.OriginalIssuedAt + _lifetime.ReportedMaximumTtl
        : _lifetime.AbsoluteLifetimeLimit;

    private bool EstablishLifetime()
    {
        DateTimeOffset now = _time.GetUtcNow();
        if (_lifetime.OriginalIssuedAt > now || _expiresAt <= _lifetime.OriginalIssuedAt ||
            _lifetime.ReportedMaximumTtl < TimeSpan.Zero ||
            _lifetime.ReportedMaximumTtl > TimeSpan.FromDays(36500))
            return false;
        if (_lifetime.Lifetime == InfisicalTokenLifetime.Finite)
        {
            if (_lifetime.ReportedMaximumTtl <= TimeSpan.Zero || _lifetime.Period is not null ||
                _lifetime.AbsoluteLifetimeLimit is not null ||
                _lifetime.OriginalIssuedAt > DateTimeOffset.MaxValue - _lifetime.ReportedMaximumTtl)
                return false;
        }
        else if (_lifetime.Lifetime == InfisicalTokenLifetime.Periodic)
        {
            if (_lifetime.Period is not { } period || period <= _renewBefore ||
                period > TimeSpan.FromDays(36500) ||
                _expiresAt - now > period)
                return false;
        }
        else
            return false;
        return (LifetimeLimit is not { } limit || (_expiresAt <= limit && limit > now)) &&
            _expiresAt > now;
    }

    /// <summary>The clock governing expiry, renewal and the original shutdown deadline.</summary>
    public TimeProvider TimeProvider => _time;

    /// <summary>Current expiry minus the configured renewal margin; reading does not schedule work.</summary>
    public DateTimeOffset RenewalDueAt
    {
        get { lock (_gate) return _expiresAt - _renewBefore; }
    }

    /// <summary>The most recently started renewal receipt, or null before explicit renewal.</summary>
    public InfisicalTokenRenewal? LastRenewal
    {
        get { lock (_gate) return _lastRenewal; }
    }

    /// <summary>Current local state, updated against expiry and lifetime ceilings on access.</summary>
    public InfisicalTokenSessionState State
    {
        get
        {
            DateTimeOffset now = _time.GetUtcNow();
            lock (_gate)
            {
                UpdateDeadline(now);
                return _state;
            }
        }
    }

    private void UpdateDeadline(DateTimeOffset now)
    {
        if (_state is InfisicalTokenSessionState.Ready or InfisicalTokenSessionState.RenewalDue or
            InfisicalTokenSessionState.Renewing)
        {
            if (now >= _expiresAt || LifetimeLimit is { } limit && now >= limit)
            {
                _state = InfisicalTokenSessionState.Expired;
                _token?.Dispose();
                _token = null;
            }
            else if (_state != InfisicalTokenSessionState.Renewing && now >= _expiresAt - _renewBefore)
                _state = InfisicalTokenSessionState.RenewalDue;
        }
    }

    /// <summary>Returns a caller-owned copy without renewing; expired/lost sessions report RecoveryRequired.</summary>
    /// <exception cref="ObjectDisposedException">The session has stopped accepting token reads.</exception>
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DateTimeOffset now = _time.GetUtcNow();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_state == InfisicalTokenSessionState.Stopped, this);
            UpdateDeadline(now);
            if (_state is InfisicalTokenSessionState.Expired or InfisicalTokenSessionState.RecoveryRequired)
                return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Failure(SecretStatus.RecoveryRequired));
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new InfisicalAccessToken(_token!.Copy(), _expiresAt)));
        }
    }

    /// <summary>
    /// Concurrent waiters share the request, not their cancellation scopes. No automatic retries:
    /// the admitted operation establishes no safe replay, including after 429 or transport loss.
    /// LastRenewal is established before the send boundary and survives cancellation/shutdown.
    /// </summary>
    public async ValueTask<SecretStatus> RenewAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DateTimeOffset now = _time.GetUtcNow();
        Task<SecretStatus> task;
        TaskCompletionSource<SecretStatus>? completion = null;
        SecretMaterial? ownedToken = null;
        DateTimeOffset expiresAt = default;
        InfisicalTokenRenewal? receipt = null;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_state == InfisicalTokenSessionState.Stopped, this);
            UpdateDeadline(now);
            if (_state is InfisicalTokenSessionState.Expired or InfisicalTokenSessionState.RecoveryRequired)
                return SecretStatus.RecoveryRequired;
            if (_renewalTask is { IsCompleted: false })
                task = _renewalTask;
            else
            {
                receipt = _lastRenewal = new InfisicalTokenRenewal();
                ownedToken = _token!.Copy();
                expiresAt = _expiresAt;
                _state = InfisicalTokenSessionState.Renewing;
                completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
                task = _renewalTask = completion.Task;
            }
        }
        if (completion is not null)
            _ = CompleteRenewalAsync(completion, receipt!, ownedToken!, expiresAt);
        return await task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task CompleteRenewalAsync(TaskCompletionSource<SecretStatus> completion,
        InfisicalTokenRenewal receipt, SecretMaterial ownedToken, DateTimeOffset expiresAt)
    {
        using (ownedToken)
        {
            try
            {
                completion.TrySetResult(await RenewCoreAsync(receipt, ownedToken, expiresAt).ConfigureAwait(false));
            }
            catch (OperationCanceledException exception) { completion.TrySetCanceled(exception.CancellationToken); }
            catch (Exception)
            {
                FailRecovery();
                completion.TrySetException(new InvalidOperationException("Token renewal failed."));
            }
        }
    }

    private async Task<SecretStatus> RenewCoreAsync(InfisicalTokenRenewal receipt,
        SecretMaterial ownedToken, DateTimeOffset expiresAt)
    {
        DateTimeOffset sentAt = _time.GetUtcNow();
        TimeSpan remaining = expiresAt - sentAt;
        if (remaining <= TimeSpan.Zero) return FailRecovery();
        using var deadline = new CancellationTokenSource(
            remaining < _requestTimeout ? remaining : _requestTimeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, _shutdown.Token);
        SecretMaterial? candidate = null;
        try
        {
            using var payload = new MemoryStream();
            char[] characters = ownedToken.ExportCharacters();
            try
            {
                if (characters.Length is < 1 or > 16384 || characters.Any(char.IsControl))
                    return FailRecovery();
                using (var writer = new Utf8JsonWriter(payload))
                {
                    writer.WriteStartObject();
                    writer.WriteString("accessToken", characters.AsSpan());
                    writer.WriteEndObject();
                }
                using var content = new ByteArrayContent(payload.GetBuffer(), 0, checked((int)payload.Length));
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                using HttpRequestMessage request = await _wire.BuildRenewalAsync(content, linked.Token)
                    .ConfigureAwait(false);
                _binding.BindRequest(request);
                linked.Token.ThrowIfCancellationRequested();
                receipt.Record(InfisicalRenewalEvidence.PossiblyDispatched);
                using HttpResponseMessage response = await _transport
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    // The response does not prove this mutation is safely repeatable.
                    if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized or
                        HttpStatusCode.Forbidden or HttpStatusCode.NotFound or HttpStatusCode.UnprocessableEntity)
                        receipt.Record(InfisicalRenewalEvidence.Rejected);
                    SecretStatus result = response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                        ? SecretStatus.Denied : SecretStatus.RecoveryRequired;
                    return FailRecovery(result);
                }
                byte[] buffer = new byte[_responseLimit + 1];
                try
                {
                    using Stream body = await response.Content.ReadAsStreamAsync(linked.Token).ConfigureAwait(false);
                    int length = 0;
                    while (length < buffer.Length)
                    {
                        int read = await body.ReadAsync(buffer.AsMemory(length), linked.Token).ConfigureAwait(false);
                        if (read == 0) break;
                        length += read;
                    }
                    if (length > _responseLimit) return FailRecovery();
                    using JsonDocument document = JsonDocument.Parse(buffer.AsMemory(0, length),
                        new JsonDocumentOptions { MaxDepth = 8 });
                    JsonElement json = document.RootElement;
                    if (json.ValueKind != JsonValueKind.Object ||
                        json.EnumerateObject().Any(property => property.Name is not
                            ("accessToken" or "accessTokenMaxTTL" or "expiresIn" or "tokenType")) ||
                        json.EnumerateObject().Select(property => property.Name).Distinct(StringComparer.Ordinal).Count() !=
                        json.EnumerateObject().Count() ||
                        !json.TryGetProperty("accessToken", out var token) || token.ValueKind != JsonValueKind.String ||
                        !json.TryGetProperty("tokenType", out var type) || type.ValueKind != JsonValueKind.String ||
                        type.GetString() != "Bearer" ||
                        !json.TryGetProperty("expiresIn", out var expiry) || !expiry.TryGetDouble(out double seconds) ||
                        !double.IsFinite(seconds) || seconds <= _renewBefore.TotalSeconds || seconds > 3153600000 ||
                        !json.TryGetProperty("accessTokenMaxTTL", out var maximum) ||
                        !maximum.TryGetDouble(out double maximumSeconds) ||
                        maximumSeconds != _lifetime.ReportedMaximumTtl.TotalSeconds ||
                        (_lifetime.Lifetime == InfisicalTokenLifetime.Periodic && seconds > _lifetime.Period!.Value.TotalSeconds))
                        return FailRecovery();
                    string text = token.GetString()!;
                    if (text.Length is < 1 or > 16384 || text.Any(char.IsControl))
                        return FailRecovery();
                    DateTimeOffset expires = sentAt.AddSeconds(seconds);
                    if (LifetimeLimit is { } limit && expires > limit)
                        expires = limit;
                    if (expires - _time.GetUtcNow() <= _renewBefore)
                        return FailRecovery();
                    candidate = SecretMaterial.FromText(text);
                    DateTimeOffset observedAt = _time.GetUtcNow();
                    lock (_gate)
                    {
                        linked.Token.ThrowIfCancellationRequested();
                        UpdateDeadline(observedAt);
                        if (_state is InfisicalTokenSessionState.Expired or InfisicalTokenSessionState.RecoveryRequired or
                            InfisicalTokenSessionState.Stopped)
                            return FailRecovery();
                        _token!.Dispose();
                        _token = candidate;
                        candidate = null;
                        _expiresAt = expires;
                        receipt.Record(InfisicalRenewalEvidence.Applied);
                        _state = InfisicalTokenSessionState.Ready;
                    }
                    return SecretStatus.Success;
                }
                finally { Array.Clear(buffer); }
            }
            finally
            {
                Array.Clear(characters);
                Array.Clear(payload.GetBuffer());
            }
        }
        catch (OperationCanceledException)
        {
            FailRecovery();
            if (_shutdown.IsCancellationRequested) throw new OperationCanceledException(_shutdown.Token);
            return SecretStatus.RecoveryRequired;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException or
            ArgumentOutOfRangeException or InvalidOperationException)
        {
            return FailRecovery();
        }
        finally { candidate?.Dispose(); }
    }

    private SecretStatus FailRecovery(SecretStatus status = SecretStatus.RecoveryRequired)
    {
        lock (_gate)
        {
            _token?.Dispose();
            _token = null;
            if (_state != InfisicalTokenSessionState.Stopped)
                _state = InfisicalTokenSessionState.RecoveryRequired;
        }
        return status;
    }

    /// <summary>Joins the same bounded stop result as StopAsync; does not revoke the remote token.</summary>
    public ValueTask DisposeAsync() => new(StopAsync());

    /// <summary>
    /// Ends this credential generation and cancels/drains its shared renewal within the
    /// configured shutdown bound. Does not dispose a host-owned transport or caller copies.
    /// </summary>
    /// <remarks>All callers share the original deadline and terminal result. Timeout does not kill
    /// host callbacks: cleanup remains owned and completes if pending work later returns.
    /// No late renewal can publish a token after stop.</remarks>
    /// <exception cref="TimeoutException">The public bound elapsed before owned cleanup completed.</exception>
    public Task StopAsync()
    {
        TaskCompletionSource completion;
        Task? pending;
        SecretMaterial? detached;
        lock (_gate)
        {
            if (_stopTask is not null) return _stopTask;
            completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _stopTask = completion.Task;
            _state = InfisicalTokenSessionState.Stopped;
            pending = _renewalTask;
            detached = _token;
            _token = null;
        }
        detached?.Dispose();
        _ = DrainAsync(pending, completion);
        return completion.Task;
    }

    private async Task DrainAsync(Task? pending, TaskCompletionSource completion)
    {
        var cleanup = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<bool> bounded = cleanup.Task.WaitAsync(_shutdownTimeout, _time);
        _ = Task.Run(async () =>
        {
            bool succeeded = true;
            try
            {
                try { await _shutdown.CancelAsync().ConfigureAwait(false); }
                catch (Exception) { succeeded = false; }
            }
            finally
            {
                try
                {
                    if (pending is not null)
                        try { await pending.ConfigureAwait(false); }
                        catch (OperationCanceledException) { }
                        catch (Exception) { succeeded = false; }
                }
                finally
                {
                    try { _binding.Dispose(); }
                    catch (Exception) { succeeded = false; }
                    finally
                    {
                        _shutdown.Dispose();
                        cleanup.TrySetResult(succeeded);
                    }
                }
            }
        });
        try
        {
            if (await bounded.ConfigureAwait(false))
                completion.TrySetResult();
            else
                completion.TrySetException(new InvalidOperationException("Token session shutdown failed."));
        }
        catch (TimeoutException)
        {
            completion.TrySetException(new TimeoutException("Token session shutdown timed out."));
        }
    }

    /// <summary>Returns local state without token or deployment details.</summary>
    public override string ToString() => $"[InfisicalPeriodicTokenSession:{State}]";
}

// Refit binds the handwritten native route/body. The controlled HttpClient owns
// dispatch so the receipt and raw streaming budget remain at the actual send boundary.
internal interface IInfisicalTokenRenewalWire
{
    [Post("/api/v1/auth/token/renew")]
    Task<HttpRequestMessage> BuildRenewalAsync([Body] HttpContent payload, CancellationToken cancellationToken);
}
