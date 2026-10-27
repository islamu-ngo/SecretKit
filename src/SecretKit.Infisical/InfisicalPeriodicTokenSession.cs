using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Refit;
using SecretKit.Core;

[assembly: InternalsVisibleTo("SecretKit.Hosting.Tests")]

namespace SecretKit.Infisical;

public enum InfisicalTokenLifetime
{
    Unknown,
    Finite,
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
    public required DateTimeOffset OriginalIssuedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required InfisicalTokenLifetime Lifetime { get; init; }
    public required TimeSpan ReportedMaximumTtl { get; init; }
    public TimeSpan? Period { get; init; }
    public DateTimeOffset? AbsoluteLifetimeLimit { get; init; }
}

public enum InfisicalTokenSessionState
{
    Ready,
    RenewalDue,
    Renewing,
    Expired,
    RecoveryRequired,
    Stopped
}

public enum InfisicalRenewalEvidence
{
    NotDispatched,
    PossiblyDispatched,
    Applied,
    Rejected
}

/// <summary>Material-free, caller-retainable evidence; not an idempotency key.</summary>
public sealed class InfisicalTokenRenewal
{
    private int _evidence;
    public InfisicalRenewalEvidence Evidence => (InfisicalRenewalEvidence)Volatile.Read(ref _evidence);
    internal void Record(InfisicalRenewalEvidence evidence) => Volatile.Write(ref _evidence, (int)evidence);
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
    private Task? _disposeTask;

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

    public TimeProvider TimeProvider => _time;

    public DateTimeOffset RenewalDueAt
    {
        get { lock (_gate) return _expiresAt - _renewBefore; }
    }

    public InfisicalTokenRenewal? LastRenewal
    {
        get { lock (_gate) return _lastRenewal; }
    }

    public InfisicalTokenSessionState State
    {
        get
        {
            lock (_gate)
            {
                UpdateDeadline();
                return _state;
            }
        }
    }

    private void UpdateDeadline()
    {
        if (_state is InfisicalTokenSessionState.Ready or InfisicalTokenSessionState.RenewalDue or
            InfisicalTokenSessionState.Renewing)
        {
            DateTimeOffset now = _time.GetUtcNow();
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

    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_state == InfisicalTokenSessionState.Stopped, this);
            UpdateDeadline();
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
        Task<SecretStatus> task;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_state == InfisicalTokenSessionState.Stopped, this);
            UpdateDeadline();
            if (_state is InfisicalTokenSessionState.Expired or InfisicalTokenSessionState.RecoveryRequired)
                return SecretStatus.RecoveryRequired;
            if (_renewalTask is { IsCompleted: false })
                task = _renewalTask;
            else
            {
                _lastRenewal = new InfisicalTokenRenewal();
                _state = InfisicalTokenSessionState.Renewing;
                task = _renewalTask = RenewCoreAsync(_lastRenewal);
            }
        }
        return await task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<SecretStatus> RenewCoreAsync(InfisicalTokenRenewal receipt)
    {
        DateTimeOffset sentAt = _time.GetUtcNow();
        TimeSpan remaining = _expiresAt - sentAt;
        if (remaining <= TimeSpan.Zero) return FailRecovery();
        using var deadline = new CancellationTokenSource(
            remaining < _requestTimeout ? remaining : _requestTimeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, _shutdown.Token);
        SecretMaterial? candidate = null;
        try
        {
            using var payload = new MemoryStream();
            char[] characters = _token!.ExportCharacters();
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
                    lock (_gate)
                    {
                        linked.Token.ThrowIfCancellationRequested();
                        UpdateDeadline();
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

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _disposeTask ??= DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    /// <summary>
    /// Ends this credential generation and cancels/drains its shared renewal within the
    /// configured shutdown bound. Does not dispose a host-owned transport or caller copies.
    /// </summary>
    public Task StopAsync()
    {
        lock (_gate)
        {
            _state = InfisicalTokenSessionState.Stopped;
            _shutdown.Cancel();
            return _stopTask ??= DrainAsync();
        }
    }

    private async Task DrainAsync()
    {
        try
        {
            if (_renewalTask is { } pending)
                await pending.WaitAsync(_shutdownTimeout, _time).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        finally
        {
            lock (_gate)
            {
                _token?.Dispose();
                _token = null;
            }
        }
    }

    private async Task DisposeCoreAsync()
    {
        try { await StopAsync().ConfigureAwait(false); }
        finally { _binding.Dispose(); }
    }

    public override string ToString() => $"[InfisicalPeriodicTokenSession:{State}]";
}

// Refit binds the handwritten native route/body. The controlled HttpClient owns
// dispatch so the receipt and raw streaming budget remain at the actual send boundary.
internal interface IInfisicalTokenRenewalWire
{
    [Post("/api/v1/auth/token/renew")]
    Task<HttpRequestMessage> BuildRenewalAsync([Body] HttpContent payload, CancellationToken cancellationToken);
}
