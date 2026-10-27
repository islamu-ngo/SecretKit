using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Protected lease identity bound to its validated definition; retained for explicit remote cleanup.</summary>
public sealed class InfisicalLeaseReference
{
    internal InfisicalLeaseReference(InfisicalDynamicDefinition definition, Guid id)
    {
        Definition = definition;
        Id = id;
    }
    /// <summary>The definition establishing client, scope and native resource identity.</summary>
    [JsonIgnore] public InfisicalDynamicDefinition Definition { get; }
    /// <summary>The observed native lease UUID.</summary>
    [JsonIgnore] public Guid Id { get; }
    internal InfisicalDatabaseLease? MaterialOwner { get; set; }
    /// <summary>Returns a fixed label without native identifiers.</summary>
    public override string ToString() => "[InfisicalLeaseReference]";
}

/// <summary>Validated native lease metadata without credential acquisition.</summary>
public sealed class InfisicalLeaseObservation
{
    internal InfisicalLeaseObservation(InfisicalLeaseReference reference, DateTimeOffset createdAt,
        DateTimeOffset expiresAt, decimal version, string? status)
    {
        Reference = reference;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
        Version = version;
        NativeStatus = status;
    }
    /// <summary>The retained client-bound lease reference.</summary>
    [JsonIgnore] public InfisicalLeaseReference Reference { get; }
    /// <summary>Native creation time, preserved when validating renewal.</summary>
    public DateTimeOffset CreatedAt { get; }
    /// <summary>Provider-returned expiry; renewal never fabricates an extension.</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>The observed native version.</summary>
    public decimal Version { get; }
    /// <summary>Protected provider text; a non-null status prevents assuming local material is active.</summary>
    [JsonIgnore] public string? NativeStatus { get; }
    /// <summary>Returns a fixed label without lease coordinates or status text.</summary>
    public override string ToString() => "[InfisicalLeaseObservation]";
}

/// <summary>Local usability derived from time and observed lifecycle, not downstream readiness.</summary>
public enum InfisicalLeaseLocalState { /** <summary>Material is locally eligible before expiry.</summary> */ Active, /** <summary>Observed expiry elapsed.</summary> */ Expired, /** <summary>A remote effect or native status is uncertain.</summary> */ EffectUnknown, /** <summary>Revocation was acknowledged.</summary> */ Revoked, /** <summary>This local material owner was disposed.</summary> */ Disposed }

/// <summary>Native database fields, never a portable static secret. Exports create ordinary strings.</summary>
public sealed class InfisicalDatabaseCredentials : IDisposable
{
    private readonly SecretMaterial _username;
    private readonly SecretMaterial _password;
    private readonly Func<bool> _canUse;
    internal InfisicalDatabaseCredentials(string username, string password, Func<bool> canUse)
    {
        _username = SecretMaterial.FromText(username);
        _password = SecretMaterial.FromText(password);
        _canUse = canUse;
    }
    private InfisicalDatabaseCredentials(SecretMaterial username, SecretMaterial password, Func<bool> canUse)
    {
        _username = username;
        _password = password;
        _canUse = canUse;
    }
    internal InfisicalDatabaseCredentials Copy(Func<bool> canUse) =>
        new(_username.Copy(), _password.Copy(), canUse);
    /// <summary>Exports an ordinary plaintext username only while the shared observed lifecycle permits use.</summary>
    public string RevealUsername()
    {
        CheckValidity();
        return _username.Reveal();
    }
    /// <summary>Exports an ordinary plaintext password only while the shared observed lifecycle permits use.</summary>
    public string RevealPassword()
    {
        CheckValidity();
        return _password.Reveal();
    }
    private void CheckValidity()
    {
        if (!_canUse())
        {
            throw new InvalidOperationException("Native lease material is not locally usable.");
        }
    }
    /// <summary>Erases this copy's material without revoking the lease or erasing earlier plaintext exports.</summary>
    public void Dispose()
    {
        _username.Dispose();
        _password.Dispose();
    }
    /// <summary>Returns a fixed label without either credential.</summary>
    public override string ToString() => "[InfisicalDatabaseCredentials]";
}

/// <summary>
/// Caller owns local material disposal AND explicit remote cleanup. Dispose sends no request.
/// Copies own independent character storage while sharing the observed remote lifecycle.
/// </summary>
public sealed class InfisicalDatabaseLease : IDisposable
{
    private readonly object _gate = new();
    private readonly TimeProvider _time;
    private readonly InfisicalDatabaseCredentials _credentials;
    private InfisicalLeaseObservation _observation;
    private InfisicalLeaseLocalState _state;
    private bool _mutation;
    private bool _disposed;

    internal InfisicalDatabaseLease(InfisicalLeaseObservation observation, TimeProvider time,
        string username, string password)
    {
        _observation = observation;
        _time = time;
        _credentials = new InfisicalDatabaseCredentials(username, password, CanUse);
        observation.Reference.MaterialOwner = this;
    }
    /// <summary>Retained reference for renewal or remote cleanup, including after local disposal.</summary>
    [JsonIgnore] public InfisicalLeaseReference Reference => _observation.Reference;
    /// <summary>Latest validated lease observation; no provider request occurs on access.</summary>
    [JsonIgnore] public InfisicalLeaseObservation Observation { get { lock (_gate) { return _observation; } } }
    /// <summary>Local state accounting for disposal, observed expiry and uncertain native effects.</summary>
    public InfisicalLeaseLocalState State
    {
        get
        {
            lock (_gate)
            {
                if (_disposed)
                {
                    return InfisicalLeaseLocalState.Disposed;
                }
                if (_state == InfisicalLeaseLocalState.Active && _time.GetUtcNow() >= _observation.ExpiresAt)
                {
                    return InfisicalLeaseLocalState.Expired;
                }
                return _state == InfisicalLeaseLocalState.Active && _observation.NativeStatus is not null
                    ? InfisicalLeaseLocalState.EffectUnknown : _state;
            }
        }
    }
    /// <summary>Returns caller-owned independent buffers while sharing remote expiry/revocation uncertainty.</summary>
    /// <remarks>Local lease disposal does not dispose a returned copy. Expired material reports Expired;
    /// disposed owners report Invalid; otherwise unusable or in-flight lifecycle state reports Unknown.</remarks>
    public SecretOutcome<InfisicalDatabaseCredentials> CopyCredentials()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return SecretOutcome<InfisicalDatabaseCredentials>.Failure(SecretStatus.Invalid);
            }
            if (State == InfisicalLeaseLocalState.Expired)
            {
                return SecretOutcome<InfisicalDatabaseCredentials>.Failure(SecretStatus.Expired);
            }
            if (!CanUse())
            {
                return SecretOutcome<InfisicalDatabaseCredentials>.Failure(SecretStatus.Unknown);
            }
            // Disposal of the lease does not invalidate the independently owned copy.
            return SecretOutcome<InfisicalDatabaseCredentials>.Success(_credentials.Copy(RemoteCanUse));
        }
    }
    private bool CanUse() => !_disposed && RemoteCanUse();
    private bool RemoteCanUse()
    {
        lock (_gate)
        {
            return !_mutation && _state == InfisicalLeaseLocalState.Active &&
                _observation.NativeStatus is null && _time.GetUtcNow() < _observation.ExpiresAt;
        }
    }
    internal bool BeginMutation(bool renewal)
    {
        lock (_gate)
        {
            if ((_disposed && renewal) || _mutation || _state == InfisicalLeaseLocalState.Revoked ||
                (renewal && State != InfisicalLeaseLocalState.Active))
            {
                return false;
            }
            _mutation = true;
            return true;
        }
    }
    internal void FinishMutation(InfisicalDynamicMutationReceipt receipt,
        InfisicalLeaseObservation? observation, bool revoked)
    {
        lock (_gate)
        {
            if (receipt.Evidence == DispatchEvidence.PossiblyDispatched)
            {
                _state = InfisicalLeaseLocalState.EffectUnknown;
            }
            else if (revoked && receipt.Evidence == DispatchEvidence.Applied)
            {
                _state = InfisicalLeaseLocalState.Revoked;
            }
            else if (observation is not null && receipt.Evidence == DispatchEvidence.Applied)
            {
                _observation = observation;
                _state = InfisicalLeaseLocalState.Active;
            }
            _mutation = false;
        }
    }
    /// <summary>Disposes this lease's local credential buffers only; explicit Revoke remains the caller's responsibility.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _credentials.Dispose();
        }
    }
    /// <summary>Returns local state without credential or reference details.</summary>
    public override string ToString() => $"[InfisicalDatabaseLease:{State}]";
}

/// <summary>Native deletion acknowledgement, distinct from externally verified credential revocation.</summary>
public sealed class InfisicalDynamicDeletion
{
    internal InfisicalDynamicDeletion(bool forced, string? nativeStatus)
    {
        ForcedRecordRemoval = forced;
        NativeStatus = nativeStatus;
    }
    /// <summary>Whether force-record-removal was requested; this is not downstream cleanup proof.</summary>
    public bool ForcedRecordRemoval { get; }
    /// <summary>Record removal does not prove downstream credential revocation or convergence.</summary>
    public bool ExternalRevocationVerified => false;
    /// <summary>Protected provider status text, if returned.</summary>
    [JsonIgnore] public string? NativeStatus { get; }
    /// <summary>Returns a fixed label without provider text.</summary>
    public override string ToString() => "[InfisicalDynamicDeletion]";
}
