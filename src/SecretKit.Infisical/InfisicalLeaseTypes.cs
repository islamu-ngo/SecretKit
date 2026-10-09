using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

public sealed class InfisicalLeaseReference
{
    internal InfisicalLeaseReference(InfisicalDynamicDefinition definition, Guid id)
    {
        Definition = definition;
        Id = id;
    }
    [JsonIgnore] public InfisicalDynamicDefinition Definition { get; }
    [JsonIgnore] public Guid Id { get; }
    internal InfisicalDatabaseLease? MaterialOwner { get; set; }
    public override string ToString() => "[InfisicalLeaseReference]";
}

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
    [JsonIgnore] public InfisicalLeaseReference Reference { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public decimal Version { get; }
    [JsonIgnore] public string? NativeStatus { get; }
    public override string ToString() => "[InfisicalLeaseObservation]";
}

public enum InfisicalLeaseLocalState { Active, Expired, EffectUnknown, Revoked, Disposed }

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
    public string RevealUsername()
    {
        CheckValidity();
        return _username.Reveal();
    }
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
    public void Dispose()
    {
        _username.Dispose();
        _password.Dispose();
    }
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
    [JsonIgnore] public InfisicalLeaseReference Reference => _observation.Reference;
    [JsonIgnore] public InfisicalLeaseObservation Observation { get { lock (_gate) { return _observation; } } }
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
    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _credentials.Dispose();
        }
    }
    public override string ToString() => $"[InfisicalDatabaseLease:{State}]";
}

public sealed class InfisicalDynamicDeletion
{
    internal InfisicalDynamicDeletion(bool forced, string? nativeStatus)
    {
        ForcedRecordRemoval = forced;
        NativeStatus = nativeStatus;
    }
    public bool ForcedRecordRemoval { get; }
    /// <summary>Record removal does not prove downstream credential revocation or convergence.</summary>
    public bool ExternalRevocationVerified => false;
    [JsonIgnore] public string? NativeStatus { get; }
    public override string ToString() => "[InfisicalDynamicDeletion]";
}
