using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Protected exact coordinates. Null is absent, not a wildcard; an empty project selector is distinct.</summary>
public sealed class ManagementTarget
{
    /// <summary>Captures exact protected coordinates; null selectors are absent, never wildcards.</summary>
    public ManagementTarget(string organizationId, string? projectId = null,
        string? resourceId = null, string? secondaryId = null)
    {
        ManagementJson.Text(organizationId);
        if (projectId is { Length: > 0 }) ManagementJson.Text(projectId);
        foreach (string? value in new[] { resourceId, secondaryId })
        {
            if (value is not null)
            {
                ManagementJson.Text(value);
            }
        }
        OrganizationId = organizationId;
        ProjectId = projectId;
        ResourceId = resourceId;
        SecondaryId = secondaryId;
    }

    /// <summary>Gets the exact organization coordinate approved by the host.</summary>
    [JsonIgnore] public string OrganizationId { get; }
    /// <summary>Gets the project selector; null is absent and differs from an empty selector.</summary>
    [JsonIgnore] public string? ProjectId { get; }
    /// <summary>Gets the resource coordinate, or null when the operation has none.</summary>
    [JsonIgnore] public string? ResourceId { get; }
    /// <summary>Gets the operation-specific secondary selector or intent binding, or null when absent.</summary>
    [JsonIgnore] public string? SecondaryId { get; }

    internal bool SameScope(ManagementTarget other) =>
        OrganizationId == other.OrganizationId && ProjectId == other.ProjectId;

    internal bool SameTarget(ManagementTarget other) => SameScope(other) &&
        ResourceId == other.ResourceId && SecondaryId == other.SecondaryId;

    /// <summary>Returns a marker without exposing any protected coordinates.</summary>
    public override string ToString() => "[ManagementTarget]";
}

/// <summary>
/// An explicitly selected host administrative identity and exact local scope.
/// Neither construction nor granting attests provider membership or capability.
/// Keep this issuer in the trusted host, not in untrusted request handling code.
/// </summary>
public sealed class ManagementAuthority
{
    internal SecretAuthority ClientAuthority { get; }
    internal IInfisicalTokenSource Tokens { get; }
    private readonly ManagementTarget _scope;

    /// <summary>Binds a borrowed token source and exact host scope to one client's local authority; performs no provider permission probe.</summary>
    public ManagementAuthority(SecretAuthority clientAuthority, IInfisicalTokenSource tokens,
        string organizationId, string? projectId = null)
    {
        ArgumentNullException.ThrowIfNull(clientAuthority);
        ArgumentNullException.ThrowIfNull(tokens);
        ClientAuthority = clientAuthority;
        Tokens = tokens;
        _scope = new ManagementTarget(organizationId, projectId);
    }

    /// <summary>
    /// Records host authorization, using independently selected target coordinates.
    /// The host must verify principal/scope correspondence out of band. This is not
    /// a provider permission probe, bearer token, signature, or security sandbox.
    /// </summary>
    public ManagementGrant IssueGrant(string operationId, ManagementTarget target)
    {
        ManagementJson.Text(operationId, 256);
        ArgumentNullException.ThrowIfNull(target);
        if (!_scope.SameScope(target))
        {
            throw new ArgumentException("The grant is outside the selected administrative scope.");
        }
        return new ManagementGrant(this, operationId, target);
    }

    /// <summary>Returns a marker without identity, token-source or scope details.</summary>
    public override string ToString() => "[ManagementAuthority]";
}

/// <summary>In-process host intent, bound to one issuer, operation and exact target.</summary>
public sealed class ManagementGrant
{
    internal ManagementAuthority Issuer { get; }
    private readonly string _operationId;
    private readonly ManagementTarget _target;

    internal ManagementGrant(ManagementAuthority issuer, string operationId, ManagementTarget target)
    {
        Issuer = issuer;
        _operationId = operationId;
        _target = target;
    }

    internal bool Matches(SecretAuthority client, ManagementAuthority selected,
        string operationId, ManagementTarget target) =>
        ReferenceEquals(Issuer, selected) && ReferenceEquals(Issuer.ClientAuthority, client) &&
        _operationId == operationId && _target.SameTarget(target);

    /// <summary>Returns a marker without disclosing the approved target or operation.</summary>
    public override string ToString() => "[ManagementGrant]";
}

/// <summary>Caller-held receipt bound to one immutable request and client.</summary>
public sealed class ManagementReceipt
{
    private readonly object _request;
    private readonly SecretAuthority _client;
    private readonly SecretReference _reference;
    private readonly MutationReceipt _receipt;

    internal ManagementReceipt(object request, SecretAuthority client)
    {
        _request = request;
        _client = client;
        _reference = new SecretReference(client, new ReceiptAddress());
        _receipt = new MutationReceipt(_reference);
    }

    /// <summary>Gets known dispatch evidence; unknown or pending evidence is not proof of rollback or rejection.</summary>
    public DispatchEvidence Evidence => _receipt.Evidence;
    /// <summary>Gets a process-local correlation identifier, not a provider transaction identifier.</summary>
    [JsonIgnore] public Guid LocalId => _receipt.LocalId;
    internal bool Matches(object request, SecretAuthority client) =>
        ReferenceEquals(_request, request) && ReferenceEquals(_client, client);
    internal bool TryBeginDispatch()
    {
        try
        {
            _receipt.BeginDispatch(_reference);
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
    internal void Record(DispatchEvidence evidence) => _receipt.Record(evidence);
    /// <summary>Returns the evidence state without protected request coordinates.</summary>
    public override string ToString() => $"[ManagementReceipt:{Evidence}]";
    private sealed class ReceiptAddress : SecretAddress;
}
