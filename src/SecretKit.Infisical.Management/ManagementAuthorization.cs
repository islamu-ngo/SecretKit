using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Protected exact coordinates. Null is an absent coordinate, never a wildcard.</summary>
public sealed class ManagementTarget
{
    public ManagementTarget(string organizationId, string? projectId = null,
        string? resourceId = null, string? secondaryId = null)
    {
        ManagementJson.Text(organizationId);
        foreach (string? value in new[] { projectId, resourceId, secondaryId })
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

    [JsonIgnore] public string OrganizationId { get; }
    [JsonIgnore] public string? ProjectId { get; }
    [JsonIgnore] public string? ResourceId { get; }
    [JsonIgnore] public string? SecondaryId { get; }

    internal bool SameScope(ManagementTarget other) =>
        OrganizationId == other.OrganizationId && ProjectId == other.ProjectId;

    internal bool SameTarget(ManagementTarget other) => SameScope(other) &&
        ResourceId == other.ResourceId && SecondaryId == other.SecondaryId;

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

    public DispatchEvidence Evidence => _receipt.Evidence;
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
    public override string ToString() => $"[ManagementReceipt:{Evidence}]";
    private sealed class ReceiptAddress : SecretAddress;
}
