using System.Text.Json.Serialization;

namespace SecretKit.Core;

/// <summary>Opaque instance identity. Construct a separate identity for each authority boundary.</summary>
public sealed class SecretAuthority
{
    /// <inheritdoc />
    public override string ToString() => "[SecretAuthority]";
}

/// <summary>Provider-owned coordinates. A reference never selects a new network endpoint.</summary>
public abstract class SecretAddress
{
    /// <inheritdoc />
    public sealed override string ToString() => "[SecretAddress]";
}

/// <summary>Binds a typed address to exactly one provider instance.</summary>
public sealed class SecretReference
{
    private readonly SecretAuthority _authority;

    public SecretReference(SecretAuthority authority, SecretAddress address)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(address);
        _authority = authority;
        Address = address;
    }

    public SecretAddress Address { get; }

    public bool BelongsTo(SecretAuthority authority) => ReferenceEquals(_authority, authority);

    /// <inheritdoc />
    public override string ToString() => "[SecretReference]";
}

/// <summary>Provider-owned inventory coordinates bound to one authority.</summary>
public abstract class SecretInventoryScope
{
    private readonly SecretAuthority _authority;

    protected SecretInventoryScope(SecretAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        _authority = authority;
    }

    public bool BelongsTo(SecretAuthority authority) => ReferenceEquals(_authority, authority);

    /// <inheritdoc />
    public sealed override string ToString() => "[SecretInventoryScope]";
}
