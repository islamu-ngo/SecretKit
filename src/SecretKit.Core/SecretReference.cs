using System.Text.Json.Serialization;

namespace SecretKit.Core;

/// <summary>Opaque instance identity. Construct a separate identity for each authority boundary.</summary>
public sealed class SecretAuthority
{
    /// <summary>Returns a fixed marker without exposing instance identity.</summary>
    public override string ToString() => "[SecretAuthority]";
}

/// <summary>Provider-owned coordinates. A reference never selects a new network endpoint.</summary>
public abstract class SecretAddress
{
    /// <summary>Returns a fixed marker without formatting provider coordinates.</summary>
    public sealed override string ToString() => "[SecretAddress]";
}

/// <summary>Binds a typed address to exactly one provider instance.</summary>
public sealed class SecretReference
{
    private readonly SecretAuthority _authority;

    /// <summary>Binds the supplied address to an authority instance without granting remote access.</summary>
    /// <param name="authority">The exact provider-instance identity to retain.</param>
    /// <param name="address">Provider-owned coordinates to retain without copying.</param>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    public SecretReference(SecretAuthority authority, SecretAddress address)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(address);
        _authority = authority;
        Address = address;
    }

    /// <summary>Gets the retained typed coordinates; they cannot select a new network endpoint.</summary>
    public SecretAddress Address { get; }

    /// <summary>Checks authority by object identity, not names, credentials or matching endpoints.</summary>
    /// <param name="authority">The provider-instance identity to compare.</param>
    /// <returns>True only for the exact authority supplied at construction.</returns>
    public bool BelongsTo(SecretAuthority authority) => ReferenceEquals(_authority, authority);

    /// <summary>Returns a fixed marker without authority or provider coordinates.</summary>
    public override string ToString() => "[SecretReference]";
}

/// <summary>Provider-owned inventory coordinates bound to one authority.</summary>
public abstract class SecretInventoryScope
{
    private readonly SecretAuthority _authority;

    /// <summary>Binds a provider-specific inventory selection to an authority instance.</summary>
    /// <param name="authority">The identity the inspecting adapter must own.</param>
    /// <exception cref="ArgumentNullException"><paramref name="authority"/> is null.</exception>
    protected SecretInventoryScope(SecretAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        _authority = authority;
    }

    /// <summary>Checks whether this selection belongs to the exact authority instance.</summary>
    /// <param name="authority">The provider-instance identity to compare.</param>
    /// <returns>True only for the authority retained at construction.</returns>
    public bool BelongsTo(SecretAuthority authority) => ReferenceEquals(_authority, authority);

    /// <summary>Returns a fixed marker without inventory coordinates.</summary>
    public sealed override string ToString() => "[SecretInventoryScope]";
}
