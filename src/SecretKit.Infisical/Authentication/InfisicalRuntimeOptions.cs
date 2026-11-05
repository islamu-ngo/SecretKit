using System.Text.Json.Serialization;

namespace SecretKit.Infisical;

/// <summary>Immutable, explicit runtime context and independently established lifetime policy.</summary>
/// <remarks>Selection grants no provider authority. No option discovers credentials or starts maintenance.</remarks>
public sealed class InfisicalRuntimeOptions
{
    /// <summary>The explicitly selected provider origin.</summary>
    [JsonIgnore]
    public required Uri Origin { get; init; }

    /// <summary>The explicit Universal Auth client identity, required only for bootstrap opening; token handoff may omit it.</summary>
    [JsonIgnore]
    public string ClientId { get; init; } = string.Empty;

    /// <summary>The selected project context; borrowed native clients still require explicit addresses.</summary>
    [JsonIgnore]
    public required string ProjectId { get; init; }

    /// <summary>The optional explicitly selected organization.</summary>
    [JsonIgnore]
    public string? OrganizationSlug { get; init; }

    /// <summary>Independently established policy for opening; a reported zero maximum does not establish periodicity.</summary>
    public InfisicalTokenLifetime Lifetime { get; init; }

    /// <summary>Verified original issuance or an explicitly conservative lower bound; missing timing requires recovery.</summary>
    public DateTimeOffset? OriginalIssuedAt { get; init; }

    /// <summary>Independently verified periodic interval when opening a periodic session.</summary>
    public TimeSpan? Period { get; init; }

    /// <summary>Optional independently established absolute ceiling for periodic policy.</summary>
    public DateTimeOffset? AbsoluteLifetimeLimit { get; init; }

    /// <summary>Positive renewal margin, at most one day; reads never initiate renewal.</summary>
    public TimeSpan RenewBefore { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>Explicit renewal request timeout, positive and at most one minute.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Frozen networking selection shared by owned children; supplied pipelines remain host-owned.</summary>
    [JsonIgnore]
    public InfisicalNetworkOptions Network { get; init; } = new();

    /// <summary>Clock for admission, expiry and the original aggregate shutdown deadline.</summary>
    [JsonIgnore]
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Validates bootstrap context, origin and budgets without acquiring credentials or performing I/O.</summary>
    /// <remarks>Opening still requires separately admitted lifetime evidence and provider authorization.</remarks>
    /// <exception cref="ArgumentException">The context, transport selection or budgets are invalid.</exception>
    public void ValidateForBootstrap() => ValidateContext(bootstrap: true);

    /// <summary>Validates supplied-token context without requiring a bootstrap client identity or acquiring credentials.</summary>
    /// <remarks>The token's admitted lifetime evidence is validated separately.</remarks>
    /// <exception cref="ArgumentException">The context, transport selection or budgets are invalid.</exception>
    public void ValidateForTokenHandoff() => ValidateContext(bootstrap: false);

    private void ValidateContext(bool bootstrap)
    {
        ArgumentNullException.ThrowIfNull(Origin);
        ArgumentNullException.ThrowIfNull(Network);
        ArgumentNullException.ThrowIfNull(TimeProvider);
        InfisicalTransportBinding.ValidateOrigin(Origin, Network);
        if (bootstrap && (string.IsNullOrWhiteSpace(ClientId) || ClientId.Length > 1024 ||
            ClientId.Any(char.IsControl)) || string.IsNullOrWhiteSpace(ProjectId) ||
            ProjectId.Length > 1024 || ProjectId.Any(char.IsControl) ||
            OrganizationSlug is { } organization &&
                (organization.Length is < 1 or > 64 || organization.Any(char.IsControl)) ||
            RenewBefore <= TimeSpan.Zero || RenewBefore > TimeSpan.FromDays(1) ||
            RequestTimeout <= TimeSpan.Zero || RequestTimeout > TimeSpan.FromMinutes(1) ||
            Network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            Network.ShutdownTimeout <= TimeSpan.Zero || Network.ShutdownTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentException("Invalid runtime context or budget.");
    }

    /// <summary>Returns a fixed label without selected coordinates or identity.</summary>
    public override string ToString() => "[InfisicalRuntimeOptions]";
}
