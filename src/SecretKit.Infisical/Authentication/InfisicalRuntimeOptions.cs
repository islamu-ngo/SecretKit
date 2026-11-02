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

    /// <summary>Returns a fixed label without selected coordinates or identity.</summary>
    public override string ToString() => "[InfisicalRuntimeOptions]";
}
