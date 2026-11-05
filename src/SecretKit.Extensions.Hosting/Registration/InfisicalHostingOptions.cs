using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Extensions.Hosting;

/// <summary>Host composition of an explicit immutable runtime selection and one bootstrap material factory.</summary>
/// <remarks>The factory transfers freshly owned material and is invoked at most once per runtime.
/// Registration and options validation perform no credential acquisition or network I/O.</remarks>
public sealed class InfisicalHostingOptions
{
    /// <summary>Explicit identity, origin, network and independently established lifetime policy.</summary>
    [JsonIgnore]
    public InfisicalRuntimeOptions? Runtime { get; set; }

    /// <summary>Transfers one newly owned bootstrap material when authentication is explicitly admitted.</summary>
    [JsonIgnore]
    public Func<CancellationToken, ValueTask<SecretMaterial>>? ClientSecret { get; set; }

    /// <summary>Returns a fixed label without selected coordinates or credentials.</summary>
    public override string ToString() => "[InfisicalHostingOptions]";
}

internal sealed class InfisicalHostingOptionsValidator : IValidateOptions<InfisicalHostingOptions>
{
    public ValidateOptionsResult Validate(string? name, InfisicalHostingOptions options)
    {
        if (options.Runtime is not { } runtime || options.ClientSecret is null)
            return ValidateOptionsResult.Fail("An explicit runtime and bootstrap material factory are required.");
        try { runtime.ValidateForBootstrap(); }
        catch (ArgumentException)
        {
            return ValidateOptionsResult.Fail("Runtime context or network selection is invalid.");
        }
        if (runtime.OriginalIssuedAt is not { } original || original > runtime.TimeProvider.GetUtcNow() ||
            runtime.Lifetime == InfisicalTokenLifetime.Finite && (runtime.Period is not null || runtime.AbsoluteLifetimeLimit is not null) ||
            runtime.Lifetime == InfisicalTokenLifetime.Periodic &&
                (runtime.Period is not { } period || period <= runtime.RenewBefore || period > TimeSpan.FromDays(36500) ||
                runtime.AbsoluteLifetimeLimit <= runtime.TimeProvider.GetUtcNow()) ||
            runtime.Lifetime is not (InfisicalTokenLifetime.Finite or InfisicalTokenLifetime.Periodic))
            return ValidateOptionsResult.Fail("Runtime lifetime requires independently established valid evidence.");
        return ValidateOptionsResult.Success;
    }
}
