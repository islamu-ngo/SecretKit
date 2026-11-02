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
        if (runtime.Origin is not { IsAbsoluteUri: true } origin || origin.Scheme != Uri.UriSchemeHttps ||
            origin.UserInfo.Length != 0 || origin.AbsolutePath != "/" ||
            origin.Query.Length != 0 || origin.Fragment.Length != 0)
            return ValidateOptionsResult.Fail("Runtime Origin must be a fixed HTTPS origin.");
        if (!ValidCoordinate(runtime.ClientId) || !ValidCoordinate(runtime.ProjectId) ||
            runtime.OrganizationSlug is { } organization &&
                (organization.Length is < 1 or > 64 || organization.Any(char.IsControl)))
            return ValidateOptionsResult.Fail("Runtime identity and project selection must be valid.");
        if (runtime.TimeProvider is null || runtime.Network is null || runtime.Network.Transport is null ||
            runtime.RenewBefore <= TimeSpan.Zero || runtime.RenewBefore > TimeSpan.FromDays(1) ||
            runtime.RequestTimeout <= TimeSpan.Zero || runtime.RequestTimeout > TimeSpan.FromMinutes(1) ||
            runtime.Network.ShutdownTimeout <= TimeSpan.Zero || runtime.Network.ShutdownTimeout > TimeSpan.FromMinutes(1) ||
            runtime.Network.OperationTimeout <= TimeSpan.Zero || runtime.Network.OperationTimeout > TimeSpan.FromMinutes(1) ||
            runtime.Network.MaximumRequestBytes is < 1024 or > 16 * 1024 * 1024 ||
            runtime.Network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024)
            return ValidateOptionsResult.Fail("Runtime network and timing budgets must be valid.");
        if (runtime.OriginalIssuedAt is not { } original || original > runtime.TimeProvider.GetUtcNow() ||
            runtime.Lifetime == InfisicalTokenLifetime.Finite && (runtime.Period is not null || runtime.AbsoluteLifetimeLimit is not null) ||
            runtime.Lifetime == InfisicalTokenLifetime.Periodic &&
                (runtime.Period is not { } period || period <= runtime.RenewBefore || period > TimeSpan.FromDays(36500) ||
                runtime.AbsoluteLifetimeLimit <= runtime.TimeProvider.GetUtcNow()) ||
            runtime.Lifetime is not (InfisicalTokenLifetime.Finite or InfisicalTokenLifetime.Periodic))
            return ValidateOptionsResult.Fail("Runtime lifetime requires independently established valid evidence.");
        return ValidateOptionsResult.Success;
    }

    private static bool ValidCoordinate(string? value) => !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 1024 && !value.Any(char.IsControl);
}
