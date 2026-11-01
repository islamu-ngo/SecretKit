using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Explicit composition of already opened Infisical resources, without acquisition or background startup.</summary>
public static class InfisicalServiceCollectionExtensions
{
    /// <summary>Borrows the runtime and its narrow contracts without transferring disposal ownership.</summary>
    /// <param name="services">The host's service collection.</param>
    /// <param name="runtime">An already opened, application-owned runtime.</param>
    /// <returns>The same collection.</returns>
    /// <exception cref="InvalidOperationException">A different owner already occupies an alias.</exception>
    public static IServiceCollection AddInfisicalRuntime(this IServiceCollection services,
        InfisicalRuntimeSession runtime)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(runtime);
        (Type Contract, object Instance)[] aliases =
        [
            (typeof(InfisicalRuntimeSession), runtime),
            (typeof(InfisicalClient), runtime.Client),
            (typeof(ISecretReader), runtime.Client),
            (typeof(ISecretInventory), runtime.Client),
            (typeof(InfisicalPeriodicTokenSession), runtime.TokenSession),
            (typeof(IInfisicalTokenSource), runtime.TokenSession)
        ];
        foreach (var alias in aliases)
            if (services.Any(descriptor => descriptor.ServiceType == alias.Contract &&
                !ReferenceEquals(descriptor.ImplementationInstance, alias.Instance)))
                throw new InvalidOperationException("A different Infisical runtime contract is already registered.");
        foreach (var alias in aliases)
            if (!services.Any(descriptor => descriptor.ServiceType == alias.Contract))
                services.Add(ServiceDescriptor.Singleton(alias.Contract, alias.Instance));
        return services;
    }

    /// <summary>Explicitly opts into one host-started maintenance helper for the borrowed runtime.</summary>
    /// <param name="services">The host's service collection.</param>
    /// <param name="runtime">The application-owned runtime dedicated to this helper's session lifecycle.</param>
    /// <param name="shutdownTimeout">The helper's positive shutdown budget, at most one minute.</param>
    /// <returns>The same collection.</returns>
    /// <exception cref="InvalidOperationException">A different owner or maintenance selection is registered.</exception>
    public static IServiceCollection AddInfisicalAuthenticationMaintenance(this IServiceCollection services,
        InfisicalRuntimeSession runtime, TimeSpan shutdownTimeout)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(runtime);
        if (shutdownTimeout <= TimeSpan.Zero || shutdownTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(shutdownTimeout));
        ServiceDescriptor? selected = services.SingleOrDefault(descriptor =>
            descriptor.ServiceType == typeof(MaintenanceSelection));
        if (selected is not null)
        {
            if (selected.ImplementationInstance is not MaintenanceSelection selection ||
                !ReferenceEquals(selection.Runtime, runtime) || selection.ShutdownTimeout != shutdownTimeout)
                throw new InvalidOperationException("A different Infisical maintenance selection is already registered.");
            return services.AddInfisicalRuntime(runtime);
        }
        if (services.Any(descriptor => descriptor.ServiceType == typeof(InfisicalAuthenticationMaintenance)))
            throw new InvalidOperationException("Infisical maintenance is already registered independently.");
        services.AddInfisicalRuntime(runtime);
        services.AddSingleton(new MaintenanceSelection(runtime, shutdownTimeout));
        // These factories create/capture only the new helper, never borrowed runtime aliases.
        services.AddSingleton(_ => new InfisicalAuthenticationMaintenance(runtime.TokenSession, shutdownTimeout));
        services.AddSingleton<IHostedService>(provider =>
            provider.GetRequiredService<InfisicalAuthenticationMaintenance>());
        services.AddSingleton<IHealthCheck>(provider =>
            provider.GetRequiredService<InfisicalAuthenticationMaintenance>());
        return services;
    }

    private sealed record MaintenanceSelection(InfisicalRuntimeSession Runtime, TimeSpan ShutdownTimeout);
}
