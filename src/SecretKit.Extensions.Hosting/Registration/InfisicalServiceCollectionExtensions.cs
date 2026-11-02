using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Explicit composition of already opened Infisical resources, without acquisition or background startup.</summary>
public static class InfisicalServiceCollectionExtensions
{
    /// <summary>Registers one owned, deferred runtime using explicit host options; registration performs no I/O.</summary>
    /// <remarks>The host owns and disposes the runtime. Authentication is lazy on first read or explicit admission.
    /// Configuration is frozen when the runtime is resolved; options reload never replaces a principal.</remarks>
    public static ISecretKitInfisicalBuilder AddSecretKitInfisical(this IServiceCollection services,
        Action<InfisicalHostingOptions> configureOptions) => AddRuntime(services, null, configureOptions);

    /// <summary>Registers an independently owned runtime under an explicit non-null service key.</summary>
    /// <remarks>Each key retains independent options, authority, bootstrap attempt and token lifecycle.</remarks>
    /// <exception cref="ArgumentException">The wildcard key would permit fallback credentials.</exception>
    public static ISecretKitInfisicalBuilder AddKeyedSecretKitInfisical(this IServiceCollection services,
        object serviceKey, Action<InfisicalHostingOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(serviceKey);
        if (ReferenceEquals(serviceKey, KeyedService.AnyKey))
            throw new ArgumentException("A specific service key is required; wildcard credentials are not permitted.", nameof(serviceKey));
        return AddRuntime(services, serviceKey, configureOptions);
    }

    private static RuntimeBuilder AddRuntime(IServiceCollection services, object? key,
        Action<InfisicalHostingOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);
        Type[] contracts = [typeof(InfisicalRuntimeSession), typeof(IInfisicalSecretReader), typeof(ISecretReader),
            typeof(ISecretInventory), typeof(InfisicalClient), typeof(InfisicalSecretScope)];
        if (services.Any(descriptor => contracts.Contains(descriptor.ServiceType) && Equals(descriptor.ServiceKey, key)))
            throw new InvalidOperationException("An Infisical runtime contract is already registered for this key.");
        string name = key is null ? Microsoft.Extensions.Options.Options.DefaultName : Guid.NewGuid().ToString("N");
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<InfisicalHostingOptions>, InfisicalHostingOptionsValidator>());
        services.AddOptions<InfisicalHostingOptions>(name).Configure(configureOptions).ValidateOnStart();
        InfisicalRuntimeSession Create(IServiceProvider provider)
        {
            var options = provider.GetRequiredService<IOptionsMonitor<InfisicalHostingOptions>>().Get(name);
            return InfisicalRuntimeSession.CreateDeferred(options.Runtime!, options.ClientSecret!);
        }
        if (key is null)
        {
            services.AddSingleton(Create);
            services.AddSingleton(provider => provider.GetRequiredService<InfisicalRuntimeSession>().Client);
            services.AddSingleton<IInfisicalSecretReader>(provider => provider.GetRequiredService<InfisicalRuntimeSession>().Client);
            services.AddSingleton<ISecretReader>(provider => provider.GetRequiredService<InfisicalRuntimeSession>().Client);
            services.AddSingleton<ISecretInventory>(provider => provider.GetRequiredService<InfisicalRuntimeSession>().Client);
        }
        else
        {
            services.AddKeyedSingleton<InfisicalRuntimeSession>(key, (provider, _) => Create(provider));
            services.AddKeyedSingleton<InfisicalClient>(key, (provider, _) => provider.GetRequiredKeyedService<InfisicalRuntimeSession>(key).Client);
            services.AddKeyedSingleton<IInfisicalSecretReader>(key, (provider, _) => provider.GetRequiredKeyedService<InfisicalRuntimeSession>(key).Client);
            services.AddKeyedSingleton<ISecretReader>(key, (provider, _) => provider.GetRequiredKeyedService<InfisicalRuntimeSession>(key).Client);
            services.AddKeyedSingleton<ISecretInventory>(key, (provider, _) => provider.GetRequiredKeyedService<InfisicalRuntimeSession>(key).Client);
        }
        return new RuntimeBuilder(services, key, name);
    }

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
            (typeof(IInfisicalSecretReader), runtime.Client),
            (typeof(ISecretReader), runtime.Client),
            (typeof(ISecretInventory), runtime.Client),
            (typeof(InfisicalPeriodicTokenSession), runtime.TokenSession),
            (typeof(IInfisicalTokenSource), runtime.TokenSession)
        ];
        foreach (var alias in aliases)
            if (services.Any(descriptor => !descriptor.IsKeyedService && descriptor.ServiceType == alias.Contract &&
                !ReferenceEquals(descriptor.ImplementationInstance, alias.Instance)))
                throw new InvalidOperationException("A different Infisical runtime contract is already registered.");
        foreach (var alias in aliases)
            if (!services.Any(descriptor => !descriptor.IsKeyedService && descriptor.ServiceType == alias.Contract))
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

    private sealed class RuntimeBuilder(IServiceCollection services, object? key, string optionsName) : ISecretKitInfisicalBuilder
    {
        private bool _scope;
        private bool _admission;
        private bool _health;
        public IServiceCollection Services => services;
        private InfisicalRuntimeSession Runtime(IServiceProvider provider) => key is null
            ? provider.GetRequiredService<InfisicalRuntimeSession>()
            : provider.GetRequiredKeyedService<InfisicalRuntimeSession>(key);

        public ISecretKitInfisicalBuilder WithDefaultScope(string projectId, string environment, string folder = "/")
        {
            _ = new InfisicalSecretAddress(projectId, environment, folder, "validation");
            if (_scope) throw new InvalidOperationException("A default scope is already selected.");
            _scope = true;
            if (key is null)
                services.AddSingleton(provider => Runtime(provider).Client.CreateScope(projectId, environment, folder));
            else
                services.AddKeyedSingleton<InfisicalSecretScope>(key,
                    (provider, _) => Runtime(provider).Client.CreateScope(projectId, environment, folder));
            return this;
        }

        public ISecretKitInfisicalBuilder WithStartupAdmission()
        {
            if (_admission) return this;
            _admission = true;
            services.AddSingleton<IHostedService>(provider => new InfisicalStartupAdmissionService(Runtime(provider),
                provider.GetService<ILogger<InfisicalStartupAdmissionService>>() ?? NullLogger<InfisicalStartupAdmissionService>.Instance));
            return this;
        }

        public ISecretKitInfisicalBuilder WithHealthChecks()
        {
            if (_health) return this;
            _health = true;
            services.AddHealthChecks().Add(new HealthCheckRegistration("secretkit-infisical" +
                (key is null ? string.Empty : "-" + optionsName), provider => new RuntimeHealthCheck(Runtime(provider)), null, null));
            return this;
        }
    }

    private sealed class RuntimeHealthCheck(InfisicalRuntimeSession runtime) : IHealthCheck
    {
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!runtime.IsAuthenticated) return Task.FromResult(HealthCheckResult.Unhealthy());
            return Task.FromResult(runtime.TokenSession.State switch
            {
                InfisicalTokenSessionState.Ready => HealthCheckResult.Healthy(),
                InfisicalTokenSessionState.RenewalDue or InfisicalTokenSessionState.Renewing => HealthCheckResult.Degraded(),
                _ => HealthCheckResult.Unhealthy()
            });
        }
    }
}
