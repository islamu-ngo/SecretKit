using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

namespace SecretKit.Hosting.Tests;

public sealed class HostingRegistrationTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ResolvedBorrowedAliasesSurviveContainerDisposal(bool asynchronous)
    {
        using var wire = new RegistrationWire();
        await using InfisicalRuntimeSession runtime = Runtime(wire);
        var services = new ServiceCollection();
        services.AddInfisicalRuntime(runtime);
        int count = services.Count;
        services.AddInfisicalRuntime(runtime);
        await Assert.That(services.Count).IsEqualTo(count);
        ServiceProvider provider = services.BuildServiceProvider();
        await Assert.That(provider.GetRequiredService<InfisicalRuntimeSession>()).IsSameReferenceAs(runtime);
        await Assert.That(provider.GetRequiredService<InfisicalClient>()).IsSameReferenceAs(runtime.Client);
        await Assert.That(provider.GetRequiredService<ISecretReader>()).IsSameReferenceAs(runtime.Client);
        await Assert.That(provider.GetRequiredService<ISecretInventory>()).IsSameReferenceAs(runtime.Client);
        await Assert.That(provider.GetRequiredService<InfisicalPeriodicTokenSession>()).IsSameReferenceAs(runtime.TokenSession);
        await Assert.That(provider.GetRequiredService<IInfisicalTokenSource>()).IsSameReferenceAs(runtime.TokenSession);
        await Assert.That(provider.GetServices<IHostedService>().Any()).IsFalse();
        await Assert.That(wire.Requests).IsEqualTo(0);
        if (asynchronous)
            await provider.DisposeAsync();
        else
            provider.Dispose();
        var token = await runtime.TokenSession.GetTokenAsync(CancellationToken.None);
        await Assert.That(token.IsSuccess).IsTrue();
        using var owned = token.Value;
        await Assert.That(owned.Material.Reveal()).IsEqualTo("registration-token");
        var reference = new SecretReference(runtime.Client.Authority,
            new InfisicalSecretAddress("selected-project", "test", "/", "key"));
        var read = await runtime.Client.ReadAsync(reference);
        await Assert.That(read.IsSuccess).IsTrue();
        using SecretRead independent = read.Value;
        await Assert.That(independent.Material.Reveal()).IsEqualTo("registered-value");
        await Assert.That(wire.Disposed).IsFalse();
    }

    [Test]
    public async Task DifferentOwnersAreRejectedByBothEntryPoints()
    {
        await using InfisicalRuntimeSession first = Runtime();
        await using InfisicalRuntimeSession second = Runtime();
        var services = new ServiceCollection();
        services.AddInfisicalRuntime(first);
        await Assert.That(() => services.AddInfisicalRuntime(second)).Throws<InvalidOperationException>();
        await Assert.That(() => services.AddInfisicalAuthenticationMaintenance(second, TimeSpan.FromSeconds(5)))
            .Throws<InvalidOperationException>();
        services.AddInfisicalAuthenticationMaintenance(first, TimeSpan.FromSeconds(5));
        int count = services.Count;
        services.AddInfisicalAuthenticationMaintenance(first, TimeSpan.FromSeconds(5));
        await Assert.That(services.Count).IsEqualTo(count);
        await Assert.That(() => services.AddInfisicalAuthenticationMaintenance(second, TimeSpan.FromSeconds(5)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MaintenanceIsExplicitAndEndsOnlyTheBorrowedSessionGeneration()
    {
        await using InfisicalRuntimeSession runtime = Runtime();
        var services = new ServiceCollection();
        services.AddInfisicalAuthenticationMaintenance(runtime, TimeSpan.FromSeconds(5));
        await using ServiceProvider provider = services.BuildServiceProvider();
        InfisicalAuthenticationMaintenance helper = provider.GetRequiredService<InfisicalAuthenticationMaintenance>();
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.NotStarted);
        await Assert.That(provider.GetServices<IHostedService>().Single()).IsSameReferenceAs(helper);
        await Assert.That(provider.GetServices<IHealthCheck>().Single()).IsSameReferenceAs(helper);
        var token = await runtime.TokenSession.GetTokenAsync(CancellationToken.None);
        using InfisicalAccessToken independent = token.Value;
        await helper.StartAsync(CancellationToken.None);
        await Assert.That(helper.State).IsEqualTo(AuthenticationMaintenanceState.Ready);
        await helper.StopAsync(CancellationToken.None);
        await helper.StopAsync(CancellationToken.None);
        await Assert.That(runtime.TokenSession.State).IsEqualTo(InfisicalTokenSessionState.Stopped);
        await Assert.That(independent.Material.Reveal()).IsEqualTo("registration-token");
        // Aggregate disposal is still the application's responsibility.
        await Assert.That(provider.GetRequiredService<InfisicalRuntimeSession>()).IsSameReferenceAs(runtime);
    }

    private static InfisicalRuntimeSession Runtime(HttpMessageHandler? transport = null)
    {
        using SecretMaterial token = SecretMaterial.FromText("registration-token");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var evidence = new InfisicalTokenLifetimeEvidence
        {
            OriginalIssuedAt = now.AddSeconds(-1),
            ExpiresAt = now.AddHours(1),
            Lifetime = InfisicalTokenLifetime.Finite,
            ReportedMaximumTtl = TimeSpan.FromHours(2)
        };
        var options = new InfisicalRuntimeOptions
        {
            Origin = new Uri("https://vault.invalid"),
            ProjectId = "selected-project",
            Lifetime = InfisicalTokenLifetime.Finite,
            RenewBefore = TimeSpan.FromSeconds(10),
            RequestTimeout = TimeSpan.FromSeconds(5),
            Network = new InfisicalNetworkOptions
            {
                Transport = transport is null ? InfisicalTransportOptions.SafeDefault :
                    InfisicalTransportOptions.HostControlled(transport)
            }
        };
        var result = InfisicalRuntimeSession.CreateFromToken(options, token, evidence);
        if (!result.IsSuccess)
            throw new InvalidOperationException("Controlled runtime was not admitted.");
        return result.Value;
    }

    private sealed class RegistrationWire : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        internal bool Disposed { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests++;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"secret":{"secretValue":"registered-value","secretKey":"key","secretValueHidden":false}}""")
            });
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
