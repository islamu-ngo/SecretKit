using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

namespace SecretKit.Samples.Infisical.WorkerDemo;

internal static class WorkerDemoApplication
{
    private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(5);

    internal static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || args is ["--help"])
            return DemoOutput.Write("help", 0);
        if (args is not (["run"] or ["run", "--maintain"]))
            return DemoOutput.Write("invalid", 2);

        using var deadline = new CancellationTokenSource(OperationTimeout);
        ConsoleCancelEventHandler cancel = (_, e) =>
        {
            e.Cancel = true;
            deadline.Cancel();
        };
        Console.CancelKeyPress += cancel;
        try
        {
            bool maintain = args.Length == 2;
            return await RunSelectedSessionAsync(maintain, deadline.Token);
        }
        catch (OperationCanceledException)
        {
            return DemoOutput.Write("cancelled", 5);
        }
        catch (Exception exception) when (exception is ArgumentException or JsonException or
            FormatException or InvalidOperationException or KeyNotFoundException or OverflowException)
        {
            return DemoOutput.Write("invalid", 2);
        }
        catch (TimeoutException)
        {
            return DemoOutput.Write("shutdown-timeout", 6);
        }
        catch (Exception)
        {
            return DemoOutput.Write("unavailable", 4);
        }
        finally
        {
            Console.CancelKeyPress -= cancel;
        }
    }

    private static async Task<int> RunSelectedSessionAsync(bool maintain, CancellationToken cancellationToken)
    {
        using var controls = new BufferedStream(Console.OpenStandardInput(), 4096);
        using WorkerInput input = await WorkerInput.ReadAsync(controls, cancellationToken);
        DemoInput connection = input.Connection;
        var network = new InfisicalNetworkOptions
        {
            AllowLoopbackDevelopmentHttp = connection.DevelopmentHttp,
            ShutdownTimeout = ShutdownTimeout
        };
        await using var session = new InfisicalPeriodicTokenSession(connection.Origin,
            connection.ExistingToken, input.LifetimeEvidence, OperationTimeout, ShutdownTimeout, network);
        await using var client = new InfisicalClient(connection.Origin, session, network);
        var reference = new SecretReference(client.Authority,
            new InfisicalSecretAddress(connection.Project, connection.Environment, connection.Folder, connection.Key));

        // Admission must finish before dependent services are constructed or started.
        SecretStatus admission = await ReadRequiredSecretAsync(client, reference, cancellationToken);
        if (admission != SecretStatus.Success)
            return DemoOutput.Write(Category(admission), 4);
        DemoOutput.Write("prepared", 0);

        // Supplied instances remain application-owned, outside the DI container.
        await using var maintenance = new InfisicalAuthenticationMaintenance(session, ShutdownTimeout);
        using var worker = new SecretWorker(client, reference, session, controls, maintain, cancellationToken);
        using IHost host = BuildHost(worker, maintenance, maintain);
        int result = await RunHostAsync(host, worker, cancellationToken);
        return result == 0 ? DemoOutput.Write("stopped", 0) : result;
    }

    private static async Task<SecretStatus> ReadRequiredSecretAsync(
        InfisicalClient client, SecretReference reference, CancellationToken cancellationToken)
    {
        var admission = await client.ReadAsync(reference, cancellationToken);
        if (admission.IsSuccess)
            admission.Value.Dispose();
        return admission.Status;
    }

    private static IHost BuildHost(SecretWorker worker,
        InfisicalAuthenticationMaintenance maintenance, bool maintain)
    {
        return new HostBuilder()
            .ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureServices(services =>
            {
                services.Configure<HostOptions>(options => options.ShutdownTimeout = ShutdownTimeout);
                if (maintain)
                    services.AddSingleton<IHostedService>(maintenance);
                services.AddSingleton<IHostedService>(worker);
            })
            .Build();
    }

    private static async Task<int> RunHostAsync(
        IHost host, SecretWorker worker, CancellationToken cancellationToken)
    {
        try
        {
            await host.StartAsync(cancellationToken);
            return await worker.Completion.WaitAsync(cancellationToken);
        }
        finally
        {
            await StopAndDrainAsync(host, worker);
        }
    }

    private static async Task StopAndDrainAsync(IHost host, SecretWorker worker)
    {
        // Stop work and maintenance before disposing their session and client.
        using var shutdown = new CancellationTokenSource(ShutdownTimeout);
        try
        {
            await host.StopAsync(shutdown.Token);
            await worker.Completion.WaitAsync(shutdown.Token);
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
        {
            throw new TimeoutException();
        }
    }

    private static string Category(SecretStatus status) => status == SecretStatus.RecoveryRequired
        ? "recovery-required" : status.ToString().ToLowerInvariant();
}
