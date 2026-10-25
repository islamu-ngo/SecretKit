using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using SecretKit.Infisical;
using SecretKit.Samples.Infisical;

namespace SecretKit.Samples.Infisical.WebDemo;

internal static class WebDemoApplication
{
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(5);

    internal static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || args is ["--help"])
            return DemoOutput.Write("help", 0);
        if (args is not ["serve"])
            return DemoOutput.Write("invalid", 2);

        // Process-boundary errors deliberately reveal categories, never exception details.
        try
        {
            return await ServeAsync();
        }
        catch (OperationCanceledException)
        {
            return DemoOutput.Write("cancelled", 5);
        }
        catch (Exception exception) when (exception is ArgumentException or JsonException or FormatException)
        {
            return DemoOutput.Write("invalid", 2);
        }
        catch (Exception)
        {
            return DemoOutput.Write("unavailable", 4);
        }
    }

    private static async Task<int> ServeAsync()
    {
        using var lifetime = new CancellationTokenSource();
        using var startup = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        startup.CancelAfter(StartupTimeout);
        ConsoleCancelEventHandler cancel = (_, e) =>
        {
            e.Cancel = true;
            lifetime.Cancel();
        };
        Console.CancelKeyPress += cancel;
        try
        {
            Stream source = Console.OpenStandardInput();
            using DemoInput input = await ReadInputAsync(source, startup.Token);
            WebDemoOptions options = await WebDemoOptions.ReadAsync(source, startup.Token);
            await using var provider = new InfisicalClient(input.Origin, new DemoTokenSource(input.Token),
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = input.DevelopmentHttp });
            var runtime = new WebDemoRuntime(provider, input, options, lifetime.Token);
            WebApplication? app = null;
            try
            {
                if (!(await runtime.Required.EnableAsync(startup.Token)).Active)
                    return DemoOutput.Write("unavailable", 4);
                runtime.StartOptionalAdmission();
                app = CreateApplication(runtime);
                await app.StartAsync(startup.Token);
                WriteListening(app);
                await runtime.ReadControlsAsync(source);
                return DemoOutput.Write("stopping", 0);
            }
            finally
            {
                lifetime.Cancel();
                await StopAsync(app, runtime);
            }
        }
        finally
        {
            Console.CancelKeyPress -= cancel;
        }
    }

    private static async Task<DemoInput> ReadInputAsync(Stream source, CancellationToken token)
    {
        byte[] frame = await DemoInputReader.ReadFrameAsync(source, 65536, token) ??
            throw new ArgumentException("Missing input.");
        try
        {
            using var content = new MemoryStream(frame);
            return await DemoInput.ReadAsync(content, token);
        }
        finally
        {
            Array.Clear(frame);
        }
    }

    private static WebApplication CreateApplication(WebDemoRuntime runtime)
    {
        // Empty configuration excludes environment/CLI listener and developer defaults.
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Production"
        });
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(ConfigureKestrel);
        WebApplication app = builder.Build();
        var endpoints = new WebDemoEndpoints(runtime.Required, runtime.Optional);
        app.Run(endpoints.HandleAsync);
        return app;
    }

    private static void ConfigureKestrel(Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions options)
    {
        options.Listen(IPAddress.Loopback, 0);
        options.Limits.MaxRequestBodySize = 0;
    }

    private static void WriteListening(WebApplication app)
    {
        string address = app.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!.Addresses.Single();
        Console.WriteLine(JsonSerializer.Serialize(new { outcome = "listening", address }));
    }

    private static async Task StopAsync(WebApplication? app, WebDemoRuntime runtime)
    {
        bool timedOut = false;
        try
        {
            try
            {
                if (app is not null)
                {
                    using var stop = new CancellationTokenSource(ShutdownTimeout);
                    try
                    {
                        await app.StopAsync(stop.Token);
                    }
                    catch (OperationCanceledException) when (stop.IsCancellationRequested)
                    {
                        // Cancellation is classified below even if Kestrel returns normally.
                    }
                    if (stop.IsCancellationRequested)
                    {
                        timedOut = true;
                        DemoOutput.Write("stop-timeout", 4);
                    }
                }
            }
            finally
            {
                timedOut |= await runtime.DrainAsync();
            }
        }
        finally
        {
            if (app is not null)
                await app.DisposeAsync();
        }
        if (timedOut)
            throw new InvalidOperationException("Shutdown did not drain within its budget.");
    }
}
