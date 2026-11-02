using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Samples.Infisical.WorkerDemo;

internal sealed class SecretWorker(InfisicalClient client, SecretReference reference,
    InfisicalPeriodicTokenSession session, Stream controls, bool maintain,
    CancellationToken operation) : BackgroundService
{
    private readonly TaskCompletionSource<int> _completion =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _result;

    internal Task<int> Completion => _completion.Task;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var requestedStop = new CancellationTokenSource();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(operation, stoppingToken,
            requestedStop.Token);
        var commands = Channel.CreateBounded<string>(new BoundedChannelOptions(1)
        {
            SingleReader = true,
            SingleWriter = true
        });
        DemoOutput.Write("started", 0);
        // Console input may complete synchronously; control intake must not block work.
        Task reader = Task.Run(
            () => ReadControlsAsync(commands.Writer, requestedStop, linked.Token), CancellationToken.None);
        try
        {
            await ProcessCommandsAsync(commands.Reader, linked.Token);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            if (!requestedStop.IsCancellationRequested)
                _result = DemoOutput.Write("cancelled", 5);
        }
        catch (ArgumentException)
        {
            _result = DemoOutput.Write("invalid", 2);
        }
        catch (Exception)
        {
            // Do not let BackgroundService route protected exception text to host sinks.
            _result = DemoOutput.Write("unavailable", 4);
        }
        finally
        {
            linked.Cancel();
            await reader;
            _completion.TrySetResult(_result);
        }
    }

    private async Task ReadControlsAsync(ChannelWriter<string> commands,
        CancellationTokenSource requestedStop, CancellationToken cancellationToken)
    {
        try
        {
            while (await DemoInputReader.ReadFrameAsync(controls, 16, cancellationToken) is { } frame)
            {
                try
                {
                    if (frame.AsSpan().SequenceEqual("stop"u8))
                    {
                        requestedStop.Cancel();
                        break;
                    }
                    string command = ReadCommand(frame);
                    await commands.WriteAsync(command, cancellationToken);
                }
                finally
                {
                    Array.Clear(frame);
                }
            }
            commands.TryComplete();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            commands.TryComplete();
        }
        catch (Exception exception)
        {
            commands.TryComplete(exception);
        }
    }

    private string ReadCommand(byte[] frame)
    {
        if (frame.AsSpan().SequenceEqual("work"u8))
            return "work";
        if (maintain && frame.AsSpan().SequenceEqual("renew"u8))
            return "renew";
        throw new ArgumentException("Invalid control.");
    }

    private async Task ProcessCommandsAsync(ChannelReader<string> commands, CancellationToken cancellationToken)
    {
        await foreach (string command in commands.ReadAllAsync(cancellationToken))
        {
            if (_result != 0)
            {
                // Only a new, separately authorized process may replace this session.
                DemoOutput.Write("recovery-required", 4);
                continue;
            }
            _result = command switch
            {
                "renew" => await RenewSessionAsync(cancellationToken),
                _ => await WorkAsync(cancellationToken)
            };
        }
    }

    private async Task<int> WorkAsync(CancellationToken cancellationToken)
    {
        var outcome = await client.ReadAsync(reference, cancellationToken);
        if (!outcome.IsSuccess)
        {
            string category = outcome.Status == SecretStatus.RecoveryRequired
                ? "recovery-required" : outcome.Status.ToString().ToLowerInvariant();
            return DemoOutput.Write(category, 4);
        }
        using SecretRead read = outcome.Value;
        return DemoOutput.Write("success", 0, version: read.Observation.Version);
    }

    private async Task<int> RenewSessionAsync(CancellationToken cancellationToken)
    {
        // Establish the native start/join task before the observable awaiting barrier.
        ValueTask<SecretStatus> renewal = session.RenewAsync(cancellationToken);
        DemoOutput.Write("renewal-awaiting", 0);
        SecretStatus status = await renewal;
        return status == SecretStatus.Success
            ? DemoOutput.Write("renewed", 0)
            : DemoOutput.Write("recovery-required", 4);
    }
}
