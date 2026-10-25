using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Infisical;
using SecretKit.Samples.Infisical;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Samples.Infisical.WebDemo;

// Owns application generations and all admission/collection tasks, not the provider or host.
internal sealed class WebDemoRuntime
{
    private static readonly TimeSpan CollectionTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);
    private const int MaximumCollections = 16;

    private readonly Uri _downstream;
    private readonly CancellationToken _lifetime;
    private readonly List<Task> _collections = [];

    internal WebDemoRuntime(InfisicalClient provider, DemoInput input, WebDemoOptions options,
        CancellationToken lifetime)
    {
        _downstream = options.Downstream;
        _lifetime = lifetime;
        Required = CreateCoordinator(provider, input, input.Key);
        Optional = options.OptionalKey is { } key ? CreateCoordinator(provider, input, key) : null;
    }

    internal RuntimeIntegrationCoordinator Required { get; }
    internal RuntimeIntegrationCoordinator? Optional { get; }

    private RuntimeIntegrationCoordinator CreateCoordinator(InfisicalClient provider, DemoInput input,
        string selectedKey) => new(provider,
        new Dictionary<string, SecretReference>
        {
            ["credential"] = new(provider.Authority,
                new InfisicalSecretAddress(input.Project, input.Environment, input.Folder, selectedKey))
        }, ValidateCandidate, RuntimeStalePolicy.BoundedLastKnown, TimeSpan.FromMinutes(5), TimeProvider.System);

    private ValueTask<SecretOutcome<IRuntimeIntegrationClient>> ValidateCandidate(
        SecretSnapshotHandle candidate, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using SecretRead read = candidate.Read("credential");
        string credential = read.Material.Reveal();
        if (credential.Length is 0 or > 16384 || credential.Any(c => c < 33 || c > 126))
            return ValueTask.FromResult(SecretOutcome<IRuntimeIntegrationClient>.Failure(SecretStatus.Invalid));
        return ValueTask.FromResult(SecretOutcome<IRuntimeIntegrationClient>.Success(
            new JobClient(_downstream, credential)));
    }

    internal void StartOptionalAdmission()
    {
        if (Optional is not null)
            _collections.Add(PrepareOptionalAsync(Optional));
    }

    internal async Task ReadControlsAsync(Stream source)
    {
        while (!_lifetime.IsCancellationRequested)
        {
            byte[]? frame = await DemoInputReader.ReadFrameAsync(source, 64, _lifetime);
            if (frame is null)
                break;
            string command;
            try
            {
                command = Encoding.ASCII.GetString(frame);
            }
            finally
            {
                Array.Clear(frame);
            }
            if (command == "stop")
                break;
            await HandleControlAsync(command);
        }
    }

    private async Task HandleControlAsync(string command)
    {
        switch (command)
        {
            case "disable":
                await Required.DisableAsync();
                WriteObservation("disabled", Required.Observe());
                break;
            case "enable":
            case "check":
                Task[] completed = _collections.Where(task => task.IsCompleted).ToArray();
                await Task.WhenAll(completed);
                foreach (Task task in completed)
                    _collections.Remove(task);
                if (_collections.Count < MaximumCollections)
                    _collections.Add(CollectAsync(command == "enable"));
                else
                    DemoOutput.Write("busy", 4);
                break;
            default:
                DemoOutput.Write("invalid-control", 2);
                break;
        }
    }

    private async Task CollectAsync(bool enable)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(_lifetime);
        budget.CancelAfter(CollectionTimeout);
        try
        {
            // Reserve the desired revision before exposing the collecting event to the operator.
            Task<RuntimeActivationObservation> pending = (enable
                ? Required.EnableAsync(budget.Token) : Required.CheckAgainAsync(budget.Token)).AsTask();
            DemoOutput.Write("collecting", 0);
            WriteObservation(enable ? "enabled" : "checked", await pending);
        }
        catch (OperationCanceledException)
        {
            DemoOutput.Write("cancelled", 5);
        }
        catch (Exception)
        {
            DemoOutput.Write("unavailable", 4);
        }
    }

    private async Task PrepareOptionalAsync(RuntimeIntegrationCoordinator optional)
    {
        // Independent from required startup's budget; retained until shutdown even on cancellation.
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(_lifetime);
        budget.CancelAfter(CollectionTimeout);
        try
        {
            await optional.EnableAsync(budget.Token);
        }
        catch (OperationCanceledException)
        {
            DemoOutput.Write("optional-unavailable", 4);
        }
        catch (Exception)
        {
            DemoOutput.Write("optional-unavailable", 4);
        }
    }

    internal async Task<bool> DrainAsync()
    {
        // Retain and observe every collection and retirement after any bounded waiter expires.
        await Task.WhenAll(_collections);
        Task cleanup = Task.WhenAll(Required.DisposeAsync().AsTask(),
            Optional?.DisposeAsync().AsTask() ?? Task.CompletedTask);
        try
        {
            await cleanup.WaitAsync(DrainTimeout);
            return false;
        }
        catch (TimeoutException)
        {
            DemoOutput.Write("drain-timeout", 4);
            await cleanup;
            return true;
        }
    }

    private static void WriteObservation(string outcome, RuntimeActivationObservation observation) =>
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            outcome,
            active = observation.Active,
            revision = observation.ObservedRevision,
            status = observation.LastStatus.ToString().ToLowerInvariant()
        }));
}
