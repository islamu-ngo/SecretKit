using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Samples.Infisical.ConsoleDemo;

internal sealed class ConsoleDemoApplication
{
    private static readonly TimeSpan OperationBudget = TimeSpan.FromSeconds(30);

    // Keep the receipt outside operation scopes so cancellation cannot discard it.
    private MutationReceipt? _receipt;

    internal static Task<int> RunAsync(string[] args)
    {
        ConsoleDemoCommand command = ClassifyCommand(args);
        if (command == ConsoleDemoCommand.Help)
        {
            return Task.FromResult(DemoOutput.Write("help", 0));
        }

        if (command == ConsoleDemoCommand.Invalid)
        {
            return Task.FromResult(DemoOutput.Write("invalid", 2));
        }

        return new ConsoleDemoApplication().ExecuteAsync(command);
    }

    private static ConsoleDemoCommand ClassifyCommand(string[] args) => args switch
    {
        [] or ["--help"] => ConsoleDemoCommand.Help,
        ["read"] => ConsoleDemoCommand.Read,
        ["create"] => ConsoleDemoCommand.Create,
        ["update"] => ConsoleDemoCommand.Update,
        _ => ConsoleDemoCommand.Invalid
    };

    private async Task<int> ExecuteAsync(ConsoleDemoCommand command)
    {
        using var deadline = new CancellationTokenSource(OperationBudget);
        void CancelOperation(object? sender, ConsoleCancelEventArgs eventArgs)
        {
            eventArgs.Cancel = true;
            deadline.Cancel();
        }

        Console.CancelKeyPress += CancelOperation;
        try
        {
            using Stream standardInput = Console.OpenStandardInput();
            if (command == ConsoleDemoCommand.Read)
            {
                using DemoInput input = await DemoInput.ReadAsync(standardInput, deadline.Token);
                return await ReadAsync(input, deadline.Token);
            }

            using MutationInput mutation = await MutationInput.ReadAsync(standardInput, deadline.Token);
            return command switch
            {
                ConsoleDemoCommand.Create => await CreateAsync(mutation, deadline.Token),
                ConsoleDemoCommand.Update => await UpdateAsync(mutation, deadline.Token),
                _ => throw new InvalidOperationException("Invalid command.")
            };
        }
        catch (OperationCanceledException)
        {
            return DemoOutput.Write("cancelled", 5, _receipt?.Evidence);
        }
        catch (Exception exception) when (exception is ArgumentException or JsonException or
            InvalidOperationException or FormatException)
        {
            return DemoOutput.Write("invalid", 2, _receipt?.Evidence);
        }
        catch (Exception)
        {
            // This executable is the boundary: exception text must never reach output.
            return DemoOutput.Write("unavailable", 4, _receipt?.Evidence);
        }
        finally
        {
            Console.CancelKeyPress -= CancelOperation;
        }
    }

    private static async Task<int> ReadAsync(DemoInput input, CancellationToken cancellationToken)
    {
        await using InfisicalClient client = CreateClient(input);
        SecretReference reference = CreateReference(client, input);
        SecretOutcome<SecretRead> result = await client.ReadAsync(reference, cancellationToken);
        if (!result.IsSuccess)
        {
            return ConsoleDemoOutcomes.WriteFailure(result.Status);
        }

        using SecretRead read = result.Value;
        return DemoOutput.Write("success", 0, version: read.Observation.Version);
    }

    private async Task<int> CreateAsync(MutationInput input, CancellationToken cancellationToken)
    {
        await using InfisicalClient client = CreateClient(input.Connection);
        SecretReference reference = CreateReference(client, input.Connection);
        _receipt = new MutationReceipt(reference);

        SecretOutcome<InfisicalStaticChange> result =
            await client.CreateAsync(reference, input.Value, _receipt, cancellationToken);
        return ConsoleDemoOutcomes.WriteChange(result, _receipt);
    }

    private async Task<int> UpdateAsync(MutationInput input, CancellationToken cancellationToken)
    {
        await using InfisicalClient client = CreateClient(input.Connection);
        SecretReference reference = CreateReference(client, input.Connection);
        _receipt = new MutationReceipt(reference);

        SecretOutcome<InfisicalStaticChange> result =
            await client.UpdateValueAsync(reference, input.Value, _receipt, cancellationToken);
        return ConsoleDemoOutcomes.WriteChange(result, _receipt);
    }

    private static InfisicalClient CreateClient(DemoInput input) =>
        new(input.Origin, new DemoTokenSource(input.Token),
            new InfisicalNetworkOptions
            {
                AllowLoopbackDevelopmentHttp = input.DevelopmentHttp
            });

    private static SecretReference CreateReference(InfisicalClient client, DemoInput input) =>
        new(client.Authority,
            new InfisicalSecretAddress(input.Project, input.Environment, input.Folder, input.Key));
}
