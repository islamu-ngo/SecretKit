using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class RotationMaterialEffects
{
    internal const string Prefix = "i.runtime.InfisicalRotationClient.";
    internal const string Selection = "rotationMaterialWitness";

    internal static bool Supports(NativeCaseDefinition row) => row.Key.Provider == "Infisical" &&
        row.Key.Operation is Prefix + "GetAsync" or Prefix + "ListAsync";

    // Parent dispatches here BEFORE deserializing the legacy SQL-only RotationInput.
    // Selection is per original row; absent selection preserves its old gate.
    internal static bool Selected(NativeEnvironment env, NativeCaseDefinition row) =>
        Supports(row) && InfisicalLifecycleFamilies.Input<JsonElement>(env,
            InfisicalRotationClientEffects.Family, row).TryGetProperty(Selection, out _);

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, IInfisicalRotationMaterialSource? source = null,
        HttpMessageHandler? transport = null,
        Func<NativeIdentityRole, InfisicalClient>? consumerFactory = null)
    {
        foreach (var row in expected.Where(Supports))
            registry.Add(new(row, (probe, token) => InfisicalLifecycleFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, row, probe, source, transport, consumerFactory, bounded))));
    }

    internal static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition row,
        NativeCaseProbe probe, IInfisicalRotationMaterialSource? source,
        HttpMessageHandler? offlineTransport, Func<NativeIdentityRole, InfisicalClient>? consumerFactory,
        CancellationToken token)
    {
        InfisicalLifecycleFamilies.Admission(row, probe);
        probe.Contract(Supports(row), NativeFailure.ContractMismatch);
        JsonElement selected = InfisicalLifecycleFamilies.Input<JsonElement>(env,
            InfisicalRotationClientEffects.Family, row).GetProperty(Selection);
        var input = selected.Deserialize<RotationMaterialInput>(InfisicalLifecycleFamilies.Options)
            ?? throw new NativeCaseFailureException("missing-input");
        // Controlled input is deliberately injection-only; it cannot be selected
        // through the native service settings to manufacture native evidence.
        probe.Contract(source is null ? input.Source == RotationMaterialSource.NativeProvider :
            input.Source == RotationMaterialSource.ControlledFixture, NativeFailure.MissingInput);
        if (source is null)
        {
            var observer = InfisicalLifecycleObservers.FromInputs(env, InfisicalRotationClientEffects.Family);
            if (observer is null) probe.Effect(NativeObservation.Unavailable);
            probe.Contract(env.RequireFamilyInput(InfisicalRotationClientEffects.Family)
                .GetProperty("observer").GetProperty("identity").GetString() == input.SourceIdentity,
                NativeFailure.MissingInput);
            source = new InfisicalRotationMaterialSource(observer!, input.SourceIdentity);
        }
        await using var trial = await RotationMaterialTrial.OpenAsync(source!, input, row, token);
        await trial.ArmAsync(token);
        bool denied = row.Key.Case == "denied-authority";
        bool cancel = row.Key.Case == "cancellation-boundary";
        using var transport = new LifecycleTransport(row.Key.Case, offlineTransport);
        using var http = new HttpClient(transport) { Timeout = Timeout.InfiniteTimeSpan };
        var authority = new SecretAuthority();
        var client = new InfisicalRotationClient(env.Origin, authority,
            new(authority, env.Tokens(denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime), input.ProjectId),
            new() { Transport = InfisicalTransportOptions.HostControlled(http) });
        var address = new InfisicalRotationAddress(input.ProjectId, input.Environment, input.Folder,
            input.Profile, input.RotationId);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        // Subscribe before sending, and join the exact cancellation event.
        Task? cancellationTask = cancel ? transport.Reached.Task.ContinueWith(_ => cancellation.Cancel(),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default) : null;
        transport.Arm();
        SecretStatus status = SecretStatus.Unknown;
        try
        {
            if (row.Key.Operation == Prefix + "GetAsync")
            {
                var result = await client.GetAsync(new(authority, address), cancellation.Token);
                status = result.Status;
                if (result.IsSuccess) Validate(result.Value);
            }
            else
            {
                var result = await client.ListAsync(new(authority, new InfisicalRotationScope(input.ProjectId)),
                    input.MaximumItems, cancellation.Token);
                status = result.Status;
                if (result.IsSuccess)
                {
                    probe.Contract(result.Value.Items.Count is > 0 &&
                        result.Value.Items.Count <= input.MaximumItems, NativeFailure.ContractMismatch);
                    foreach (var item in result.Value.Items) Validate(item);
                    probe.Contract(result.Value.Items.Count == 1, NativeFailure.ContractMismatch);
                }
            }
        }
        catch (OperationCanceledException) when (cancel && transport.Reached.Task.IsCompletedSuccessfully &&
            !token.IsCancellationRequested)
        { }
        finally
        {
            transport.Disarm();
            // If construction failed before reaching the event, this continuation
            // has no work to join. Never strand a wait after a synchronous failure.
            if (cancellationTask is not null && transport.Reached.Task.IsCompleted)
                await cancellationTask.WaitAsync(token);
        }
        probe.Contract(status == (cancel ? SecretStatus.Unknown : denied ? SecretStatus.Denied : SecretStatus.Success) &&
            (!cancel || transport.Reached.Task.IsCompletedSuccessfully), NativeFailure.ContractMismatch);
        await using var consumer = consumerFactory is null ? env.CreateRuntimeClient() :
            consumerFactory(NativeIdentityRole.Runtime);
        using var actual = await RotationMaterialPacket.ReadAsync(consumer, input, false, token);
        await using var deniedConsumer = consumerFactory is null ? env.CreateDeniedClient() :
            consumerFactory(NativeIdentityRole.Denied);
        using var deniedRead = await RotationMaterialPacket.ReadAsync(deniedConsumer, input, true, token);
        await trial.AuthenticateAsync(actual, token);
        await trial.CompleteAsync(status, token);
        probe.Effect(NativeObservation.Matched);

        void Validate(InfisicalRotationProgress progress) => probe.Contract(
            progress.Address.Profile == input.Profile && progress.Address.RotationId == input.RotationId &&
            progress.Address.ProjectId == input.ProjectId && progress.Address.Environment == input.Environment &&
            progress.Address.Folder == input.Folder && progress.AutoRotationEnabled == false &&
            !progress.ConsumerDeliveryVerified && !progress.FleetConvergenceVerified,
            NativeFailure.ContractMismatch);
    }
}
