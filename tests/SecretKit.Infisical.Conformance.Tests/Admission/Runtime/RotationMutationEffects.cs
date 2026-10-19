using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class RotationMutationEffects
{
    internal const string Prefix = "i.runtime.InfisicalRotationClient.";
    internal const string Selection = "rotationMutationWitness";
    internal static bool Supports(NativeCaseDefinition row) => row.Key.Provider == "Infisical" &&
        row.Key.Operation is Prefix + "RotateSecretsAsync" or Prefix + "SetAutomaticRotationAsync";
    internal static bool Selected(NativeEnvironment env, NativeCaseDefinition row) => Supports(row) &&
        InfisicalLifecycleFamilies.Input<JsonElement>(env, InfisicalRotationClientEffects.Family, row)
            .TryGetProperty(Selection, out _);

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, IInfisicalRotationMutationSource? source = null,
        HttpMessageHandler? transport = null, Func<NativeIdentityRole, InfisicalClient>? consumers = null)
    {
        foreach (var row in expected.Where(Supports))
            registry.Add(new(row, (probe, token) => InfisicalLifecycleFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, row, probe, source, transport, consumers, bounded))));
    }

    // Parent calls this before the legacy SQL-only RotationInput deserialization.
    internal static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition row,
        NativeCaseProbe probe, IInfisicalRotationMutationSource? source, HttpMessageHandler? offlineTransport,
        Func<NativeIdentityRole, InfisicalClient>? consumers, CancellationToken token)
    {
        InfisicalLifecycleFamilies.Admission(row, probe);
        probe.Contract(Supports(row), NativeFailure.ContractMismatch);
        var input = InfisicalLifecycleFamilies.Input<JsonElement>(env,
            InfisicalRotationClientEffects.Family, row).GetProperty(Selection)
            .Deserialize<RotationMutationInput>(InfisicalLifecycleFamilies.Options)
            ?? throw new NativeCaseFailureException("missing-input");
        var m = input.Material;
        probe.Contract(source is null ? m.Source == RotationMaterialSource.NativeProvider :
            m.Source == RotationMaterialSource.ControlledFixture, NativeFailure.MissingInput);
        if (source is null)
        {
            var channel = InfisicalLifecycleObservers.FromInputs(env, InfisicalRotationClientEffects.Family);
            if (channel is null) probe.Effect(NativeObservation.Unavailable);
            probe.Contract(env.RequireFamilyInput(InfisicalRotationClientEffects.Family).GetProperty("observer")
                .GetProperty("identity").GetString() == m.SourceIdentity, NativeFailure.MissingInput);
            source = new InfisicalRotationMutationSource(channel!, m.SourceIdentity);
        }
        bool manual = row.Key.Operation == Prefix + "RotateSecretsAsync";
        bool enabled = row.Key.Variant == "enabled.true" || row.Key.Variant != "enabled.false" && input.Enabled;
        var action = manual ? InfisicalRotationAction.RotateSecrets : enabled ?
            InfisicalRotationAction.EnableAutomaticRotation : InfisicalRotationAction.DisableAutomaticRotation;
        var precondition = Precondition(row.Key.Variant);
        await using var trial = await RotationMutationTrial.OpenAsync(source!, input, row, action, precondition, token);
        bool denied = row.Key.Case == "denied-authority";
        bool cancel = row.Key.Case == "cancellation-boundary" && precondition == InfisicalRotationPrecondition.None;
        bool lost = row.Key.Case == "lost-response-no-replay" && precondition == InfisicalRotationPrecondition.None;
        using var transport = new BoundaryTransport(cancel, lost, offlineTransport);
        using var http = new HttpClient(transport) { Timeout = Timeout.InfiniteTimeSpan };
        var authority = new SecretAuthority();
        var client = new InfisicalRotationClient(env.Origin, http, authority,
            new(authority, env.Tokens(denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime), m.ProjectId));
        var target = new SecretReference(authority,
            new InfisicalRotationAddress(m.ProjectId, m.Environment, m.Folder, m.Profile, m.RotationId));
        var receipt = new InfisicalRotationReceipt(target, action);
        await trial.ArmAsync(token);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        // The event is after the original upstream response headers, never a
        // pre-send no-occurrence claim. Subscribe before the public SDK call.
        Task? cancelTask = cancel ? transport.Reached.Task.ContinueWith(_ => cancellation.Cancel(),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default) : null;
        SecretStatus status = SecretStatus.Unknown;
        try
        {
            status = manual ? (await client.RotateSecretsAsync(target, receipt, precondition, cancellation.Token)).Status :
                (await client.SetAutomaticRotationAsync(target, enabled, receipt, precondition, cancellation.Token)).Status;
        }
        catch (OperationCanceledException) when (cancel && transport.Reached.Task.IsCompletedSuccessfully &&
            !token.IsCancellationRequested)
        { }
        finally
        {
            if (cancelTask is not null && transport.Reached.Task.IsCompleted)
                await cancelTask.WaitAsync(token);
        }
        bool rejected = precondition != InfisicalRotationPrecondition.None;
        probe.Contract(status == (rejected ? SecretStatus.Unsupported : cancel || lost ? SecretStatus.Unknown :
            denied ? SecretStatus.Denied : SecretStatus.Success), NativeFailure.ContractMismatch);
        probe.Contract(!(cancel || lost) || transport.Reached.Task.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
        var original = RotationMutationReceipt.Capture(trial.Root, receipt, status);
        probe.Contract(original.Dispatch == (rejected ? InfisicalRotationDispatch.NotDispatched :
            cancel || lost ? InfisicalRotationDispatch.ResponseUnknown : denied ? InfisicalRotationDispatch.Rejected :
            InfisicalRotationDispatch.ResponseObserved) &&
            original.Effect == (rejected || denied || cancel || lost ? InfisicalRotationEffect.Unknown : manual ?
                InfisicalRotationEffect.AcceptedPending : InfisicalRotationEffect.AutomaticRotationSettingApplied),
            NativeFailure.ContractMismatch);
        var settledInput = await trial.SettleAsync(original, token);
        await using var consumer = consumers is null ? env.CreateRuntimeClient() : consumers(NativeIdentityRole.Runtime);
        using var actual = await RotationMaterialPacket.ReadAsync(consumer, settledInput, false, token);
        await using var deniedConsumer = consumers is null ? env.CreateDeniedClient() : consumers(NativeIdentityRole.Denied);
        using var deniedRead = await RotationMaterialPacket.ReadAsync(deniedConsumer, settledInput, true, token);
        await trial.AuthenticateAsync(actual, token);
        // Source settlement/authentication cannot reinterpret the caller's receipt.
        probe.Contract(RotationMutationReceipt.Capture(trial.Root, receipt, status) == original,
            NativeFailure.ContractMismatch);
        await trial.DisposeAsync();
        probe.Contract(RotationMutationReceipt.Capture(trial.Root, receipt, status) == original,
            NativeFailure.ContractMismatch);
        probe.Effect(NativeObservation.Matched);
    }

    internal static InfisicalRotationPrecondition Precondition(string variant) => variant switch
    {
        "precondition.RequireCompareAndSwap.rejected" => InfisicalRotationPrecondition.RequireCompareAndSwap,
        "precondition.RequireIdempotency.rejected" => InfisicalRotationPrecondition.RequireIdempotency,
        _ => InfisicalRotationPrecondition.None
    };

    internal sealed class BoundaryTransport(bool cancel, bool lose, HttpMessageHandler? transport) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker upstream = new(transport ?? new SocketsHttpHandler
        { AllowAutoRedirect = false, UseCookies = false, ActivityHeadersPropagator = null }, transport is null);
        internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            HttpResponseMessage response = await upstream.SendAsync(request, token);
            if (!(cancel || lose)) return response;
            response.Dispose();
            Reached.TrySetResult();
            if (cancel)
                await new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously).Task.WaitAsync(token);
            throw new HttpRequestException("rotation-original-response-withheld");
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) upstream.Dispose();
            base.Dispose(disposing);
        }
    }
}
