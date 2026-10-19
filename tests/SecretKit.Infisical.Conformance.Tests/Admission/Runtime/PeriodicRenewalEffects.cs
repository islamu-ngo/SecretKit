using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class PeriodicRenewalEffects
{
    internal const string Prefix = "i.runtime.InfisicalPeriodicTokenSession.";
    internal const string Selection = "periodicRenewalWitness";
    internal static bool Supports(NativeCaseDefinition row) => row.Key.Provider == "Infisical" &&
        row.Key.Operation is Prefix + "RenewAsync" or Prefix + "GetTokenAsync";
    internal static bool Selected(NativeEnvironment env, NativeCaseDefinition row) => Supports(row) &&
        InfisicalLifecycleFamilies.Input<JsonElement>(env, InfisicalPeriodicTokenSessionEffects.Family, row)
            .TryGetProperty(Selection, out _);

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, TimeProvider time, IInfisicalPeriodicRenewalSource source)
    {
        foreach (var row in expected.Where(Supports))
            registry.Add(new(row, (probe, token) => InfisicalLifecycleFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, row, probe, time, source, bounded))));
    }

    // Parent routes here before legacy SessionInput execution only when Selected.
    internal static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition row,
        NativeCaseProbe probe, TimeProvider time, IInfisicalPeriodicRenewalSource? source, CancellationToken token)
    {
        InfisicalLifecycleFamilies.Admission(row, probe);
        probe.Contract(Supports(row), NativeFailure.ContractMismatch);
        var json = InfisicalLifecycleFamilies.Input<JsonElement>(env, InfisicalPeriodicTokenSessionEffects.Family, row);
        var selectedInput = json.Deserialize<PeriodicRenewalCaseInput>(InfisicalLifecycleFamilies.Options)
            ?? throw new NativeCaseFailureException("missing-input");
        var input = new InfisicalPeriodicTokenSessionEffects.SessionInput(selectedInput.Sandbox,
            selectedInput.Evidence, selectedInput.RenewBeforeSeconds, selectedInput.RequestTimeoutSeconds,
            selectedInput.TokenLost, selectedInput.ProtectedValue);
        var witness = selectedInput.PeriodicRenewalWitness;
        probe.Contract(source is null ? witness.Source == PeriodicRenewalSourceKind.NativeProvider :
            witness.Source == PeriodicRenewalSourceKind.ControlledFixture, NativeFailure.MissingInput);
        if (source is null)
        {
            var channel = InfisicalLifecycleObservers.FromInputs(env, InfisicalPeriodicTokenSessionEffects.Family);
            if (channel is null) probe.Effect(NativeObservation.Unavailable);
            probe.Contract(env.RequireFamilyInput(InfisicalPeriodicTokenSessionEffects.Family).GetProperty("observer")
                .GetProperty("identity").GetString() == witness.SourceIdentity, NativeFailure.MissingInput);
            source = new InfisicalPeriodicRenewalSource(channel!, witness.SourceIdentity);
        }
        string variant = row.Key.Variant;
        bool renew = row.Key.Operation == Prefix + "RenewAsync";
        bool recovery = variant is "lifetime.Unknown.recovery-required" or "session.recovery-required";
        bool expired = variant == "session.expired";
        bool denied = row.Key.Case == "denied-authority";
        bool cancel = row.Key.Case == "cancellation-boundary";
        bool lost = row.Key.Case == "lost-response-no-replay";
        bool dispatch = renew && !recovery && !expired;
        var boundary = !dispatch ? PeriodicRenewalBoundary.None : lost ? PeriodicRenewalBoundary.ResponseWithheld :
            cancel ? PeriodicRenewalBoundary.RequestCaptured : PeriodicRenewalBoundary.None;
        probe.Contract(input.Evidence is not null && input.RenewBeforeSeconds is > 0 and <= 86400 &&
            input.RequestTimeoutSeconds is > 0 and <= 60 &&
            input.TokenLost == (variant == "session.recovery-required") &&
            (variant == "lifetime.Finite" ? input.Evidence.Lifetime == InfisicalTokenLifetime.Finite :
                variant.StartsWith("lifetime.Periodic.", StringComparison.Ordinal) ?
                    input.Evidence.Lifetime == InfisicalTokenLifetime.Periodic &&
                    (input.Evidence.AbsoluteLifetimeLimit is not null) == variant.EndsWith(".absolute-limit", StringComparison.Ordinal) :
                variant == "lifetime.Unknown.recovery-required" ? input.Evidence.Lifetime == InfisicalTokenLifetime.Unknown : true),
            NativeFailure.MissingInput);
        var selected = await env.Tokens(denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime).GetTokenAsync(token);
        probe.Contract(selected.IsSuccess, NativeFailure.MissingPrerequisite);
        using var borrowed = selected.Value;
        await using var trial = await PeriodicRenewalTrial.OpenAsync(source!, witness, row, borrowed.Material,
            input.Evidence!, dispatch, boundary, token);
        await using var session = InfisicalPeriodicTokenSessionEffects.CreateSession(env, input, borrowed.Material, time);
        if (expired)
        {
            await trial.ExpireAsync(token);
            probe.Contract(session.State == InfisicalTokenSessionState.Expired, NativeFailure.ContractMismatch);
        }
        await trial.ArmAsync(token);
        InfisicalAccessToken? actual = null;
        SecretStatus status = SecretStatus.Unknown;
        try
        {
            using var waiter = CancellationTokenSource.CreateLinkedTokenSource(token);
            if (dispatch && boundary != PeriodicRenewalBoundary.None)
            {
                // The private source subscription identifies this exact request.
                // No System.Net.Http global event can cancel another request.
                Task arrival = trial.AwaitBoundaryAsync(token);
                Task<SecretStatus> execution = session.RenewAsync(waiter.Token).AsTask();
                try
                {
                    await arrival;
                    waiter.Cancel();
                    await session.StopAsync();
                    try { status = await execution; }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
                }
                finally
                {
                    await session.StopAsync();
                    try { await execution; }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
                }
                probe.Contract(session.LastRenewal?.Evidence == InfisicalRenewalEvidence.PossiblyDispatched &&
                    status == SecretStatus.Unknown, NativeFailure.ContractMismatch);
            }
            else if (renew)
            {
                status = await session.RenewAsync(token);
                probe.Contract(status == (recovery || expired ? SecretStatus.RecoveryRequired :
                    denied ? SecretStatus.Denied : SecretStatus.Success), NativeFailure.ContractMismatch);
                if (status == SecretStatus.Success) actual = (await session.GetTokenAsync(token)).Value;
                else probe.Contract(!(await session.GetTokenAsync(token)).IsSuccess, NativeFailure.ContractMismatch);
            }
            else if (cancel)
            {
                waiter.Cancel();
                bool cancelled = false;
                try
                {
                    var result = await session.GetTokenAsync(waiter.Token);
                    if (result.IsSuccess) result.Value.Dispose();
                }
                catch (OperationCanceledException) when (waiter.IsCancellationRequested) { cancelled = true; }
                probe.Contract(cancelled, NativeFailure.ContractMismatch);
            }
            else
            {
                var result = await session.GetTokenAsync(token);
                status = result.Status;
                if (result.IsSuccess) actual = result.Value;
                probe.Contract(status == (recovery || expired ? SecretStatus.RecoveryRequired : SecretStatus.Success),
                    NativeFailure.ContractMismatch);
                if (actual is not null)
                {
                    using var independent = (await session.GetTokenAsync(token)).Value;
                    probe.Contract(independent.Material.Reveal() == actual.Material.Reveal(), NativeFailure.ContractMismatch);
                }
            }
            await session.StopAsync();
            var original = session.LastRenewal;
            var receipt = new PeriodicRenewalReceipt(original?.Evidence, status);
            probe.Contract(dispatch ? receipt.Evidence == (boundary != PeriodicRenewalBoundary.None ?
                InfisicalRenewalEvidence.PossiblyDispatched : denied ? InfisicalRenewalEvidence.Rejected :
                InfisicalRenewalEvidence.Applied) : original is null, NativeFailure.ContractMismatch);
            await trial.SettleAsync(receipt, token);
            if (actual is not null)
            {
                await trial.InspectDeliveryAsync(actual, dispatch, token);
                await ProtectedUseAsync(env, input, witness, actual.Material, denied, token);
            }
            // Captured-but-inaccessible material is never called SDK-delivered.
            await trial.DisposeAsync();
            probe.Contract(ReferenceEquals(original, session.LastRenewal) && receipt.Evidence == original?.Evidence &&
                session.State == InfisicalTokenSessionState.Stopped, NativeFailure.ContractMismatch);
            probe.Effect(NativeObservation.Matched);
        }
        finally { actual?.Dispose(); }
    }

    internal static async ValueTask ProtectedUseAsync(NativeEnvironment env,
        InfisicalPeriodicTokenSessionEffects.SessionInput input, PeriodicRenewalInput witness,
        SecretMaterial actual, bool denied, CancellationToken token)
    {
        using var wrong = SecretMaterial.FromText("wrong-" + Guid.NewGuid().ToString("N"));
        var first = await ReadAsync(actual, witness.AllowedKey);
        var negative = await ReadAsync(wrong, witness.AllowedKey);
        var action = await ReadAsync(actual, witness.DeniedKey);
        var recheck = await ReadAsync(actual, witness.AllowedKey);
        var deniedToken = await env.Tokens(NativeIdentityRole.Denied).GetTokenAsync(token);
        using var deniedMaterial = deniedToken.Value;
        var deniedRead = await ReadAsync(deniedMaterial.Material, witness.AllowedKey);
        var observerToken = await env.Tokens(NativeIdentityRole.Observer).GetTokenAsync(token);
        using var observerMaterial = observerToken.Value;
        var independent = await ReadAsync(observerMaterial.Material, witness.AllowedKey);
        PeriodicRenewalTrial.Require(first == (denied ? SecretStatus.Denied : SecretStatus.Success) &&
            recheck == first && negative == SecretStatus.Denied && action == SecretStatus.Denied &&
            deniedRead == SecretStatus.Denied && independent == SecretStatus.Success, "effect-mismatch");

        async ValueTask<SecretStatus> ReadAsync(SecretMaterial material, string key)
        {
            using var tokens = new PeriodicRenewalConsumerTokens(material);
            await using var client = new InfisicalClient(env.Origin, tokens,
                new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
            var result = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress(
                input.Sandbox.ProjectId, input.Sandbox.Environment, input.Sandbox.Parent, key)), token);
            if (result.IsSuccess)
            {
                using var delivered = result.Value;
                PeriodicRenewalTrial.Require(delivered.Material.Reveal() == input.ProtectedValue, "effect-mismatch");
            }
            return result.Status;
        }
    }

    private sealed record PeriodicRenewalCaseInput(LifecycleSandbox Sandbox, InfisicalTokenLifetimeEvidence Evidence,
        int RenewBeforeSeconds, int RequestTimeoutSeconds, bool TokenLost, string ProtectedValue,
        PeriodicRenewalInput PeriodicRenewalWitness)
    {
        public override string ToString() => "[PeriodicRenewalCaseInput]";
    }
}

internal sealed class PeriodicRenewalConsumerTokens(SecretMaterial material) : IInfisicalTokenSource, IDisposable
{
    private readonly SecretMaterial copy = material.Copy();
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(copy.Copy())));
    }
    public void Dispose() => copy.Dispose();
    public override string ToString() => "[PeriodicRenewalConsumerTokens]";
}
