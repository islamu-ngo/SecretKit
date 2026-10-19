using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalPeriodicTokenSessionEffects
{
    internal const string Family = "C08-IR-InfisicalPeriodicTokenSession";
    private const string Prefix = "i.runtime.InfisicalPeriodicTokenSession.";

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, TimeProvider? time = null,
        IInfisicalSessionLifetimeObserver? lifetimeObserver = null,
        IInfisicalPeriodicRenewalSource? periodicRenewals = null)
    {
        foreach (var row in expected.Where(d => d.Key.Provider == "Infisical" &&
            d.Key.Operation.StartsWith(Prefix, StringComparison.Ordinal)))
            registry.Add(new(row, (probe, token) => InfisicalLifecycleFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, row, probe, time ?? TimeProvider.System, lifetimeObserver,
                    periodicRenewals, bounded))));
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition row,
        NativeCaseProbe probe, TimeProvider time, IInfisicalSessionLifetimeObserver? lifetimeObserver,
        IInfisicalPeriodicRenewalSource? periodicRenewals,
        CancellationToken token)
    {
        InfisicalLifecycleFamilies.Admission(row, probe);
        if (PeriodicRenewalEffects.Selected(env, row))
        {
            await PeriodicRenewalEffects.ExecuteAsync(env, row, probe, time, periodicRenewals, token);
            return;
        }
        SessionInput input = InfisicalLifecycleFamilies.Input<SessionInput>(env, Family, row);
        lifetimeObserver ??= InfisicalLifecycleObservers.FromInputs(env, Family);
        bool renewal = row.Key.Operation == Prefix + "RenewAsync";
        string variant = row.Key.Variant;
        bool recovery = variant is "lifetime.Unknown.recovery-required" or "session.recovery-required";
        bool expired = variant == "session.expired";
        probe.Contract(input.Evidence is not null &&
            (variant == "lifetime.Finite" ? input.Evidence.Lifetime == InfisicalTokenLifetime.Finite :
                variant.StartsWith("lifetime.Periodic.", StringComparison.Ordinal) ?
                    input.Evidence.Lifetime == InfisicalTokenLifetime.Periodic &&
                    (input.Evidence.AbsoluteLifetimeLimit is not null) == variant.EndsWith(".absolute-limit", StringComparison.Ordinal) :
                variant == "lifetime.Unknown.recovery-required" ?
                    input.Evidence.Lifetime == InfisicalTokenLifetime.Unknown : true) &&
            input.RenewBeforeSeconds > 0 && input.RenewBeforeSeconds <= 86400 &&
            input.RequestTimeoutSeconds is > 0 and <= 60, NativeFailure.MissingInput);
        bool denied = row.Key.Case == "denied-authority";
        SecretOutcome<InfisicalAccessToken> selected = await env.Tokens(denied ?
            NativeIdentityRole.Denied : NativeIdentityRole.Runtime).GetTokenAsync(token);
        probe.Contract(selected.IsSuccess, NativeFailure.MissingPrerequisite);
        using var original = selected.Value;
        await using var session = CreateSession(env, input, original.Material, time);
        if (expired)
        {
            if (lifetimeObserver is null) probe.Effect(NativeObservation.Unavailable);
            // Subscribe to a selected token's expiry event, not a clock delay or hidden poll.
            await lifetimeObserver!.ExpiredAsync(original.Material, input.Evidence!, token);
            probe.Contract(session.State == InfisicalTokenSessionState.Expired, NativeFailure.ContractMismatch);
        }

        bool cancelled = row.Key.Case == "cancellation-boundary";
        bool lost = row.Key.Case == "lost-response-no-replay";
        if (!renewal)
        {
            using var localCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            if (cancelled) localCancellation.Cancel();
            if (cancelled)
            {
                bool observed = false;
                try { (await session.GetTokenAsync(localCancellation.Token)).Value.Dispose(); }
                catch (OperationCanceledException) when (localCancellation.IsCancellationRequested) { observed = true; }
                probe.Contract(observed && session.LastRenewal is null, NativeFailure.ContractMismatch);
                probe.Effect(NativeObservation.Matched);
                return;
            }
            SecretOutcome<InfisicalAccessToken> result = await session.GetTokenAsync(token);
            probe.Contract(result.Status == (recovery || expired ? SecretStatus.RecoveryRequired : SecretStatus.Success) &&
                session.LastRenewal is null, NativeFailure.ContractMismatch);
            if (recovery || expired)
            {
                probe.Effect(!result.IsSuccess ? NativeObservation.Matched : NativeObservation.Mismatched);
                return;
            }
            using var copy = result.Value;
            using var second = (await session.GetTokenAsync(token)).Value;
            copy.Dispose();
            probe.Contract(second.ExpiresAt == input.Evidence!.ExpiresAt &&
                second.Material.Reveal() == original.Material.Reveal() && session.LastRenewal is null,
                NativeFailure.ContractMismatch);
            await ProtectedUseAsync(env, input, second, probe, denied, row.Key.Scope, token, recordEffect: false);
            if (lifetimeObserver is null) probe.Effect(NativeObservation.Unavailable);
            SessionLifetimeFacts lifetime = await lifetimeObserver!.MeasureAsync(second.Material, token);
            probe.Effect(lifetime.OriginalIssuedAt == input.Evidence.OriginalIssuedAt &&
                lifetime.ExpiresAt == second.ExpiresAt && lifetime.Lifetime == input.Evidence.Lifetime &&
                lifetime.ReportedMaximumTtl == input.Evidence.ReportedMaximumTtl &&
                lifetime.Period == input.Evidence.Period &&
                lifetime.AbsoluteLifetimeLimit == input.Evidence.AbsoluteLifetimeLimit ?
                NativeObservation.Matched : NativeObservation.Mismatched);
            return;
        }

        if (recovery || expired)
        {
            var result = await session.RenewAsync(token);
            probe.Contract(result == SecretStatus.RecoveryRequired && session.LastRenewal is null &&
                !(await session.GetTokenAsync(token)).IsSuccess, NativeFailure.ContractMismatch);
            probe.Effect(NativeObservation.Matched);
            return;
        }
        using var waiter = CancellationTokenSource.CreateLinkedTokenSource(token);
        Task? stop = null;
        using var boundary = cancelled || lost ? new LifecycleSessionBoundary(env.Origin, waiter, lost,
            () => stop = session.StopAsync()) : null;
        Task? reached = boundary?.Reached.Task; // subscribed before SDK renewal
        SecretStatus status = SecretStatus.Unknown;
        Task<SecretStatus> execution = session.RenewAsync(waiter.Token).AsTask();
        try { status = await execution; }
        catch (OperationCanceledException) when (waiter.IsCancellationRequested && !token.IsCancellationRequested) { }
        InfisicalTokenRenewal? receipt = session.LastRenewal;
        if (cancelled || lost)
        {
            if (stop is not null) await stop;
            probe.Contract(reached!.IsCompletedSuccessfully && receipt is not null,
                NativeFailure.ContractMismatch);
            if (lost)
            {
                // Waiter cancellation does not cancel the shared renewal. Stop cancels/drains it
                // and retains the same uncertain receipt; no second renewal or login is attempted.
                await session.StopAsync();
                probe.Contract(ReferenceEquals(receipt, session.LastRenewal) &&
                    receipt!.Evidence == InfisicalRenewalEvidence.PossiblyDispatched &&
                    session.State == InfisicalTokenSessionState.Stopped, NativeFailure.ContractMismatch);
            }
            else
            {
                // The receipt is caller-owned before send. The independently selected observer
                // must establish whether the shared renewal applied despite waiter cancellation.
                await session.StopAsync();
                probe.Contract(ReferenceEquals(receipt, session.LastRenewal) &&
                    receipt!.Evidence is InfisicalRenewalEvidence.PossiblyDispatched or
                        InfisicalRenewalEvidence.Applied or InfisicalRenewalEvidence.Rejected,
                    NativeFailure.ContractMismatch);
            }
            // A snapshot cannot attribute renewal or fence a later commit after
            // local Stop. Only a prearmed original-attempt source may qualify
            // this boundary; legacy lifetime measurement is insufficient.
            probe.Effect(NativeObservation.Unavailable);
            return;
        }
        probe.Contract(status == (denied ? SecretStatus.Denied : SecretStatus.Success) &&
            receipt?.Evidence == (denied ? InfisicalRenewalEvidence.Rejected : InfisicalRenewalEvidence.Applied),
            NativeFailure.ContractMismatch);
        if (denied)
        {
            probe.Contract(session.State == InfisicalTokenSessionState.RecoveryRequired &&
                !(await session.GetTokenAsync(token)).IsSuccess, NativeFailure.ContractMismatch);
            await ProtectedUseAsync(env, input, original, probe, true, row.Key.Scope, token, recordEffect: false);
            if (lifetimeObserver is null) probe.Effect(NativeObservation.Unavailable);
            SessionLifetimeFacts unchanged = await lifetimeObserver!.MeasureAsync(original.Material, token);
            probe.Effect(unchanged.OriginalIssuedAt == input.Evidence!.OriginalIssuedAt &&
                unchanged.ExpiresAt == input.Evidence.ExpiresAt && unchanged.Lifetime == input.Evidence.Lifetime &&
                unchanged.ReportedMaximumTtl == input.Evidence.ReportedMaximumTtl &&
                unchanged.Period == input.Evidence.Period &&
                unchanged.AbsoluteLifetimeLimit == input.Evidence.AbsoluteLifetimeLimit ?
                NativeObservation.Matched : NativeObservation.Mismatched);
            return;
        }
        using var renewed = (await session.GetTokenAsync(token)).Value;
        await ProtectedUseAsync(env, input, renewed, probe, false, row.Key.Scope, token, recordEffect: false);
        if (lifetimeObserver is null) probe.Effect(NativeObservation.Unavailable);
        SessionLifetimeFacts observedLifetime = await lifetimeObserver!.MeasureAsync(renewed.Material, token);
        probe.Effect(observedLifetime.OriginalIssuedAt == input.Evidence!.OriginalIssuedAt &&
            observedLifetime.ExpiresAt == renewed.ExpiresAt &&
            observedLifetime.Lifetime == input.Evidence.Lifetime &&
            observedLifetime.ReportedMaximumTtl == input.Evidence.ReportedMaximumTtl &&
            observedLifetime.Period == input.Evidence.Period &&
            observedLifetime.AbsoluteLifetimeLimit == input.Evidence.AbsoluteLifetimeLimit ?
            NativeObservation.Matched : NativeObservation.Mismatched);
    }

    internal static InfisicalPeriodicTokenSession CreateSession(NativeEnvironment env, SessionInput input,
        SecretMaterial material, TimeProvider time) => new(env.Origin,
            input.TokenLost ? null : material, input.Evidence,
            TimeSpan.FromSeconds(input.RenewBeforeSeconds), TimeSpan.FromSeconds(input.RequestTimeoutSeconds),
            new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp }, time);

    private static async ValueTask ProtectedUseAsync(NativeEnvironment env, SessionInput input,
        InfisicalAccessToken issued, NativeCaseProbe probe, bool denied, string scope,
        CancellationToken token, bool recordEffect = true)
    {
        await using var folder = new LifecycleOwnedFolder(env, input.Sandbox, probe, scope);
        await folder.InitializeAsync(token);
        await using var setup = env.CreateClient(NativeIdentityRole.Setup);
        await using var observer = env.CreateObserverClient();
        string key = "token-consumer-" + Guid.NewGuid().ToString("N");
        using var value = SecretMaterial.FromText(input.ProtectedValue);
        var setupTarget = new SecretReference(setup.Authority, new InfisicalSecretAddress(input.Sandbox.ProjectId,
            input.Sandbox.Environment, folder.Path, key));
        var receipt = new MutationReceipt(setupTarget);
        var seeded = await setup.CreateAsync(setupTarget, value, receipt, token);
        probe.Contract(seeded.IsSuccess && seeded.Value.Disposition == InfisicalChangeDisposition.Applied &&
            receipt.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
        using var supplied = new SessionConsumerTokens(issued.Material);
        await using var consumer = new InfisicalClient(env.Origin, supplied,
            new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        var intended = await consumer.ReadAsync(new(consumer.Authority, setupTarget.Address), token);
        var observed = await observer.ReadAsync(new(observer.Authority, setupTarget.Address), token);
        if (intended.IsSuccess)
        {
            using var delivered = intended.Value;
            probe.Contract(delivered.Material.Reveal() == input.ProtectedValue, NativeFailure.EffectMismatch);
        }
        if (observed.IsSuccess)
        {
            using var independent = observed.Value;
            probe.Contract(independent.Material.Reveal() == input.ProtectedValue, NativeFailure.EffectMismatch);
        }
        probe.Contract(observed.IsSuccess && intended.Status == (denied ? SecretStatus.Denied : SecretStatus.Success),
            NativeFailure.EffectMismatch);
        if (!denied)
        {
            // A fresh protected request under the explicitly denied role supplies the counterexample.
            await using var deniedClient = env.CreateDeniedClient();
            var rejected = await deniedClient.ReadAsync(new(deniedClient.Authority, setupTarget.Address), token);
            if (rejected.IsSuccess) rejected.Value.Dispose();
            probe.Contract(rejected.Status == SecretStatus.Denied, NativeFailure.EffectMismatch);
        }
        if (recordEffect) probe.Effect(NativeObservation.Matched);
    }

    internal sealed record SessionInput(LifecycleSandbox Sandbox, InfisicalTokenLifetimeEvidence Evidence,
        int RenewBeforeSeconds, int RequestTimeoutSeconds, bool TokenLost, string ProtectedValue)
    {
        public override string ToString() => "[SessionInput]";
    }
    private sealed class SessionConsumerTokens(SecretMaterial material) : IInfisicalTokenSource, IDisposable
    {
        private readonly SecretMaterial copy = material.Copy();
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(copy.Copy())));
        }
        public void Dispose() => copy.Dispose();
        public override string ToString() => "[SessionConsumerTokens]";
    }
}

internal sealed record SessionLifetimeFacts(DateTimeOffset OriginalIssuedAt, DateTimeOffset ExpiresAt,
    InfisicalTokenLifetime Lifetime, TimeSpan ReportedMaximumTtl, TimeSpan? Period, DateTimeOffset? AbsoluteLifetimeLimit);

internal interface IInfisicalSessionLifetimeObserver
{
    ValueTask<SessionLifetimeFacts> MeasureAsync(SecretMaterial token, CancellationToken cancellationToken);
    ValueTask ExpiredAsync(SecretMaterial token, InfisicalTokenLifetimeEvidence previous, CancellationToken cancellationToken);
}
