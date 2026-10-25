using SecretKit.Core;
using SecretKit.Infisical;

// Private installed-child protocol. No management package or ambient credentials.
internal sealed record LocalNativeTrial(string Id, string ActorId, string ClientId, string Token,
    DateTimeOffset IssuedAt, DateTimeOffset CompletedAt, double ExpiresIn, double MaximumTtl,
    int ConfiguredTtl, int ConfiguredMaximum, int PeriodSeconds, long TokenUseLimit, long BootstrapUseLimit,
    LocalTrialScope Scope)
{
    public override string ToString() => "[LocalNativeTrial]";
}
internal sealed record LocalTrialScope(string RunId, string RecordSha256, string ProjectId, string Environment, string Folder)
{
    public override string ToString() => "[LocalTrialScope]";
}

internal sealed record LocalTrialExchange(SecretStatus Status, DispatchEvidence Effect, LocalNativeTrial? Issued)
{
    public override string ToString() => "[LocalTrialExchange]";
}

internal static class NativeLifetimeTrials
{
    internal static readonly string[] Ids = ["Q01", "Q02", "Q03", "Q04", "Q05", "Q06"];

    internal static void Validate(LocalNativeTrial trial)
    {
        NativeWorkflow.Require(Ids.Contains(trial.Id, StringComparer.Ordinal) &&
            Guid.TryParseExact(trial.ActorId, "D", out _) && !string.IsNullOrWhiteSpace(trial.ClientId) &&
            trial.Token.Length is > 0 and <= 16384 && trial.Token.All(c => c > ' ' && c < 127) &&
            trial.CompletedAt >= trial.IssuedAt && trial.CompletedAt - trial.IssuedAt <= TimeSpan.FromSeconds(5) &&
            trial.ConfiguredTtl == 10 && trial.ConfiguredMaximum == 20 &&
            trial.PeriodSeconds == (trial.Id == "Q02" ? 60 : 0) &&
            trial.TokenUseLimit == (trial.Id == "Q05" ? 1 : 0) &&
            trial.BootstrapUseLimit == (trial.Id is "Q04" or "Q06" ? 1 : 0) &&
            trial.ExpiresIn == (trial.Id == "Q02" ? 60 : 10) &&
            trial.MaximumTtl == (trial.Id == "Q02" ? 0 : 20));
    }

    internal static async Task<LocalNativeCase> RunAsync(LocalNativeTrial trial, LocalNativeSettings settings,
        SocketsHttpHandler handler, TimeProvider time,
        Func<string, CancellationToken, Task<LocalTrialExchange>> exchange,
        Func<string?, DispatchEvidence, CancellationToken, Task> renewalObservation, CancellationToken token,
        Func<DateTimeOffset, CancellationToken, Task>? probeArmed = null)
    {
        try
        {
            Validate(trial);
            NativeWorkflow.Require(settings.Issuance is { } issuance && trial.Scope.RunId == issuance.RunId &&
                trial.Scope.RecordSha256 == issuance.RecordSha256 && trial.Scope.ProjectId == settings.ProjectId &&
                trial.Scope.Environment == settings.Environment && trial.Scope.Folder == settings.Folder);
            // This is admission, not a new issue time. A delayed handoff cannot extend a trial.
            if (time.GetUtcNow() >= trial.IssuedAt.AddSeconds(trial.ExpiresIn - 2))
                return new(trial.Id, "unavailable", "stale-trial");
            var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = settings.AllowLoopbackDevelopmentHttp };
            var origin = new Uri(settings.Origin);
            using var original = SecretMaterial.FromText(trial.Token);
            var evidence = new InfisicalTokenLifetimeEvidence
            {
                OriginalIssuedAt = trial.IssuedAt,
                ExpiresAt = trial.IssuedAt.AddSeconds(trial.ExpiresIn),
                Lifetime = trial.PeriodSeconds > 0 ? InfisicalTokenLifetime.Periodic : InfisicalTokenLifetime.Finite,
                Period = trial.PeriodSeconds > 0 ? TimeSpan.FromSeconds(trial.PeriodSeconds) : null,
                ReportedMaximumTtl = TimeSpan.FromSeconds(trial.MaximumTtl)
            };
            await using var session = new InfisicalPeriodicTokenSession(origin, original, evidence,
                TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), handler, network, time);
            bool passed;
            switch (trial.Id)
            {
                case "Q01":
                    await At(trial.IssuedAt.AddSeconds(5));
                    if (!await Renew()) return Failed();
                    await At(trial.IssuedAt.AddSeconds(12));
                    if (!await Renew()) return Failed();
                    using (var renewed = (await session.GetTokenAsync(token)).Value)
                    {
                        await At(trial.CompletedAt.AddSeconds(trial.ConfiguredMaximum + 1));
                        var local = await session.GetTokenAsync(token);
                        if (local.IsSuccess) local.Value.Dispose();
                        passed = local.Status == SecretStatus.RecoveryRequired &&
                            await Read(renewed.Material) == SecretStatus.Denied &&
                            await session.RenewAsync(token) == SecretStatus.RecoveryRequired;
                    }
                    break;
                case "Q02":
                    await At(trial.IssuedAt.AddSeconds(5));
                    if (!await Renew()) return Failed();
                    await At(trial.CompletedAt.AddSeconds(trial.ConfiguredMaximum + 1));
                    passed = await Renew();
                    if (passed)
                    {
                        using var continued = (await session.GetTokenAsync(token)).Value;
                        passed = await Read(continued.Material) == SecretStatus.Success;
                    }
                    break;
                case "Q03":
                    await At(trial.CompletedAt.AddSeconds(trial.ExpiresIn + 1));
                    var expired = await session.GetTokenAsync(token);
                    if (expired.IsSuccess) expired.Value.Dispose();
                    passed = await Read(original) == SecretStatus.Denied &&
                        expired.Status == SecretStatus.RecoveryRequired && session.LastRenewal is null;
                    break;
                case "Q04":
                    // The first permitted exchange was acknowledged by the host producer.
                    LocalTrialExchange second = await exchange("second-bootstrap", token);
                    NativeWorkflow.Require(second.Status is SecretStatus.Success or SecretStatus.Denied &&
                        second.Effect != DispatchEvidence.PossiblyDispatched);
                    passed = second.Status == SecretStatus.Denied && second.Effect == DispatchEvidence.Rejected &&
                        second.Issued is null;
                    break;
                case "Q05":
                    // Exactly two selected reads. No inspection, renewal or unrelated call.
                    SecretStatus first = await Read(original);
                    SecretStatus next = await Read(original);
                    passed = first == SecretStatus.Success && next == SecretStatus.Denied;
                    break;
                case "Q06":
                    // Fresh process state has neither token nor bootstrap callback. Losing it
                    // cannot manufacture a login or recover from the still-live host copy.
                    await using (var lost = new InfisicalPeriodicTokenSession(origin, null, evidence,
                        TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), handler, network, time))
                    {
                        var absent = await lost.GetTokenAsync(token);
                        if (absent.IsSuccess) absent.Value.Dispose();
                        if (absent.Status != SecretStatus.RecoveryRequired ||
                            await lost.RenewAsync(token) != SecretStatus.RecoveryRequired ||
                            lost.LastRenewal is not null) return Failed();
                    }
                    LocalTrialExchange recovered = await exchange("explicit-recovery", token);
                    NativeWorkflow.Require(recovered.Status is SecretStatus.Success or SecretStatus.Denied &&
                        recovered.Effect != DispatchEvidence.PossiblyDispatched);
                    if (recovered.Status != SecretStatus.Success || recovered.Effect != DispatchEvidence.Applied ||
                        recovered.Issued is not { } replacement) return Failed();
                    Validate(replacement);
                    NativeWorkflow.Require(replacement.Id == trial.Id && replacement.ActorId == trial.ActorId &&
                        replacement.ClientId == trial.ClientId && replacement.Token != trial.Token &&
                        replacement.Scope == trial.Scope);
                    using (var material = SecretMaterial.FromText(replacement.Token))
                    {
                        var replacementEvidence = new InfisicalTokenLifetimeEvidence
                        {
                            OriginalIssuedAt = replacement.IssuedAt,
                            ExpiresAt = replacement.IssuedAt.AddSeconds(replacement.ExpiresIn),
                            Lifetime = InfisicalTokenLifetime.Finite,
                            ReportedMaximumTtl = TimeSpan.FromSeconds(replacement.MaximumTtl)
                        };
                        await using var recoveredSession = new InfisicalPeriodicTokenSession(origin, material,
                            replacementEvidence, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), handler, network, time);
                        await renewalObservation(null, DispatchEvidence.PossiblyDispatched, token);
                        SecretStatus renewed = await recoveredSession.RenewAsync(token);
                        NativeWorkflow.Require(renewed is SecretStatus.Success or SecretStatus.Denied);
                        if (renewed != SecretStatus.Success)
                        {
                            await renewalObservation(null,
                                recoveredSession.LastRenewal?.Evidence == InfisicalRenewalEvidence.Rejected
                                    ? DispatchEvidence.Rejected : DispatchEvidence.PossiblyDispatched, token);
                            return Failed();
                        }
                        using var recoveredToken = (await recoveredSession.GetTokenAsync(token)).Value;
                        await renewalObservation(recoveredToken.Material.Reveal(), DispatchEvidence.Applied, token);
                        passed = await Read(recoveredToken.Material) == SecretStatus.Success;
                    }
                    break;
                default: return new(trial.Id, "unavailable", "trial-unavailable");
            }
            return new(trial.Id, passed ? "passed" : "failed", "observed");

            LocalNativeCase Failed() => new(trial.Id, "failed", "observed");
            async Task At(DateTimeOffset instant)
            {
                TimeSpan remaining = instant - time.GetUtcNow();
                NativeWorkflow.Require(remaining >= TimeSpan.Zero && remaining <= TimeSpan.FromSeconds(65));
                // Time is the tested behavior. One prearmed probe, never polling.
                Task probe = Task.Delay(remaining, time, token);
                if (probeArmed is not null) await probeArmed(instant, token);
                await probe;
            }
            async Task<bool> Renew()
            {
                await renewalObservation(null, DispatchEvidence.PossiblyDispatched, token);
                SecretStatus status = await session.RenewAsync(token);
                if (status != SecretStatus.Success ||
                    session.LastRenewal?.Evidence != InfisicalRenewalEvidence.Applied)
                {
                    await renewalObservation(null, session.LastRenewal?.Evidence == InfisicalRenewalEvidence.Rejected ?
                        DispatchEvidence.Rejected : DispatchEvidence.PossiblyDispatched, token);
                    NativeWorkflow.Require(status == SecretStatus.Denied);
                    return false;
                }
                var selected = await session.GetTokenAsync(token);
                if (!selected.IsSuccess) return false;
                using var current = selected.Value;
                await renewalObservation(current.Material.Reveal(), DispatchEvidence.Applied, token);
                return true;
            }
            async Task<SecretStatus> Read(SecretMaterial material)
            {
                using var selected = new LocalNativeTokens(material.Reveal());
                await using var reader = new InfisicalClient(origin, handler, selected, network, time);
                var result = await reader.ReadNativeAsync(new(reader.Authority,
                    new InfisicalSecretAddress(settings.ProjectId, settings.Environment, settings.Folder,
                        settings.ReadKey)), token);
                if (result.IsSuccess)
                {
                    using var read = result.Value;
                    NativeWorkflow.Require(read.Material.Reveal() == settings.Issuance!.ExpectedReadValue);
                }
                else NativeWorkflow.Require(result.Status is SecretStatus.Denied or SecretStatus.Absent);
                return result.Status;
            }
        }
        catch (OperationCanceledException) { return new(trial.Id, "unavailable", "deadline-or-cancellation"); }
        catch { return new(trial.Id, "unavailable", "trial-unavailable"); }
    }
}
