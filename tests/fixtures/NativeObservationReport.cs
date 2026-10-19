using System.Text.Json;
using SecretKit.Release;

namespace SecretKit.TestFixtures;

internal sealed record NativeReportContext(ReleaseScope Scope, PackageRecord[] Packages,
    string[] ContractGaps);

internal static class NativeObservationReport
{
    private static readonly HashSet<string> Reasons = new(StringComparer.Ordinal)
    {
        "observed", "missing-registration", "missing-contract", "missing-effect", "contract-mismatch",
        "missing-input", "missing-prerequisite", "observer-unavailable", "effect-mismatch",
        "unexpected-cancellation", "deadline-exceeded", "cleanup-incomplete", "unexpected-failure",
        "incomplete-execution"
    };

    internal static MachineReport Create(NativeRunRequest request, NativeReportContext context,
        NativeRunResult? result, InstallationObservation installation, DateTimeOffset started,
        DateTimeOffset completed, int processExitCode, string? processFailure = null)
    {
        request.Validate();
        Require(context.Scope.Version == request.Version && context.Scope.SourceCommit == request.SourceCommit &&
            Manifest.Hash(JsonSerializer.SerializeToUtf8Bytes(context.Scope, Manifest.JsonOptions)) == request.ScopeSha256,
            "native-report-binding");
        Require(context.Packages.Length == 7 && context.Packages.Select(p => p.Id).Distinct().Count() == 7 &&
            context.Packages.Select(p => p.Id).Order().SequenceEqual(Manifest.PackageIds.Order()) &&
            context.Packages.All(p => p.File == $"{p.Id}.{request.Version}.nupkg" && Manifest.IsHash(p.Sha256)),
            "native-report-packages");
        Require(started.Offset == TimeSpan.Zero && completed.Offset == TimeSpan.Zero && completed >= started,
            "native-report-time");

        HashSet<NativeCaseKey> expectedKeys = request.Expected.Select(d => d.Key).ToHashSet();
        bool substituted = result is not null && (result.Provider != request.Provider || result.Kind != request.Kind ||
            result.Platform != request.Platform || result.Version != request.Version ||
            result.SourceCommit != request.SourceCommit || result.ScopeSha256 != request.ScopeSha256 ||
            result.StartedAt < started || result.CompletedAt < result.StartedAt || result.CompletedAt > completed ||
            result.Cases.Select(Key).Distinct().Count() != result.Cases.Length ||
            result.Cases.Any(c => !expectedKeys.Contains(Key(c))) ||
            result.Prerequisites.Select(p => new NativePrerequisiteKey(p.Provider, p.Scope, p.Prerequisite))
                .Distinct().Count() != result.Prerequisites.Length ||
            result.Prerequisites.Any(p => !request.Prerequisites.Contains(new(p.Provider, p.Scope, p.Prerequisite))));
        Dictionary<NativeCaseKey, NativeCaseResult> measuredCases = !substituted && result is not null
            ? result.Cases.ToDictionary(Key) : [];
        bool installed = result is not null &&
            result.Installation == new NativeInstallationResult(installation.OperatingSystem,
                installation.Architecture, installation.Framework) &&
            installation.ProcessExitCode == processExitCode && installation.ProjectReferences == 0 &&
            installation.IsolatedCache && installation.PackageSource == "candidate-only" &&
            installation.Architecture == "x64" && installation.Framework == "net10.0" &&
            $"{installation.OperatingSystem}-x64-net10.0" == request.Platform;
        var prerequisites = request.Prerequisites.Select(p => new PrerequisiteObservation(p.Provider, p.Scope,
            p.Prerequisite, !substituted && result is not null && result.Prerequisites.Any(r =>
                r.Provider == p.Provider && r.Scope == p.Scope && r.Prerequisite == p.Prerequisite && r.Confirmed))).ToArray();
        var rows = new List<NativeCaseObservation>(request.Expected.Length);
        foreach (NativeCaseDefinition definition in request.Expected)
        {
            NativeCaseResult? measured = measuredCases.GetValueOrDefault(definition.Key);
            string reason = substituted ? "substituted-result" : measured is null ? "incomplete-execution" :
                !Reasons.Contains(measured.ReasonCode) ? "unexpected-failure" : measured.ReasonCode;
            bool passed = measured is { Passed: true, EffectObserved: true, ReasonCode: "observed" } && !substituted;
            if (passed && (processExitCode != 0 || processFailure is not null))
            {
                passed = false;
                reason = processFailure is "deadline-exceeded" or "unexpected-cancellation" ? processFailure : "process-exit";
            }
            if (passed && !installed) { passed = false; reason = "installation-mismatch"; }
            if (passed && context.ContractGaps.Contains(definition.Key.Operation, StringComparer.Ordinal))
            { passed = false; reason = "contract-gap"; }
            if (passed && prerequisites.Any(p => p.Scope == definition.Key.Scope && !p.Confirmed))
            { passed = false; reason = "missing-prerequisite"; }
            if (!passed && reason == "observed") reason = "missing-effect";
            rows.Add(new(definition.Key.Provider, definition.Key.Operation, definition.Key.Variant,
                definition.Key.Scope, definition.Key.Case, passed, measured?.EffectObserved == true, reason));
        }
        CheckObservation[] checks = rows.GroupBy(c => new NativeOperation(c.Provider, c.Operation,
            c.Variant, c.Scope, "complete").Key).Select(g =>
                new CheckObservation(g.Key, g.All(c => c.Passed), g.All(c => c.Passed) ? "observed" : "native-case-failed")).ToArray();
        int failed = rows.Count(c => !c.Passed);
        bool successful = failed == 0 && processExitCode == 0 && installed && prerequisites.All(p => p.Confirmed);
        return new(2, request.Purpose, request.Kind, request.Version, request.SourceCommit,
            request.RunId, request.RunAttempt, request.JobId, request.Platform,
            request.Purpose == "release-observation" ? "release-evidence" : "development",
            request.ScopeSha256, context.Scope.Inventories, context.Packages, context.Scope.ProviderScopes,
            started, completed, request.Expected.Length, failed, 0, successful ? 0 : processExitCode == 0 ? 1 : processExitCode,
            checks, rows.ToArray(), prerequisites, installation);
    }

    internal static async Task WriteAsync(string destination, MachineReport report, CancellationToken token)
    {
        Require(Path.IsPathFullyQualified(destination), "native-report-path");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(report, Manifest.JsonOptions);
        Require(bytes.Length <= EvidenceLimits.ReportBytes, "native-report-size");
        await using var stream = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await stream.WriteAsync(bytes, token).ConfigureAwait(false);
    }

    private static NativeCaseKey Key(NativeCaseResult result) =>
        new(result.Provider, result.Operation, result.Variant, result.Scope, result.Case);
    internal static void Require(bool condition, string code)
    {
        if (!condition) throw new InvalidOperationException(code);
    }
}
