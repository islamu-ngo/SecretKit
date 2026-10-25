using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Release;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class LocalProfileConformance
{
    internal static LocalNativeInput Admit(byte[] bytes, LocalNativeBinding frozen)
    {
        LocalNativeInput input = NativeWorkflow.Parse(bytes);
        // The file is setup selection only. Causal claims come exclusively from
        // this host's newly observed issuance, never an imported proof envelope.
        NativeWorkflow.Require(SameBinding(input.Binding, frozen) && input.Settings.Issuance is null);
        return input;
    }

    internal static bool SameBinding(LocalNativeBinding left, LocalNativeBinding right) =>
        left.Version == right.Version && left.ProfileSha256 == right.ProfileSha256 &&
        left.SourceSha256 == right.SourceSha256 && left.RecordSha256 == right.RecordSha256 &&
        left.Packages.OrderBy(p => p.Id, StringComparer.Ordinal)
            .SequenceEqual(right.Packages.OrderBy(p => p.Id, StringComparer.Ordinal));

    internal static LocalNativeBinding Freeze(string root, string originals, string recordDirectory)
    {
        LocalQualificationRecord record = LocalQualification.Check(root, originals, recordDirectory);
        byte[] bytes = Manifest.ReadFile(recordDirectory, LocalQualification.RecordFile, 4 * 1024 * 1024);
        // Require the checked record to be the very bytes bound to the launch.
        NativeWorkflow.Require(Manifest.Parse<LocalQualificationRecord>(bytes) is { } reopened &&
            JsonSerializer.Serialize(record, Manifest.JsonOptions) == JsonSerializer.Serialize(reopened, Manifest.JsonOptions));
        return new(record.Version, record.Profile.Sha256, record.Source.Sha256, Manifest.Hash(bytes),
            record.Packages.Select(p => new LocalNativePackage(p.Id, p.Sha256)).ToArray());
    }

    internal static byte[] ReadProtectedInput(string path)
    {
        NativeWorkflow.Require(Path.IsPathFullyQualified(path));
        if (!OperatingSystem.IsWindows())
        {
            UnixFileMode mode = File.GetUnixFileMode(path);
            NativeWorkflow.Require((mode & ~(UnixFileMode.UserRead | UnixFileMode.UserWrite)) == 0);
        }
        return Manifest.ReadFile(Path.GetDirectoryName(path)!, Path.GetFileName(path), 131072);
    }

    internal static async Task<ConsumerInstallation> InstallAsync(string root, string originals, string records,
        string output, CancellationToken token)
    {
        LocalNativeBinding before = Freeze(root, originals, records);
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(originals, before.Version);
        ConsumerInstallation installation = candidate.PrepareConsumer(output, "full");
        string project = Path.Combine(root, "tests/fixtures/SecretKit.InfisicalConsumer/SecretKit.InfisicalConsumer.csproj");
        var restored = await OwnedProcess.RunAsync("dotnet",
            ["restore", project, "--configfile", installation.Configuration, .. installation.Properties],
            root, cancellationToken: token);
        NativeWorkflow.Require(restored.ExitCode == 0);
        string assets = Path.Combine(installation.Intermediate, "project.assets.json");
        candidate.VerifyRestored(assets, installation.Packages, "full");
        var built = await OwnedProcess.RunAsync("dotnet",
            ["build", project, "--configuration", "Release", "--no-restore", .. installation.Properties],
            root, cancellationToken: token);
        NativeWorkflow.Require(built.ExitCode == 0);
        candidate.VerifyRestored(assets, installation.Packages, "full");
        NativeWorkflow.Require(SameBinding(before, Freeze(root, originals, records)));
        return installation;
    }

    internal static Task<LocalNativeReport> RunFromEnvironmentAsync() => RunSelectedAsync(causal: false);
    internal static Task<LocalNativeReport> RunCausalFromEnvironmentAsync() => RunSelectedAsync(causal: true);

    private static async Task<LocalNativeReport> RunSelectedAsync(bool causal)
    {
        // These are live-only inputs. The separately filterable offline class never enters here.
        NativeWorkflow.Require(Required("SECRETKIT_LOCAL_NATIVE_AUTHORITY") == "owned-local-native-execution" &&
            Required("SECRETKIT_LOCAL_PROFILE") == "infisical-runtime");
        string root = RequiredPath("SECRETKIT_LOCAL_SOURCE");
        string originals = RequiredPath("SECRETKIT_LOCAL_ORIGINALS");
        string records = RequiredPath("SECRETKIT_LOCAL_RECORD");
        string inputPath = RequiredPath("SECRETKIT_LOCAL_NATIVE_INPUT");
        string reportPath = RequiredPath("SECRETKIT_LOCAL_NATIVE_REPORT");
        NativeWorkflow.Require(!File.Exists(reportPath) && !Directory.Exists(reportPath));
        LocalNativeBinding binding = Freeze(root, originals, records);
        byte[] bytes = ReadProtectedInput(inputPath);
        try
        {
            LocalNativeInput input = Admit(bytes, binding);
            LocalNativeReport initial = NativeWorkflow.EmptyReport(input);
            // A report with the complete denominator exists before any pod/provider dispatch.
            await WriteAsync(reportPath, initial, FileMode.CreateNew);
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            if (!causal)
                return await RunSuppliedAsync(root, originals, records, reportPath, bytes, input, initial, deadline.Token);
            LocalNativeSettings settings = input.Settings;
            NativeWorkflow.Require(settings.AllowLoopbackDevelopmentHttp);
            using var setup = SecretMaterial.FromText(settings.Setup.Token);
            using var sandbox = new OwnedSandbox(new Uri(settings.Origin), settings.Owner, settings.OrganizationId, setup);
            await sandbox.VerifyAsync(root, deadline.Token);
            string output = Path.Combine(root, "artifacts/local-native", Guid.NewGuid().ToString("N"));
            ConsumerInstallation installation = await InstallAsync(root, originals, records, output, deadline.Token);
            NativeWorkflow.Require(SameBinding(binding, Freeze(root, originals, records)));
            await using var proof = new LocalNativeProof(sandbox, settings, binding,
                Path.Combine(output, "producer-ledger.jsonl"));
            string childReport = Path.Combine(output, "native-report.json");
            LocalNativeReport report = initial with { ProofRun = proof.RunId };
            byte[]? producedBytes = null;
            try
            {
                // The finalizer encloses the very first setup mutation, including
                // partial actor/configuration/credential issuance and failed launch.
                producedBytes = await proof.ProduceAsync(deadline.Token);
                input = proof.AdmitProduced(producedBytes);
                settings = input.Settings;
                report = NativeWorkflow.EmptyReport(input);
                await WriteAsync(reportPath, report, FileMode.Truncate);
                proof.BeginChild();
                await LaunchAsync(root, Path.Combine(installation.Binary,
                    "Release/net10.0/SecretKit.InfisicalConsumer.dll"), childReport, producedBytes,
                    settings.Recreate ? Recreate : null, observed =>
                    {
                        proof.ObserveChildReport(observed);
                        report = observed;
                    }, proof, deadline.Token);
                NativeWorkflow.Require(SameBinding(binding, Freeze(root, originals, records)));
                ValidateReport(report, binding, proof);
            }
            finally
            {
                // Cleanup retains its own bounded opportunity even if observation or
                // the execution deadline failed after an acknowledged create.
                using var cleanupDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                try
                {
                    await ReconcileCleanupAsync(report, () => proof.RemoveSecretAsync(settings.ProjectId,
                        settings.Environment, settings.Folder, settings.WriteKey, cleanupDeadline.Token),
                        () => WriteAsync(reportPath, report, FileMode.Truncate));
                }
                finally
                {
                    report.ProducerCleanup = await proof.CleanupAsync(cleanupDeadline.Token);
                    await WriteAsync(reportPath, report, FileMode.Truncate);
                    if (producedBytes is not null) Array.Clear(producedBytes);
                }
            }
            return report;

            async Task Recreate()
            {
                await proof.RecreateAsync(settings, deadline.Token);
            }
        }
        finally { Array.Clear(bytes); }
    }

    // A deliberately different observation mode: supplied tokens remain opaque
    // and unqualified. Fresh issuance never upgrades these actors or this report.
    private static async Task<LocalNativeReport> RunSuppliedAsync(string root, string originals, string records,
        string reportPath, byte[] bytes, LocalNativeInput input, LocalNativeReport initial, CancellationToken token)
    {
        var settings = input.Settings;
        if (settings.AllowLoopbackDevelopmentHttp)
        {
            using var setup = SecretMaterial.FromText(settings.Setup.Token);
            using var sandbox = new OwnedSandbox(new(settings.Origin), settings.Owner, settings.OrganizationId, setup);
            await sandbox.VerifyAsync(root, token);
        }
        string output = Path.Combine(root, "artifacts/local-native", Guid.NewGuid().ToString("N"));
        var installation = await InstallAsync(root, originals, records, output, token);
        NativeWorkflow.Require(SameBinding(input.Binding, Freeze(root, originals, records)));
        using var tokens = new LocalNativeTokens(settings.Setup.Token);
        await using var client = new InfisicalClient(new(settings.Origin), tokens,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = settings.AllowLoopbackDevelopmentHttp });
        SecretReference Select(string key) => new(client.Authority,
            new InfisicalSecretAddress(settings.ProjectId, settings.Environment, settings.Folder, key));
        var before = await client.ReadNativeAsync(Select(settings.WriteKey), token);
        if (before.IsSuccess) before.Value.Dispose();
        NativeWorkflow.Require(before.Status == SecretStatus.Absent);
        var report = initial;
        try
        {
            await LaunchAsync(root, Path.Combine(installation.Binary, "Release/net10.0/SecretKit.InfisicalConsumer.dll"),
                Path.Combine(output, "native-report.json"), bytes, settings.Recreate ? Recreate : null,
                observed => { ValidateReport(observed, input.Binding); report = observed; }, null, token);
            NativeWorkflow.Require(SameBinding(input.Binding, Freeze(root, originals, records)));
            ValidateReport(report, input.Binding);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await ReconcileCleanupAsync(report, () => Remove(settings.WriteKey, cleanup.Token),
                () => WriteAsync(reportPath, report, FileMode.Truncate));
        }
        return report;

        async Task<bool> Remove(string key, CancellationToken ct)
        {
            var reference = new SecretReference(client.Authority,
                new InfisicalBulkAddress(settings.ProjectId, settings.Environment, settings.Folder));
            var authority = new InfisicalNativeAuthority(client.Authority, tokens,
                settings.ProjectId, settings.Environment, settings.Folder);
            var receipt = new MutationReceipt(reference);
            var removed = await client.DeleteSecretsAsync(reference, [new InfisicalBulkSecret(key)], authority, receipt, ct);
            return removed.IsSuccess && removed.Value.AllApplied && receipt.Evidence == DispatchEvidence.Applied;
        }
        async Task Recreate()
        {
            NativeWorkflow.Require(await Remove(settings.ReadKey, token));
            using var material = SecretMaterial.FromText(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
            var reference = Select(settings.ReadKey);
            var receipt = new MutationReceipt(reference);
            var created = await client.CreateAsync(reference, material, receipt, token);
            NativeWorkflow.Require(created.IsSuccess && created.Value.Disposition == InfisicalChangeDisposition.Applied &&
                receipt.Evidence == DispatchEvidence.Applied);
        }
    }

    internal static async Task ReconcileCleanupAsync(LocalNativeReport report, Func<Task<bool>> remove,
        Func<Task> persist)
    {
        if (report.CreateEffect == DispatchEvidence.Applied)
        {
            int cleanup = Array.IndexOf(NativeWorkflow.CaseIds, "cleanup");
            try
            {
                bool removed = await remove();
                report.Cases[cleanup] = new("cleanup", removed ? "passed" : "failed", "owned-resource-cleanup");
            }
            catch { report.Cases[cleanup] = new("cleanup", "unavailable", "cleanup-unconfirmed"); }
        }
        await persist();
    }

    internal static void ValidateReport(LocalNativeReport report, LocalNativeBinding binding, LocalNativeProof? proof = null)
    {
        NativeWorkflow.Require(report.SchemaVersion == 1 &&
            report.Kind == "local-native-observation-not-public-approval" && SameBinding(report.Binding, binding) &&
            Version.TryParse(report.DeclaredServerVersion, out _) && report.ApiVersion == "v4" &&
            report.DeclaredEdition is "oss" or "enterprise" or "cloud" &&
            report.Platform is "linux-x64" or "linux-arm64" or "win-x64" or "win-arm64" or "osx-x64" or "osx-arm64" &&
            Enum.IsDefined(report.CreateEffect) && Enum.IsDefined(report.UpdateEffect) && Enum.IsDefined(report.ApprovalEffect) &&
            report.Cases.Length == NativeWorkflow.CaseIds.Length &&
            report.Cases.Select(c => c.Id).SequenceEqual(NativeWorkflow.CaseIds) &&
            report.Cases.All(c => c.Status is "passed" or "failed" or "unavailable" &&
                c.Reason is "not-observed" or "observed" or "deadline-or-cancellation" or
                    "observation-unavailable" or "execution-incomplete" or
                    "selected-origin-system-trust-and-proxy" or "owned-resource-cleanup" or "cleanup-unconfirmed" or
                    "authoritative-proof-unavailable" or "owned-causal-observation" or "trial-unavailable" or "stale-trial") &&
            report.SupplementalCases.Length == 6 &&
            report.SupplementalCases.Select(c => c.Id).SequenceEqual(NativeLifetimeTrials.Ids) &&
            report.SupplementalCases.All(c => c.Status is "passed" or "failed" or "unavailable" &&
                c.Reason is "observed" or "not-observed" or "trial-unavailable" or "stale-trial" or
                    "deadline-or-cancellation") &&
            report.ProducerCleanup.Status is "complete" or "incomplete" or "unavailable" &&
            report.ProducerCleanup.OutstandingKnown is >= 0 and <= 10000 &&
            report.ProducerCleanup.Uncertain is >= 0 and <= 10000 &&
            (report.ProducerCleanup.Status != "complete" ||
                report.ProducerCleanup.OutstandingKnown == 0 && report.ProducerCleanup.Uncertain == 0));
        // No supported endpoint currently proves these host declarations for the selected
        // opaque tokens. Distinct strings and a policy digest are not principal proof.
        if (proof is null)
            NativeWorkflow.Require(report.ProofRun is null && report.Cases.Where(c => c.Id is
                "deployment-binding" or "actor-binding" or "policy-binding").All(c => c.Status == "unavailable") &&
                report.SupplementalCases.All(c => c.Status == "unavailable") &&
                report.ProducerCleanup.Status == "unavailable");
        else proof.ValidateReport(report);
    }

    private static async Task LaunchAsync(string root, string binary, string report,
        byte[] input, Func<Task>? recreate, Action<LocalNativeReport> observe, LocalNativeProof? proof, CancellationToken token)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = root, UseShellExecute = false, RedirectStandardInput = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            }
        };
        process.StartInfo.Environment.Clear();
        foreach (string key in new[] { "PATH", "HOME", "DOTNET_ROOT" })
            if (Environment.GetEnvironmentVariable(key) is { } value) process.StartInfo.Environment[key] = value;
        foreach (string argument in new[] { binary, "native", report }) process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        // Discard all stderr: SDK/host diagnostics are never an evidence channel.
        Task error = process.StandardError.BaseStream.CopyToAsync(Stream.Null, token);
        try
        {
            // First line is a bounded complete JSON envelope; subsequent input is control only.
            using JsonDocument envelope = JsonDocument.Parse(input);
            string compact = JsonSerializer.Serialize(envelope.RootElement, NativeWorkflow.JsonOptions);
            await process.StandardInput.WriteLineAsync(compact.AsMemory(), token);
            await process.StandardInput.FlushAsync(token);
            string? line;
            bool handled = false;
            while ((line = await process.StandardOutput.ReadLineAsync(token)) is not null)
            {
                if (line.StartsWith("LOCAL_TRIAL ", StringComparison.Ordinal))
                {
                    NativeWorkflow.Require(proof is not null);
                    string[] command = line.Split(' ');
                    NativeWorkflow.Require(command.Length == 3);
                    LocalTrialExchange result = await proof.ExchangeAsync(command[1], command[2], token);
                    await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(result,
                        NativeWorkflow.JsonOptions).AsMemory(), token);
                    await process.StandardInput.FlushAsync(token);
                    continue;
                }
                if (line.StartsWith("LOCAL_RENEWED ", StringComparison.Ordinal))
                {
                    NativeWorkflow.Require(proof is not null);
                    string[] command = line.Split(' ', 4);
                    NativeWorkflow.Require(command.Length == 4 && Enum.TryParse<DispatchEvidence>(command[2], out _));
                    string? value = JsonSerializer.Deserialize<string>(command[3], NativeWorkflow.JsonOptions);
                    await proof.AcknowledgeRenewalAsync(command[1], value, Enum.Parse<DispatchEvidence>(command[2]), token);
                    await process.StandardInput.WriteLineAsync("acknowledged".AsMemory(), token);
                    await process.StandardInput.FlushAsync(token);
                    continue;
                }
                NativeWorkflow.Require(line == "LOCAL_RECREATE" && !handled);
                if (recreate is null) throw new InvalidOperationException("local-native-recreation-not-selected");
                handled = true;
                await recreate();
                await process.StandardInput.WriteLineAsync("continue".AsMemory(), token);
                await process.StandardInput.FlushAsync(token);
            }
            process.StandardInput.Close();
            await process.WaitForExitAsync(token);
            await error;
            NativeWorkflow.Require(process.ExitCode is 0 or 1);
        }
        finally
        {
            try
            {
                if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(CancellationToken.None); }
                try { await error; } catch (OperationCanceledException) { }
            }
            finally
            {
                // Read the durable effect witness even when the control channel or child
                // exit failed. Only a validated, bound report can authorize cleanup.
                if (File.Exists(report))
                    observe(Manifest.Parse<LocalNativeReport>(
                        Manifest.ReadFile(Path.GetDirectoryName(report)!, Path.GetFileName(report), 131072)));
            }
        }
    }
    private static async Task WriteAsync(string path, LocalNativeReport report, FileMode mode)
    {
        await using var stream = new FileStream(path, mode, FileAccess.Write, FileShare.Read);
        await JsonSerializer.SerializeAsync(stream, report, NativeWorkflow.JsonOptions);
    }
    private static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ?
        value : throw new InvalidOperationException("local-native-authority-or-input-missing");
    private static string RequiredPath(string name)
    {
        string value = Required(name);
        NativeWorkflow.Require(Path.IsPathFullyQualified(value));
        return value;
    }
}
