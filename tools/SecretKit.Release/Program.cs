using System.Globalization;
using System.IO.Compression;
using System.Text.Json;

namespace SecretKit.Release;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is ["local-demo-prepare", string demoSource, string demoOriginals,
                string demoQualification, string demoOutput, string demoCommit, string demoRun,
                string demoAttempt, string demoSdk])
            {
                await DemoInputs.PrepareAsync(demoSource, demoOriginals, demoQualification, demoOutput,
                    demoCommit, long.Parse(demoRun, NumberStyles.None, CultureInfo.InvariantCulture),
                    int.Parse(demoAttempt, NumberStyles.None, CultureInfo.InvariantCulture), demoSdk);
                Console.WriteLine("ci-temporary-demo-inputs-prepared-not-native-qualified");
                return 0;
            }

            if (args is ["local-demo-check", string demoCheckSource, string demoDirectory,
                string checkCommit, string checkRun, string checkAttempt, string checkSdk])
            {
                _ = DemoInputs.Check(demoCheckSource, demoDirectory, checkCommit,
                    long.Parse(checkRun, NumberStyles.None, CultureInfo.InvariantCulture),
                    int.Parse(checkAttempt, NumberStyles.None, CultureInfo.InvariantCulture), checkSdk);
                await DemoInputs.RequireSdkAsync(demoCheckSource, checkSdk);
                Console.WriteLine("ci-temporary-demo-inputs-consistent-not-native-qualified");
                return 0;
            }

            if (args is ["local-prepare", string localSource, string localOriginals, string localOutput])
            {
                LocalQualification.Prepare(localSource, localOriginals, localOutput);
                Console.WriteLine("local-prepared-not-native-qualified");
                return 0;
            }

            if (args is ["local-check", string checkSource, string checkOriginals, string localRecord])
            {
                LocalQualification.Check(checkSource, checkOriginals, localRecord);
                Console.WriteLine("local-content-consistent-not-native-qualified");
                return 0;
            }

            if (args is ["workflow-check", string workflow])
            {
                WorkflowPolicy.Validate(File.ReadAllBytes(workflow));
                Console.WriteLine("workflow-policy-valid");
                return 0;
            }

            if (args is ["candidate-check", string candidate, string evidenceDirectory])
            {
                Manifest.CheckCandidate(candidate, new IndependentEvidence(evidenceDirectory));
                Console.WriteLine("candidate-content-consistent-not-approved");
                return 0;
            }

            if (args.Length > 0 && args[0] is "candidate-prepare" or "candidate-measure" or
                "candidate-preparation" or "candidate-assemble")
            {
                Candidate.ValidateProducerContext(Required("GITHUB_REPOSITORY"), Required("GITHUB_EVENT_NAME"),
                    Required("GITHUB_REF"), Required("GITHUB_REF_PROTECTED"), Required("GITHUB_WORKFLOW_REF"));
                Guard.Require(Required("GITHUB_ACTIONS") == "true", "candidate-actions");
                if (args.Length > 1 && args[0] != "candidate-prepare")
                {
                    CandidateInputs current = Candidate.ReadInputs(args[1]);
                    Guard.Require(current.Manifest.SourceCommit == Required("GITHUB_SHA") &&
                        current.Manifest.SourceRunId == Number("GITHUB_RUN_ID") &&
                        current.RunAttempt == Number("GITHUB_RUN_ATTEMPT"), "candidate-current-run");
                }
                if (args is ["candidate-prepare", string source, string originals, string prepared])
                    Candidate.Prepare(source, originals, prepared, Required("GITHUB_SHA"),
                        Number("GITHUB_RUN_ID"), checked((int)Number("GITHUB_RUN_ATTEMPT")));
                else if (args is ["candidate-measure", string inputs, string kind, string platform,
                    string observations, string reportDirectory])
                {
                    Directory.CreateDirectory(reportDirectory);
                    Candidate.Write(reportDirectory, "report.json", Candidate.Measure(inputs, kind, platform,
                        Number("SECRETKIT_REPORT_JOB_ID"), observations));
                }
                else if (args is ["candidate-preparation", string inputDirectory, string proofDirectory])
                {
                    CandidatePreparation proof = Manifest.Parse<CandidatePreparation>(
                        System.Text.Encoding.UTF8.GetBytes(Required("SECRETKIT_REVIEWED_PREPARATION")));
                    Candidate.ValidatePreparation(inputDirectory, proof, DateTimeOffset.UtcNow);
                    Directory.CreateDirectory(proofDirectory);
                    Candidate.Write(proofDirectory, "preparation.json", proof);
                }
                else if (args is ["candidate-assemble", string assemblyInputs, string independentDirectory,
                    string assemblyProof, string bundleDirectory])
                    Candidate.Assemble(assemblyInputs, independentDirectory, assemblyProof, bundleDirectory,
                        DateTimeOffset.UtcNow);
                else
                    throw new ReleaseException("candidate-arguments");
                Console.WriteLine("candidate-inputs-measured-not-approved");
                return 0;
            }

            if (args is ["extract-report", string archiveDirectory, string reportId, string artifactDigest,
                string outputDirectory])
            {
                Guard.Require(long.TryParse(reportId, NumberStyles.None, CultureInfo.InvariantCulture, out long id) &&
                    id > 0, "report-artifact-id");
                ExtractReport(archiveDirectory, id, artifactDigest, outputDirectory);
                Console.WriteLine("raw-report-extracted");
                return 0;
            }

            Guard.Require(args.Length >= 2, "arguments");
            string command = args[0];
            Guard.Require(command is "verify" or "initialize" or "prepare" or "dispatch" or "reconcile", "command");
            string bundle = args[1];
            Approval approval = ReadApproval();
            var independent = new IndependentEvidence(Required("SECRETKIT_EVIDENCE_DIRECTORY"));
            VerifiedRelease release = Manifest.Verify(bundle, approval, independent);
            OriginalAdmission original = ReadAuthorization<OriginalAdmission>("SECRETKIT_ORIGINAL_ADMISSION_FILE",
                "SECRETKIT_APPROVED_ORIGINAL_ADMISSION_SHA256");
            ReleaseAuthorization.BindOriginal(original, independent);
            AuthorizationPurpose purpose = command switch
            {
                "initialize" => AuthorizationPurpose.InitialAdmission,
                "reconcile" => AuthorizationPurpose.ReadOnlyRecovery,
                "verify" => Required("SECRETKIT_VERIFY_PURPOSE") switch
                {
                    "initial-admission" => AuthorizationPurpose.InitialAdmission,
                    "read-only-recovery" => AuthorizationPurpose.ReadOnlyRecovery,
                    _ => throw new ReleaseException("verify-purpose")
                },
                _ => AuthorizationPurpose.MutationAction
            };
            if (purpose != AuthorizationPurpose.MutationAction)
                ReleaseAuthorization.Validate(purpose, original, approval, release.ManifestSha256,
                    approval.JournalHead, true, null, TimeProvider.System);
            if (purpose == AuthorizationPurpose.InitialAdmission)
                ReleaseAuthorization.ValidateRetention(original, independent);
            if (command == "verify" && purpose == AuthorizationPurpose.InitialAdmission)
            {
                Guard.Require(args.Length == 2, "arguments");
                Console.WriteLine("exact-artifacts-verified");
                return 0;
            }

            Guard.Require(args.Length >= 3, "arguments");
            Guard.Require(command == "initialize" || Directory.Exists(args[2]) &&
                Directory.GetFiles(args[2], "*.json").Length > 0, "existing-journal-required");
            using var journal = new Journal(args[2], release,
                purpose == AuthorizationPurpose.MutationAction ? null : approval.JournalHead);
            if (command == "verify")
            {
                Guard.Require(args.Length == 3 && approval.JournalHead == journal.HeadSha256 &&
                    journal.Head.Sequence > 0, "recovery-journal-binding");
                Console.WriteLine("original-artifacts-and-history-verified");
                return 0;
            }
            Action? authorizePush = null;
            if (purpose == AuthorizationPurpose.MutationAction)
            {
                Guard.Require(args.Length is 4 or 5 && Manifest.PackageIds.Contains(args[3]), "arguments");
                ActionAuthorization action = ReadAuthorization<ActionAuthorization>("SECRETKIT_ACTION_AUTHORIZATION_FILE",
                    "SECRETKIT_APPROVED_ACTION_AUTHORIZATION_SHA256");
                ReleaseAuthorization.Validate(purpose, original, approval, release.ManifestSha256,
                    command == "dispatch" ? journal.Head.PreviousSha256 : journal.HeadSha256,
                    true, action, TimeProvider.System);
                ReleaseAuthorization.ValidateTransaction(action, journal, release, args[3],
                    ReadExecutionContext(), Required("GITHUB_SHA"), command == "dispatch");
                if (command == "dispatch")
                {
                    authorizePush = () =>
                    {
                        ActionAuthorization current = ReadAuthorization<ActionAuthorization>("SECRETKIT_ACTION_AUTHORIZATION_FILE",
                            "SECRETKIT_APPROVED_ACTION_AUTHORIZATION_SHA256");
                        ReleaseAuthorization.Validate(purpose, original, approval, release.ManifestSha256,
                            journal.Head.PreviousSha256, true, current, TimeProvider.System);
                        ReleaseAuthorization.ValidateTransaction(current, journal, release, args[3],
                            ReadExecutionContext(), Required("GITHUB_SHA"), dispatch: true);
                    };
                }
            }
            string? apiKey = command == "dispatch" ? Environment.GetEnvironmentVariable("NUGET_API_KEY") : null;
            Environment.SetEnvironmentVariable("NUGET_API_KEY", null);
            var publication = new Publication(release, journal,
                new NativeFeed(approval.RepositoryCertificateSha256, approval.Owner, apiKey)
                {
                    AuthorizePush = authorizePush
                });
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(20));
            if (command is "initialize" or "reconcile")
            {
                Guard.Require(args.Length == 3, "arguments");
                await publication.ReconcileAsync(deadline.Token);
                Console.WriteLine($"journal-sha256:{journal.HeadSha256}");
                PrintState(journal);
                Guard.Require(journal.Head.Packages.All(p => p.State != "unknown"), "unresolved-dispatch");
                return command == "reconcile" && !publication.Complete ? 2 : 0;
            }

            Guard.Require(args.Length is 4 or 5 && Manifest.PackageIds.Contains(args[3]), "arguments");
            string attempt = ReadExecutionContext();
            if (command == "prepare")
            {
                Guard.Require(args.Length == 4, "arguments");
                bool ready = publication.Prepare(args[3], attempt);
                string output = Required("GITHUB_OUTPUT");
                await File.AppendAllTextAsync(output,
                    $"ready={ready.ToString().ToLowerInvariant()}\nhead={journal.HeadSha256}\n", deadline.Token);
                return 0;
            }

            Guard.Require(args is [_, _, _, _, "--execute"], "execute-authorization");
            Guard.Require(Required("SECRETKIT_EXECUTE") == "true", "execute-authorization");
            Guard.Require(long.TryParse(Required("SECRETKIT_CHECKPOINT_ARTIFACT_ID"), out long checkpoint) &&
                checkpoint > 0 && Required("SECRETKIT_CHECKPOINT_HEAD") == journal.HeadSha256,
                "checkpoint-not-persisted");
            ValidateCheckpointMetadata(Required("SECRETKIT_CHECKPOINT_METADATA_FILE"), checkpoint,
                Required("SECRETKIT_CHECKPOINT_ARTIFACT_DIGEST"), Number("GITHUB_RUN_ID"),
                Required("GITHUB_RUN_ATTEMPT"), Required("GITHUB_SHA"), original);
            await publication.DispatchAsync(args[3], attempt, deadline.Token);
            PrintState(journal);
            return 0;
        }
        catch (ReleaseException failure)
        {
            Console.Error.WriteLine(failure.Message);
            return 1;
        }
        catch (Exception)
        {
            // Native response bodies, paths and credentials are never diagnostics.
            Console.Error.WriteLine("release-operation-failed");
            return 1;
        }
    }

    public static void ValidateCheckpointMetadata(string path, long artifactId, string digest,
        long executionRun, string executionAttempt, string workflowCommit, OriginalAdmission original)
    {
        string full = Path.GetFullPath(path);
        var metadata = Manifest.Parse<JsonElement>(Manifest.ReadFile(Path.GetDirectoryName(full)!,
            Path.GetFileName(full), 1024 * 1024));
        Guard.Require(Manifest.IsHash(digest) && metadata.GetProperty("id").GetInt64() == artifactId &&
            !metadata.GetProperty("expired").GetBoolean() &&
            metadata.GetProperty("digest").GetString() == "sha256:" + digest &&
            metadata.GetProperty("name").GetString() ==
                $"publication-checkpoint-{executionRun}-{executionAttempt}-before" &&
            metadata.GetProperty("workflow_run").GetProperty("id").GetInt64() == executionRun &&
            metadata.GetProperty("workflow_run").GetProperty("head_sha").GetString() == workflowCommit,
            "checkpoint-artifact-provenance");
        Guard.Require(metadata.TryGetProperty("expires_at", out JsonElement expiry) &&
            expiry.ValueKind == JsonValueKind.String && expiry.TryGetDateTimeOffset(out DateTimeOffset expiresAt) &&
            expiresAt >= original.ProducerCompletedAt.AddDays(90), "checkpoint-retention-window");
    }

    public static void VerifyArtifactMetadata(string bundle, Approval approval)
    {
        JsonElement a = Manifest.Parse<JsonElement>(Manifest.ReadFile(bundle, "artifact-metadata.json", 1024 * 1024));
        JsonElement r = Manifest.Parse<JsonElement>(Manifest.ReadFile(bundle, "run-metadata.json", 1024 * 1024));
        Guard.Require(a.GetProperty("id").GetInt64() == approval.ArtifactId &&
            !a.GetProperty("expired").GetBoolean() &&
            a.GetProperty("digest").GetString() == "sha256:" + approval.ArtifactDigest &&
            a.GetProperty("workflow_run").GetProperty("id").GetInt64() == approval.SourceRunId &&
            a.GetProperty("workflow_run").GetProperty("head_sha").GetString() == approval.SourceCommit, "artifact-provenance");
        Guard.Require(r.GetProperty("id").GetInt64() == approval.SourceRunId &&
            r.GetProperty("head_sha").GetString() == approval.SourceCommit &&
            r.GetProperty("head_branch").GetString() == "main" &&
            r.GetProperty("event").GetString() == "push" &&
            r.GetProperty("status").GetString() == "completed" &&
            r.GetProperty("conclusion").GetString() == "success" &&
            r.GetProperty("path").GetString() == ".github/workflows/verify.yml" &&
            r.GetProperty("repository").GetProperty("full_name").GetString() == Manifest.RepositoryName &&
            r.GetProperty("head_repository").GetProperty("full_name").GetString() == Manifest.RepositoryName,
            "source-run-provenance");
    }

    private static T ReadAuthorization<T>(string fileVariable, string hashVariable)
    {
        string path = Path.GetFullPath(Required(fileVariable));
        byte[] bytes = Manifest.ReadFile(Path.GetDirectoryName(path)!, Path.GetFileName(path), 64 * 1024);
        string expected = Required(hashVariable);
        Guard.Require(Manifest.IsHash(expected) && Manifest.Hash(bytes) == expected, "protected-authorization-hash");
        return Manifest.Parse<T>(bytes);
    }

    // GitHub report artifacts contain exactly one bounded original report.json.
    // Do not use archive paths for extraction or trust a download warning alone.
    public static void ExtractReport(string archiveDirectory, long artifactId, string digest, string outputDirectory)
    {
        Guard.Require(artifactId > 0 && Manifest.IsHash(digest), "report-archive-identity");
        byte[] bytes = Manifest.ReadFile(archiveDirectory, $"{artifactId}.zip", 8 * 1024 * 1024);
        Guard.Require(Manifest.Hash(bytes) == digest, "report-archive-digest");
        using var stream = new MemoryStream(bytes);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        Guard.Require(archive.Entries.Count == 1 && archive.Entries[0].FullName == "report.json" &&
            archive.Entries[0].Length is > 0 and <= EvidenceLimits.ReportBytes, "report-archive-content");
        ZipArchiveEntry entry = archive.Entries[0];
        byte[] report = new byte[(int)entry.Length];
        using Stream input = entry.Open();
        input.ReadExactly(report);
        Guard.Require(input.ReadByte() == -1, "report-archive-size");
        _ = Manifest.Parse<MachineReport>(report, EvidenceLimits.ReportBytes);
        using var output = new FileStream(Path.Combine(outputDirectory, $"{artifactId}-report.json"),
            FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(report);
    }

    public static string ReadExecutionContext()
    {
        Guard.Require(Required("GITHUB_ACTIONS") == "true" &&
            Required("GITHUB_REPOSITORY") == Manifest.RepositoryName &&
            Required("GITHUB_EVENT_NAME") == "workflow_dispatch" && Required("GITHUB_REF") == "refs/heads/main" &&
            Required("GITHUB_REF_PROTECTED") == "true" && Required("SECRETKIT_ENVIRONMENT") == "release" &&
            Required("SECRETKIT_ENVIRONMENT_PROTECTED") == "true", "protected-execution");
        string run = Required("GITHUB_RUN_ID");
        string attempt = Required("GITHUB_RUN_ATTEMPT");
        Guard.Require(long.TryParse(run, out long runId) && runId > 0 &&
            long.TryParse(attempt, out long attemptId) && attemptId > 0, "execution-attempt");
        return run + "-" + attempt;
    }

    private static Approval ReadApproval() => new(
        Required("SECRETKIT_APPROVED_MANIFEST_SHA256"), Required("SECRETKIT_APPROVED_SOURCE_COMMIT"),
        Required("SECRETKIT_APPROVED_VERSION"), Number("SECRETKIT_APPROVED_SOURCE_RUN_ID"),
        Number("SECRETKIT_APPROVED_ARTIFACT_ID"), Required("SECRETKIT_APPROVED_ARTIFACT_DIGEST"),
        Required("SECRETKIT_APPROVED_SCOPE_SHA256"), Required("SECRETKIT_NUGET_USER"),
        Required("SECRETKIT_NUGET_OWNER"), Required("SECRETKIT_NUGET_REPOSITORY_CERT_SHA256"),
        Required("SECRETKIT_APPROVED_JOURNAL_HEAD"), Required("SECRETKIT_APPROVED_EVIDENCE_SHA256"));

    private static long Number(string name)
    {
        Guard.Require(long.TryParse(Required(name), NumberStyles.None, CultureInfo.InvariantCulture, out long value) &&
            value > 0, "approval-number");
        return value;
    }

    private static string Required(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        Guard.Require(!string.IsNullOrWhiteSpace(value), "required-approval-or-context");
        return value!;
    }

    private static void PrintState(Journal journal)
    {
        foreach (PackageState state in journal.Head.Packages)
        {
            Console.WriteLine($"{state.Id}:{state.State}:available={state.Available.ToString().ToLowerInvariant()}");
        }
    }
}
