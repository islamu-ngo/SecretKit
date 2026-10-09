using System.Globalization;
using System.Text.Json;

namespace SecretKit.Release;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is ["workflow-check", string workflow])
            {
                WorkflowPolicy.Validate(File.ReadAllBytes(workflow));
                Console.WriteLine("workflow-policy-valid");
                return 0;
            }

            Guard.Require(args.Length >= 2, "arguments");
            string command = args[0];
            Guard.Require(command is "verify" or "initialize" or "prepare" or "dispatch" or "reconcile", "command");
            string bundle = args[1];
            Approval approval = ReadApproval();
            VerifiedRelease release = Manifest.Verify(bundle, approval);
            VerifyArtifactMetadata(bundle, approval);
            if (command == "verify")
            {
                Guard.Require(args.Length == 2, "arguments");
                Console.WriteLine("exact-artifacts-verified");
                return 0;
            }

            Guard.Require(args.Length >= 3, "arguments");
            using var journal = new Journal(args[2], release, command == "initialize" ? approval.JournalHead : null);
            string? apiKey = command == "dispatch" ? Environment.GetEnvironmentVariable("NUGET_API_KEY") : null;
            Environment.SetEnvironmentVariable("NUGET_API_KEY", null);
            var publication = new Publication(release, journal,
                new NativeFeed(approval.RepositoryCertificateSha256, approval.Owner, apiKey));
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

    public static void VerifyArtifactMetadata(string bundle, Approval approval)
    {
        using JsonDocument artifact = JsonDocument.Parse(Manifest.ReadFile(bundle, "artifact-metadata.json", 1024 * 1024));
        using JsonDocument run = JsonDocument.Parse(Manifest.ReadFile(bundle, "run-metadata.json", 1024 * 1024));
        JsonElement a = artifact.RootElement;
        JsonElement r = run.RootElement;
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
        Required("SECRETKIT_APPROVED_JOURNAL_HEAD"));

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
