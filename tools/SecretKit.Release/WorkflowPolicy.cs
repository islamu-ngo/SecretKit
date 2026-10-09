using System.Text.Json;

namespace SecretKit.Release;

public static class WorkflowPolicy
{
    // JSON is a YAML 1.2 subset. The workflow intentionally uses it so the BCL
    // can inspect actual machine values without a YAML dependency or text pins.
    public static void Validate(byte[] bytes)
    {
        JsonElement root = Manifest.Parse<JsonElement>(bytes);
        Manifest.ExactSet(root.GetProperty("on").EnumerateObject().Select(p => p.Name), ["workflow_dispatch"], "workflow-trigger");
        Permissions(root.GetProperty("permissions"), publish: false);
        Guard.Require(root.GetProperty("concurrency").GetProperty("group").GetString() == "secretkit-nuget-publication" &&
            !root.GetProperty("concurrency").GetProperty("cancel-in-progress").GetBoolean(), "workflow-concurrency");
        JsonElement jobs = root.GetProperty("jobs");
        Manifest.ExactSet(jobs.EnumerateObject().Select(p => p.Name), ["verify", "publish"], "workflow-jobs");
        JsonElement verify = jobs.GetProperty("verify");
        JsonElement publish = jobs.GetProperty("publish");
        Guard.Require(!verify.TryGetProperty("environment", out _) && !verify.TryGetProperty("permissions", out _),
            "workflow-verify-authority");
        Permissions(publish.GetProperty("permissions"), publish: true);
        Guard.Require(publish.GetProperty("environment").GetString() == "release" &&
            publish.GetProperty("needs").GetString() == "verify" &&
            publish.GetProperty("if").GetString() ==
            "${{ inputs.execute && github.repository == 'islamu-ngo/SecretKit' && github.ref == 'refs/heads/main' && github.ref_protected }}",
            "workflow-publish-guard");
        var pins = new Dictionary<string, string>
        {
            ["actions/checkout"] = "11d5960a326750d5838078e36cf38b85af677262",
            ["actions/setup-dotnet"] = "67a3573c9a986a3f9c594539f4ab511d57bb3ce9",
            ["actions/download-artifact"] = "d3f86a106a0bac45b974a628896c90dbdf5c8093",
            ["actions/upload-artifact"] = "ea165f8d65b6e75b540449e92b4886f43607fa02",
            ["NuGet/login"] = "8d196754b4036150537f80ac539e15c2f1028841"
        };
        foreach (JsonProperty job in jobs.EnumerateObject())
        {
            Guard.Require(job.Value.GetProperty("runs-on").GetString() == "ubuntu-24.04" &&
                job.Value.GetProperty("timeout-minutes").GetInt32() is > 0 and <= 45 &&
                !job.Value.TryGetProperty("continue-on-error", out _), "workflow-runner");
            foreach (JsonElement step in job.Value.GetProperty("steps").EnumerateArray())
            {
                Guard.Require(!step.TryGetProperty("continue-on-error", out _), "workflow-ignored-failure");
                if (step.TryGetProperty("uses", out JsonElement uses))
                {
                    string[] action = uses.GetString()!.Split('@');
                    Guard.Require(action.Length == 2 && pins.TryGetValue(action[0], out string? pin) && pin == action[1],
                        "workflow-action-pin");
                    if (action[0] == "actions/checkout")
                    {
                        Guard.Require(job.Name == "verify" &&
                            !step.GetProperty("with").GetProperty("persist-credentials").GetBoolean() &&
                            step.GetProperty("with").GetProperty("ref").GetString() == "${{ github.sha }}", "workflow-checkout");
                    }
                    if (action[0] == "NuGet/login")
                    {
                        Manifest.ExactSet(step.GetProperty("with").EnumerateObject().Select(p => p.Name),
                            ["user"], "workflow-login-endpoint");
                        Guard.Require(job.Name == "publish" && step.GetProperty("id").GetString() == "login" &&
                            step.GetProperty("with").GetProperty("user").GetString() == "${{ vars.SECRETKIT_NUGET_USER }}",
                            "workflow-login");
                    }
                    if (action[0] == "actions/download-artifact")
                    {
                        Guard.Require(step.GetProperty("with").GetProperty("merge-multiple").GetBoolean() &&
                            !step.GetProperty("with").TryGetProperty("name", out _) &&
                            !step.GetProperty("with").TryGetProperty("pattern", out _), "workflow-artifact-selection");
                    }
                }
                if (job.Name == "publish" && step.TryGetProperty("run", out JsonElement run))
                {
                    string script = run.GetString()!;
                    Guard.Require(!script.Contains("dotnet build", StringComparison.Ordinal) &&
                        !script.Contains("dotnet pack", StringComparison.Ordinal) &&
                        !script.Contains("dotnet restore", StringComparison.Ordinal) &&
                        !script.Contains("--skip-duplicate", StringComparison.Ordinal), "workflow-rebuild-or-replay");
                }
            }
        }

        JsonElement[] steps = publish.GetProperty("steps").EnumerateArray().ToArray();
        string[] ids = steps.Select(s => s.TryGetProperty("id", out JsonElement id) ? id.GetString()! : "").ToArray();
        int verified = Array.IndexOf(ids, "verify_artifacts");
        int initialized = Array.IndexOf(ids, "initialize");
        int initialJournal = Array.IndexOf(ids, "initial_journal");
        int login = Array.IndexOf(ids, "login");
        Guard.Require(ids.Count(id => id == "login") == 1 && verified >= 0 &&
            initialized > verified && initialJournal > initialized && login > initialJournal, "workflow-gate-order");
        JsonElement artifact = steps.Single(s => s.TryGetProperty("id", out JsonElement id) &&
            id.GetString() == "artifact_download").GetProperty("with");
        Guard.Require(artifact.GetProperty("artifact-ids").GetString() == "${{ inputs.artifact_id }}" &&
            artifact.GetProperty("run-id").GetString() == "${{ inputs.source_run_id }}" &&
            artifact.GetProperty("repository").GetString() == Manifest.RepositoryName, "workflow-artifact-source");
        JsonElement environment = publish.GetProperty("env");
        Guard.Require(environment.GetProperty("SECRETKIT_ENVIRONMENT").GetString() == "release" &&
            environment.GetProperty("SECRETKIT_ENVIRONMENT_PROTECTED").GetString() == "${{ vars.SECRETKIT_ENVIRONMENT_PROTECTED }}" &&
            environment.GetProperty("SECRETKIT_EXECUTE").GetString() == "${{ inputs.execute }}" &&
            !environment.TryGetProperty("NUGET_API_KEY", out _), "workflow-execution-authority");
        for (int i = 0; i < Manifest.PackageIds.Count; i++)
        {
            int prepare = Array.IndexOf(ids, $"prepare_{i}");
            Guard.Require(prepare >= 0 && prepare + 3 < steps.Length &&
                ids[prepare + 1] == $"before_{i}" && ids[prepare + 2] == $"dispatch_{i}" &&
                ids[prepare + 3] == $"after_{i}", "workflow-journal-order");
            string condition = $"${{{{ steps.prepare_{i}.outputs.ready == 'true' }}}}";
            Guard.Require(steps[prepare + 1].GetProperty("if").GetString() == condition &&
                steps[prepare + 2].GetProperty("if").GetString() == condition &&
                steps[prepare + 1].GetProperty("uses").GetString()!.StartsWith("actions/upload-artifact@", StringComparison.Ordinal) &&
                steps[prepare + 1].GetProperty("with").GetProperty("if-no-files-found").GetString() == "error" &&
                steps[prepare + 2].GetProperty("run").GetString() ==
                    $"dotnet runner/SecretKit.Release.dll dispatch bundle journal {Manifest.PackageIds[i]} --execute" &&
                steps[prepare + 2].GetProperty("env").GetProperty("SECRETKIT_CHECKPOINT_ARTIFACT_ID").GetString() ==
                    $"${{{{ steps.before_{i}.outputs.artifact-id }}}}" &&
                steps[prepare + 2].GetProperty("env").GetProperty("SECRETKIT_CHECKPOINT_HEAD").GetString() ==
                    $"${{{{ steps.prepare_{i}.outputs.head }}}}" &&
                steps[prepare + 2].GetProperty("env").GetProperty("NUGET_API_KEY").GetString() ==
                    "${{ steps.login.outputs.NUGET_API_KEY }}", "workflow-dispatch-checkpoint");
        }
    }

    private static void Permissions(JsonElement permissions, bool publish)
    {
        Manifest.ExactSet(permissions.EnumerateObject().Select(p => p.Name),
            publish ? ["contents", "actions", "id-token"] : ["contents", "actions"], "workflow-permissions");
        Guard.Require(permissions.GetProperty("contents").GetString() == "read" &&
            permissions.GetProperty("actions").GetString() == "read" &&
            (!publish || permissions.GetProperty("id-token").GetString() == "write"), "workflow-permissions");
    }
}
