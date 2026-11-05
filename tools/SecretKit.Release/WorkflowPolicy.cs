using System.Text;
using System.Text.Json;

namespace SecretKit.Release;

public static class WorkflowPolicy
{
    public static void ValidateRoutine(byte[] bytes, IReadOnlyCollection<string> testHosts)
    {
        JsonElement root = Manifest.Parse<JsonElement>(bytes);
        Manifest.ExactSet(root.GetProperty("on").EnumerateObject().Select(p => p.Name),
            ["push", "pull_request"], "routine-events");
        Manifest.ExactSet(root.GetProperty("on").GetProperty("push").GetProperty("branches")
            .EnumerateArray().Select(p => p.GetString()!), ["main"], "routine-branches");
        Manifest.ExactSet(root.GetProperty("permissions").EnumerateObject().Select(p => p.Name),
            ["contents"], "routine-permissions");
        Guard.Require(root.GetProperty("permissions").GetProperty("contents").GetString() == "read",
            "routine-permissions");
        JsonElement jobs = root.GetProperty("jobs");
        Manifest.ExactSet(jobs.EnumerateObject().Select(p => p.Name),
            ["format", "offline", "install", "demos", "prerequisites", "native", "compatibility", "archive_evidence", "candidate"],
            "routine-jobs");
        ValidateExecutableSteps(root, ["format", "offline", "install", "demos"]);
        foreach (JsonProperty job in jobs.EnumerateObject().Where(p => p.Name is "format" or "offline" or "install" or "demos"))
        {
            Guard.Require(!job.Value.GetRawText().Contains("secrets.", StringComparison.Ordinal) &&
                !job.Value.GetRawText().Contains("github.token", StringComparison.Ordinal), "routine-credentials");
            Guard.Require(job.Value.GetProperty("runs-on").GetString() ==
                (job.Name is "install" or "demos" ? "${{ matrix.runner }}" : "ubuntu-24.04") &&
                job.Value.GetProperty("timeout-minutes").GetInt32() is > 0 and <= 45 &&
                !job.Value.TryGetProperty("permissions", out _) &&
                !job.Value.TryGetProperty("environment", out _) &&
                !job.Value.TryGetProperty("continue-on-error", out _) &&
                (job.Name is "install" or "demos" || !job.Value.TryGetProperty("needs", out _)), "routine-job-authority");
            foreach (JsonElement step in job.Value.GetProperty("steps").EnumerateArray())
            {
                Guard.Require(!step.TryGetProperty("continue-on-error", out _), "routine-ignored-failure");
                if (!step.TryGetProperty("uses", out JsonElement uses))
                    continue;
                string action = uses.GetString()!;
                Guard.Require(action is
                    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" or
                    "actions/setup-dotnet@67a3573c9a986a3f9c594539f4ab511d57bb3ce9" or
                    "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" or
                    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", "routine-action");
                if (action.StartsWith("actions/checkout@", StringComparison.Ordinal))
                    Guard.Require(!step.GetProperty("with").GetProperty("persist-credentials").GetBoolean() &&
                        step.GetProperty("with").GetProperty("ref").GetString() == "${{ github.sha }}",
                        "routine-checkout");
            }
        }

        JsonElement offline = jobs.GetProperty("offline");
        JsonElement environment = offline.GetProperty("env");
        Manifest.ExactSet(environment.EnumerateObject().Select(p => p.Name),
            ["SECRETKIT_CANDIDATE_VERSION", "SECRETKIT_CANDIDATE_DIRECTORY", "SECRETKIT_TEST_HOSTS"],
            "routine-inputs");
        Manifest.ExactSet(environment.GetProperty("SECRETKIT_TEST_HOSTS").GetString()!.Split(' ',
            StringSplitOptions.RemoveEmptyEntries), testHosts.ToArray(), "routine-test-inventory");
        Manifest.ExactSet(testHosts, Verification.Hosts.Where(host => host.Lane == "ordinary").Select(host => host.Name),
            "routine-lane-inventory");
        JsonElement[] steps = offline.GetProperty("steps").EnumerateArray().ToArray();
        string[] ids = steps.Select(s => s.TryGetProperty("id", out JsonElement id) ? id.GetString()! : "").ToArray();
        int restore = Array.IndexOf(ids, "restore");
        int build = Array.IndexOf(ids, "build");
        int pack = Array.IndexOf(ids, "pack");
        int tests = Array.IndexOf(ids, "tests");
        int metadata = Array.IndexOf(ids, "metadata");
        int upload = Array.IndexOf(ids, "reports");
        Guard.Require(restore >= 0 && build > restore && pack > build && tests > pack &&
            metadata > tests && upload > metadata, "routine-order");
        Guard.Require(steps[metadata].GetProperty("if").GetString() == "${{ always() }}" &&
            steps[metadata].GetProperty("env").GetProperty("PURPOSE").GetString() == "offline-verification" &&
            steps[upload].GetProperty("if").GetString() == "${{ always() }}" &&
            steps[upload].GetProperty("with").GetProperty("path").GetString() == "artifacts/verification" &&
            steps[upload].GetProperty("with").GetProperty("if-no-files-found").GetString() == "error",
            "routine-artifact-purpose");
        JsonElement install = jobs.GetProperty("install");
        Manifest.ExactSet(install.GetProperty("needs").EnumerateArray().Select(p => p.GetString()!),
            ["offline"], "install-original-producer");
        JsonElement strategy = install.GetProperty("strategy");
        Guard.Require(!strategy.GetProperty("fail-fast").GetBoolean(), "install-matrix-fail-fast");
        Manifest.ExactSet(strategy.GetProperty("matrix").GetProperty("include").EnumerateArray()
            .Select(p => $"{p.GetProperty("runner").GetString()}/{p.GetProperty("platform").GetString()}"),
            ["ubuntu-24.04/linux-x64-net10.0", "windows-2025/windows-x64-net10.0"], "install-matrix");
        JsonElement[] installationSteps = install.GetProperty("steps").EnumerateArray().ToArray();
        JsonElement download = installationSteps.Single(p => p.TryGetProperty("uses", out JsonElement action) &&
            action.GetString()!.StartsWith("actions/download-artifact@", StringComparison.Ordinal));
        Guard.Require(download.GetProperty("with").GetProperty("name").GetString() ==
            "local-cohort-${{ github.run_id }}-${{ github.run_attempt }}" &&
            download.GetProperty("with").GetProperty("path").GetString() == "artifacts/local-cohort",
            "install-original-artifact");
        Guard.Require(installationSteps.Single(p => p.TryGetProperty("id", out JsonElement id) &&
                id.GetString() == "test").GetProperty("run").GetString() is string installScript &&
                Matches(installScript, "dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification post-pack \"$PWD/artifacts/local-cohort\" \"$PWD/artifacts/verification/post-pack\""),
            "install-no-repack");
        ValidateDemos(jobs);
        ValidateProducer(bytes);
    }

    private static void ValidateDemos(JsonElement jobs)
    {
        JsonElement offline = jobs.GetProperty("offline");
        JsonElement[] producer = offline.GetProperty("steps").EnumerateArray().ToArray();
        int local = Array.FindIndex(producer, s => s.TryGetProperty("id", out JsonElement id) && id.GetString() == "local_install");
        int prepare = Array.FindIndex(producer, s => s.TryGetProperty("id", out JsonElement id) && id.GetString() == "demo_inputs");
        int upload = Array.FindIndex(producer, s => s.TryGetProperty("id", out JsonElement id) && id.GetString() == "demo_bundle");
        int tests = Array.FindIndex(producer, s => s.TryGetProperty("id", out JsonElement id) && id.GetString() == "demo_tests");
        Guard.Require(local >= 0 && prepare > local && upload > prepare && tests > upload,
            "demo-producer-order");
        const string runner = "dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll";
        const string selected = "\"$PWD/artifacts/local-cohort\"";
        string preparation = producer[prepare].GetProperty("run").GetString()!;
        Guard.Require(!producer[prepare].TryGetProperty("if", out _) &&
            !producer[upload].TryGetProperty("if", out _) && !producer[tests].TryGetProperty("if", out _) &&
            Matches(producer[local].GetProperty("run").GetString()!, runner + " verification prepare-local " + selected) &&
            Matches(preparation, runner + " verification check " + selected),
            "demo-producer-binding");
        JsonElement artifact = producer[upload].GetProperty("with");
        Guard.Require(artifact.GetProperty("name").GetString() ==
            "local-cohort-${{ github.run_id }}-${{ github.run_attempt }}" &&
            artifact.GetProperty("if-no-files-found").GetString() == "error" &&
            !artifact.TryGetProperty("overwrite", out _), "demo-original-artifact");
        Manifest.ExactSet(artifact.GetProperty("path").GetString()!.Split('\n'),
            new[] { "family", "symbols", "local", "local-symbols", "rebuild-family", "rebuild-symbols",
                "rebuild-local", "rebuild-local-symbols", "qualification", "demos", VerificationCohort.RecordFile }
                .Select(path => "artifacts/local-cohort/" + path), "cohort-artifact-coverage");
        JsonElement demos = jobs.GetProperty("demos");
        Manifest.ExactSet(demos.GetProperty("needs").EnumerateArray().Select(v => v.GetString()!),
            ["offline"], "demo-producer");
        Guard.Require(!demos.TryGetProperty("if", out _) &&
            !demos.GetProperty("strategy").GetProperty("fail-fast").GetBoolean(), "demo-required-matrix");
        Manifest.ExactSet(demos.GetProperty("strategy").GetProperty("matrix").GetProperty("include")
            .EnumerateArray().Select(p => $"{p.GetProperty("runner").GetString()}/{p.GetProperty("platform").GetString()}"),
            ["ubuntu-24.04/linux-x64-net10.0", "windows-2025/windows-x64-net10.0"], "demo-platforms");
        JsonElement[] consumers = demos.GetProperty("steps").EnumerateArray().ToArray();
        JsonElement download = consumers.Single(s => s.TryGetProperty("uses", out JsonElement action) &&
            action.GetString()!.StartsWith("actions/download-artifact@", StringComparison.Ordinal));
        Guard.Require(download.GetProperty("with").GetProperty("name").GetString() ==
            artifact.GetProperty("name").GetString() &&
            download.GetProperty("with").GetProperty("path").GetString() == "artifacts/local-cohort" &&
            !download.GetProperty("with").TryGetProperty("run-id", out _) &&
            !download.GetProperty("with").TryGetProperty("repository", out _), "demo-same-originals");
        string check = Step(consumers, "check").GetProperty("run").GetString()!;
        Guard.Require(Matches(check, runner + " verification check " + selected) &&
            Array.IndexOf(consumers, Step(consumers, "check")) < Array.IndexOf(consumers, Step(consumers, "test")) &&
            consumers.Where(s => s.TryGetProperty("id", out _)).All(s => !s.TryGetProperty("if", out _)),
            "demo-frozen-consumer");
        Guard.Require(!demos.TryGetProperty("env", out _) && !producer[tests].TryGetProperty("env", out _),
            "demo-cohort-selectors");
        foreach (JsonElement step in new[] { producer[tests], Step(consumers, "test") })
        {
            string script = step.GetProperty("run").GetString()!;
            Guard.Require(Matches(script, runner + " verification post-pack " + selected +
                " \"$PWD/artifacts/verification/post-pack\""), "demo-complete-discovery");
        }
        foreach (JsonElement job in new[] { offline, demos })
        {
            JsonElement checkout = job.GetProperty("steps").EnumerateArray().Single(s =>
                s.TryGetProperty("uses", out JsonElement action) &&
                action.GetString()!.StartsWith("actions/checkout@", StringComparison.Ordinal));
            JsonElement configuration = checkout.GetProperty("env");
            Guard.Require(configuration.GetProperty("GIT_CONFIG_COUNT").GetString() == "1" &&
                configuration.GetProperty("GIT_CONFIG_KEY_0").GetString() == "core.autocrlf" &&
                configuration.GetProperty("GIT_CONFIG_VALUE_0").GetString() == "false", "demo-source-bytes");
        }
    }

    public static void ValidateProducer(byte[] bytes)
    {
        JsonElement root = Manifest.Parse<JsonElement>(bytes);
        Manifest.ExactSet(root.GetProperty("on").EnumerateObject().Select(p => p.Name),
            ["push", "pull_request"], "producer-events");
        Manifest.ExactSet(root.GetProperty("permissions").EnumerateObject().Select(p => p.Name),
            ["contents"], "producer-root-permissions");
        Guard.Require(root.GetProperty("permissions").GetProperty("contents").GetString() == "read",
            "producer-root-permissions");
        Guard.Require(!root.TryGetProperty("env", out _), "producer-root-environment");
        JsonElement jobs = root.GetProperty("jobs");
        ValidateExecutableSteps(root, ["prerequisites", "native", "compatibility", "archive_evidence", "candidate"]);
        const string guard = "${{ needs.offline.outputs.candidate == 'true' && github.event_name == 'push' && github.repository == 'islamu-ngo/SecretKit' && github.ref == 'refs/heads/main' && github.ref_protected }}";
        foreach (string name in new[] { "prerequisites", "native", "compatibility", "archive_evidence", "candidate" })
        {
            JsonElement job = jobs.GetProperty(name);
            Guard.Require(job.GetProperty("if").GetString() == guard &&
                !job.TryGetProperty("continue-on-error", out _) &&
                job.GetProperty("timeout-minutes").GetInt32() is > 0 and <= 45 &&
                job.GetProperty("defaults").GetProperty("run").GetProperty("shell").GetString() == "bash" &&
                job.GetProperty("runs-on").GetString() ==
                    (name is "native" or "compatibility" ? "${{ matrix.runner }}" : "ubuntu-24.04"),
                "producer-job-guard");
            if (name is "prerequisites" or "native" or "candidate")
                Guard.Require(job.GetProperty("environment").GetString() ==
                    (name == "candidate" ? "release-candidate" : "release-evidence"), "producer-environment");
            else
                Guard.Require(!job.TryGetProperty("environment", out _), "producer-environment");
            if (name == "prerequisites")
                Guard.Require(!job.TryGetProperty("permissions", out _), "producer-permissions");
            else
                Permissions(job.GetProperty("permissions"), publish: false);
            string[] dependencies = name switch
            {
                "native" or "compatibility" => ["offline", "prerequisites"],
                "candidate" => ["format", "offline", "install", "demos", "prerequisites", "native", "compatibility", "archive_evidence"],
                _ => ["offline"]
            };
            Manifest.ExactSet(job.GetProperty("needs").EnumerateArray().Select(p => p.GetString()!),
                dependencies, "producer-dependencies");
            Guard.Require(!job.TryGetProperty("env", out JsonElement jobEnvironment) ||
                !jobEnvironment.GetRawText().Contains("secrets.", StringComparison.Ordinal), "producer-step-secrets");
            foreach (JsonElement step in job.GetProperty("steps").EnumerateArray())
            {
                Guard.Require(!step.TryGetProperty("continue-on-error", out _) &&
                    !step.TryGetProperty("if", out _), "producer-required-step");
                string raw = step.GetRawText();
                Guard.Require(!raw.Contains("NUGET_API_KEY", StringComparison.Ordinal) &&
                    !raw.Contains("id-token", StringComparison.Ordinal) &&
                    !raw.Contains("NuGet/login", StringComparison.Ordinal), "producer-no-publication-or-repack");
                if (raw.Contains("secrets.", StringComparison.Ordinal))
                {
                    string id = step.GetProperty("id").GetString()!;
                    string[] expectedSecrets = (name, id) switch
                    {
                        ("prerequisites", "preparation") => ["SECRETKIT_REVIEWED_PREPARATION"],
                        ("native", "harness") => ["SECRETKIT_NATIVE_SETTINGS"],
                        ("candidate", "collect") => ["GH_TOKEN", "SECRETKIT_REVIEWED_EVIDENCE_INDEX", "SECRETKIT_REVIEWED_EVIDENCE_SHA256"],
                        _ => throw new ReleaseException("producer-secret-placement")
                    };
                    Manifest.ExactSet(step.GetProperty("env").EnumerateObject().Select(p => p.Name),
                        expectedSecrets, "producer-secret-inventory");
                    foreach (string secret in expectedSecrets.Where(s => s != "GH_TOKEN"))
                        Guard.Require(step.GetProperty("env").GetProperty(secret).GetString() ==
                            $"${{{{ secrets.{secret} }}}}", "producer-reviewed-input");
                }
                if (!step.TryGetProperty("uses", out JsonElement uses))
                    continue;
                string action = uses.GetString()!;
                Guard.Require(action is
                    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" or
                    "actions/setup-dotnet@67a3573c9a986a3f9c594539f4ab511d57bb3ce9" or
                    "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" or
                    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", "producer-action");
                JsonElement configuration = step.GetProperty("with");
                if (action.StartsWith("actions/checkout@", StringComparison.Ordinal))
                    Guard.Require(configuration.GetProperty("ref").GetString() == "${{ github.sha }}" &&
                        !configuration.GetProperty("persist-credentials").GetBoolean(), "producer-checkout");
                if (action.StartsWith("actions/download-artifact@", StringComparison.Ordinal))
                    Guard.Require(configuration.GetProperty("name").GetString() is
                        "candidate-inputs-${{ github.run_id }}-${{ github.run_attempt }}" or
                        "candidate-preparation-${{ github.run_id }}-${{ github.run_attempt }}" &&
                        !configuration.TryGetProperty("run-id", out _) &&
                        !configuration.TryGetProperty("repository", out _), "producer-current-artifact");
                if (action.StartsWith("actions/upload-artifact@", StringComparison.Ordinal))
                    Guard.Require(configuration.GetProperty("retention-days").GetInt32() >= 91 &&
                        configuration.GetProperty("if-no-files-found").GetString() == "error" &&
                        !configuration.TryGetProperty("overwrite", out _), "producer-retention");
            }
        }
        JsonElement offline = jobs.GetProperty("offline");
        JsonElement[] offlineSteps = offline.GetProperty("steps").EnumerateArray().ToArray();
        JsonElement proposal = Step(offlineSteps, "proposal");
        Guard.Require(proposal.GetProperty("env").GetProperty("QUALIFYING_SOURCE").GetString() ==
            "${{ github.event_name == 'push' && github.repository == 'islamu-ngo/SecretKit' && github.ref == 'refs/heads/main' && github.ref_protected }}" &&
            offline.GetProperty("outputs").GetProperty("candidate").GetString() == "${{ steps.proposal.outputs.candidate }}" &&
            offline.GetProperty("outputs").GetProperty("version").GetString() == "${{ steps.proposal.outputs.version }}" &&
            Step(offlineSteps, "candidate_inputs").GetProperty("if").GetString() ==
                "${{ steps.proposal.outputs.candidate == 'true' }}", "producer-proposal");
        JsonElement inputUpload = offlineSteps.Single(s => s.TryGetProperty("uses", out JsonElement action) &&
            action.GetString()!.StartsWith("actions/upload-artifact@", StringComparison.Ordinal) &&
            s.GetProperty("with").GetProperty("path").GetString() == "artifacts/candidate-inputs");
        Guard.Require(inputUpload.GetProperty("if").GetString() == "${{ steps.proposal.outputs.candidate == 'true' }}" &&
            inputUpload.GetProperty("with").GetProperty("retention-days").GetInt32() >= 91 &&
            inputUpload.GetProperty("with").GetProperty("name").GetString() ==
                "candidate-inputs-${{ github.run_id }}-${{ github.run_attempt }}",
            "producer-original-inputs");
        foreach (string name in new[] { "native", "compatibility" })
        {
            JsonElement matrix = jobs.GetProperty(name).GetProperty("strategy");
            Guard.Require(!matrix.GetProperty("fail-fast").GetBoolean(), "producer-matrix-fail-fast");
            Manifest.ExactSet(matrix.GetProperty("matrix").GetProperty("include").EnumerateArray()
                .Select(p => $"{p.GetProperty("runner").GetString()}/{p.GetProperty("platform").GetString()}"),
                ["ubuntu-24.04/linux-x64-net10.0", "windows-2025/windows-x64-net10.0"], "producer-platforms");
        }
        JsonElement native = jobs.GetProperty("native");
        Guard.Require(native.GetProperty("name").GetString() == "${{ matrix.kind }}-${{ matrix.platform }}",
            "producer-native-job-name");
        Manifest.ExactSet(native.GetProperty("strategy").GetProperty("matrix").GetProperty("kind")
            .EnumerateArray().Select(k => k.GetString()!), ["native-operations", "live-conformance"], "producer-native-kinds");
        Manifest.ExactSet(native.GetProperty("strategy").GetProperty("matrix").GetProperty("platform")
            .EnumerateArray().Select(k => k.GetString()!), GateSemantics.Platforms, "producer-native-platforms");
        Guard.Require(native.GetProperty("strategy").GetProperty("matrix").GetProperty("exclude").GetArrayLength() == 0,
            "producer-native-exclusions");
        JsonElement compatibility = jobs.GetProperty("compatibility");
        Guard.Require(compatibility.GetProperty("name").GetString() == "compatibility-install-${{ matrix.platform }}" &&
            compatibility.GetProperty("env").GetProperty("SECRETKIT_PLATFORM_OBSERVATION").GetString() ==
                "${{ github.workspace }}/observations/installation.json", "producer-installed-observation");
        JsonElement archives = jobs.GetProperty("archive_evidence");
        Guard.Require(archives.GetProperty("name").GetString() == "${{ matrix.kind }}-none" &&
            !archives.GetProperty("strategy").GetProperty("fail-fast").GetBoolean(), "producer-archive-job");
        Manifest.ExactSet(archives.GetProperty("strategy").GetProperty("matrix").GetProperty("kind")
            .EnumerateArray().Select(k => k.GetString()!), ["provenance", "notices"], "producer-archive-kinds");
        foreach (string name in new[] { "native", "compatibility", "archive_evidence" })
        {
            JsonElement[] steps = jobs.GetProperty(name).GetProperty("steps").EnumerateArray().ToArray();
            JsonElement upload = steps.Single(s => s.TryGetProperty("uses", out JsonElement action) &&
                action.GetString()!.StartsWith("actions/upload-artifact@", StringComparison.Ordinal));
            Guard.Require(upload.GetProperty("with").GetProperty("name").GetString() ==
                "secretkit-report-${{ steps.job.outputs.id }}" &&
                upload.GetProperty("with").GetProperty("path").GetString() == "report/report.json",
                "producer-report-origin");
        }
        JsonElement[] assembly = jobs.GetProperty("candidate").GetProperty("steps").EnumerateArray().ToArray();
        int collect = Array.FindIndex(assembly, s => s.TryGetProperty("id", out JsonElement id) && id.GetString() == "collect");
        int content = Array.FindIndex(assembly, s => s.TryGetProperty("id", out JsonElement id) && id.GetString() == "content");
        int uploadIndex = Array.FindIndex(assembly, s => s.TryGetProperty("id", out JsonElement id) && id.GetString() == "candidate_upload");
        Guard.Require(collect >= 0 && content > collect && uploadIndex > content &&
            Matches(Step(assembly, "content").GetProperty("run").GetString()!,
                "dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-assemble inputs independent preparation candidate\ndotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-check candidate independent") &&
            Step(assembly, "candidate_upload").GetProperty("with").GetProperty("path").GetString() == "candidate",
            "producer-preupload-check");
    }

    private static void ValidateExecutableSteps(JsonElement root, string[] selectedJobs)
    {
        Guard.Require(!root.TryGetProperty("defaults", out _), "workflow-default-override");
        JsonElement jobs = root.GetProperty("jobs");
        foreach (string name in selectedJobs)
        {
            Guard.Require(jobs.TryGetProperty(name, out JsonElement job), "workflow-required-job");
            Guard.Require(!job.TryGetProperty("container", out _) && !job.TryGetProperty("services", out _) &&
                !job.TryGetProperty("uses", out _), "workflow-execution-override");
            if (job.TryGetProperty("defaults", out JsonElement defaults))
            {
                Manifest.ExactSet(defaults.EnumerateObject().Select(property => property.Name), ["run"], "workflow-defaults");
                JsonElement run = defaults.GetProperty("run");
                Manifest.ExactSet(run.EnumerateObject().Select(property => property.Name), ["shell"], "workflow-defaults");
                Guard.Require(run.GetProperty("shell").GetString() == "bash", "workflow-shell");
            }
            CheckEnvironment(job, name);
            if (job.TryGetProperty("strategy", out JsonElement strategy))
            {
                Manifest.ExactSet(strategy.EnumerateObject().Select(property => property.Name),
                    ["fail-fast", "matrix"], "workflow-strategy");
                string[] dimensions = name switch
                {
                    "native" => ["kind", "include", "platform", "exclude"],
                    "archive_evidence" => ["kind"],
                    _ => ["include"]
                };
                Manifest.ExactSet(strategy.GetProperty("matrix").EnumerateObject().Select(property => property.Name),
                    dimensions, "workflow-matrix");
            }
            JsonElement[] steps = job.GetProperty("steps").EnumerateArray().ToArray();
            string[] ids = steps.Where(step => step.TryGetProperty("id", out _))
                .Select(step => step.GetProperty("id").GetString()!).ToArray();
            Guard.Require(ids.Distinct(StringComparer.Ordinal).Count() == ids.Length, "workflow-step-id");
            var order = new List<string>();
            foreach (JsonElement step in steps)
            {
                Guard.Require(!step.TryGetProperty("shell", out _) &&
                    !step.TryGetProperty("working-directory", out _) &&
                    !step.TryGetProperty("continue-on-error", out _), "workflow-step-override");
                string id = step.TryGetProperty("id", out JsonElement identity) ? identity.GetString()! :
                    step.TryGetProperty("uses", out JsonElement selectedAction) &&
                        selectedAction.GetString()!.StartsWith("actions/checkout@", StringComparison.Ordinal) ? "checkout" : "";
                CheckEnvironment(step, name + "/" + id);
                if (step.TryGetProperty("run", out JsonElement command))
                {
                    Guard.Require(!step.TryGetProperty("uses", out _) && step.TryGetProperty("id", out _),
                        "workflow-executable-step");
                    Guard.Require(Commands.TryGetValue(name + "/" + id, out string? expected) &&
                        Matches(command.GetString()!, expected), "workflow-executable-contract");
                    bool conditional = name == "offline" && id is "candidate_inputs" or "metadata";
                    Guard.Require(conditional == step.TryGetProperty("if", out _), "workflow-step-condition");
                    order.Add("run/" + id);
                    continue;
                }
                Guard.Require(step.TryGetProperty("uses", out JsonElement action), "workflow-step-kind");
                string kind = action.GetString()!.Split('@')[0];
                JsonElement configuration = step.GetProperty("with");
                string[] keys = kind switch
                {
                    "actions/checkout" => ["ref", "persist-credentials"],
                    "actions/setup-dotnet" => ["global-json-file"],
                    "actions/download-artifact" => ["name", "path"],
                    "actions/upload-artifact" => ["name", "path", "if-no-files-found", "retention-days"],
                    _ => throw new ReleaseException("workflow-action")
                };
                Manifest.ExactSet(configuration.EnumerateObject().Select(property => property.Name), keys,
                    "workflow-action-inputs");
                if (kind == "actions/setup-dotnet")
                    Guard.Require(configuration.GetProperty("global-json-file").GetString() == "global.json",
                        "workflow-sdk-source");
                string role = kind switch
                {
                    "actions/checkout" => "checkout",
                    "actions/setup-dotnet" => "sdk",
                    "actions/download-artifact" => "download/" + configuration.GetProperty("path").GetString(),
                    _ => "upload/" + configuration.GetProperty("name").GetString()
                };
                bool maySkip = kind == "actions/upload-artifact" &&
                    (name is "offline" or "install" or "demos") &&
                    configuration.GetProperty("name").GetString() !=
                        "local-cohort-${{ github.run_id }}-${{ github.run_attempt }}" &&
                    configuration.GetProperty("name").GetString() !=
                        "offline-originals-${{ github.run_id }}-${{ github.run_attempt }}";
                Guard.Require(maySkip == step.TryGetProperty("if", out _), "workflow-action-condition");
                if (maySkip)
                {
                    string condition = configuration.GetProperty("path").GetString() == "artifacts/candidate-inputs"
                        ? "${{ steps.proposal.outputs.candidate == 'true' }}" : "${{ always() }}";
                    Guard.Require(step.GetProperty("if").GetString() == condition, "workflow-action-condition");
                }
                order.Add(role);
            }
            Guard.Require(order.SequenceEqual(StepOrder[name]), "workflow-step-order");
        }
    }

    private static void CheckEnvironment(JsonElement owner, string selection)
    {
        Environments.TryGetValue(selection, out IReadOnlyDictionary<string, string>? expected);
        if (!owner.TryGetProperty("env", out JsonElement environment))
        {
            Guard.Require(expected is null, "workflow-environment");
            return;
        }
        Guard.Require(expected is not null, "workflow-environment");
        Manifest.ExactSet(environment.EnumerateObject().Select(property => property.Name), expected!.Keys,
            "workflow-environment");
        foreach ((string key, string value) in expected)
            Guard.Require(environment.GetProperty(key).GetString() == value, "workflow-environment-binding");
    }

    private static bool Matches(string actual, string expected) =>
        Tokens(actual).SequenceEqual(Tokens(expected), StringComparer.Ordinal);

    // This compares a closed contract; it does not interpret or execute shell.
    // Quoted bytes, substitutions, operators and command boundaries remain exact.
    private static string[] Tokens(string script)
    {
        var tokens = new List<string>();
        var token = new StringBuilder();
        char quote = '\0';
        for (int index = 0; index < script.Length; index++)
        {
            char current = script[index];
            if (current == '\\' && quote != '\'' && index + 1 < script.Length)
            {
                char next = script[index + 1];
                if (next == '\n') { index++; continue; }
                if (next == '\r' && index + 2 < script.Length && script[index + 2] == '\n')
                {
                    index += 2;
                    continue;
                }
                token.Append(current).Append(next);
                index++;
                continue;
            }
            if (quote != '\0')
            {
                token.Append(current);
                if (current == quote) quote = '\0';
                continue;
            }
            if (current is '\'' or '"')
            {
                quote = current;
                token.Append(current);
                continue;
            }
            if (current == '#' && token.Length == 0)
            {
                while (index < script.Length && script[index] != '\n') index++;
                current = '\n';
            }
            if (char.IsWhiteSpace(current))
            {
                Flush();
                if (current == '\n' && tokens.Count > 0 && tokens[^1] != "\n") tokens.Add("\n");
                continue;
            }
            if (";&|<>(){}".Contains(current, StringComparison.Ordinal))
            {
                Flush();
                tokens.Add(current.ToString());
                continue;
            }
            token.Append(current);
        }
        Guard.Require(quote == '\0', "workflow-command-quotes");
        Flush();
        if (tokens.Count > 0 && tokens[^1] == "\n") tokens.RemoveAt(tokens.Count - 1);
        return tokens.ToArray();

        void Flush()
        {
            if (token.Length == 0) return;
            tokens.Add(token.ToString());
            token.Clear();
        }
    }

    // Closed executable contracts. Values are shell tokens, not substring hints:
    // indentation, blank lines and comments cannot add or remove an executable step.
    private static readonly IReadOnlyDictionary<string, string> Commands = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["format/format"] = """
            dotnet restore SecretKit.slnx --locked-mode
            dotnet format SecretKit.slnx --verify-no-changes --no-restore --verbosity quiet
            """,
        ["offline/proposal"] = """
            candidate=false
            if [[ "$QUALIFYING_SOURCE" == true && -f docs/internal/releases/candidate.json ]]; then
              candidate=true
              SECRETKIT_CANDIDATE_VERSION=$(jq -er '.version | select(test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[a-z][a-z0-9-]*(\\.(0|[1-9][0-9]*|[a-z][a-z0-9-]*))*)?$"))' docs/internal/releases/candidate.json)
            fi
            printf 'candidate=%s\nversion=%s\n' "$candidate" "$SECRETKIT_CANDIDATE_VERSION" >> "$GITHUB_OUTPUT"
            printf 'SECRETKIT_CANDIDATE_VERSION=%s\n' "$SECRETKIT_CANDIDATE_VERSION" >> "$GITHUB_ENV"
            """,
        ["offline/restore"] = """
            dotnet restore SecretKit.slnx --locked-mode
            """,
        ["offline/build"] = """
            dotnet build SecretKit.slnx --configuration Release --no-restore -p:Version="$SECRETKIT_CANDIDATE_VERSION"
            """,
        ["offline/offline_conformance_guards"] = """
            dotnet restore SecretKit.Conformance.slnx --locked-mode
            dotnet build SecretKit.Conformance.slnx --configuration Release --no-restore -p:Version="$SECRETKIT_CANDIDATE_VERSION"
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification offline-conformance
            """,
        ["offline/pack"] = """
            test ! -e "$SECRETKIT_CANDIDATE_DIRECTORY"
            dotnet pack SecretKit.slnx --configuration Release --no-build -p:Version="$SECRETKIT_CANDIDATE_VERSION" --output "$SECRETKIT_CANDIDATE_DIRECTORY"
            """,
        ["offline/tests"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification ordinary
            """,
        ["offline/candidate_inputs"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-prepare . "$SECRETKIT_CANDIDATE_DIRECTORY" artifacts/candidate-inputs
            """,
        ["offline/local_directory"] = """
            mkdir -p artifacts/verification/local
            """,
        ["offline/local_install"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification prepare-local "$PWD/artifacts/local-cohort"
            """,
        ["offline/demo_inputs"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification check "$PWD/artifacts/local-cohort"
            """,
        ["offline/dependency_audit"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll dependency-audit SecretKit.slnx "$PWD/artifacts/verification/advisories/source"
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll dependency-audit SecretKit.Conformance.slnx "$PWD/artifacts/verification/advisories/conformance"
            """,
        ["offline/dependency_audit_installed"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll dependency-audit-installed-set "$PWD/artifacts/local-cohort" "$PWD/artifacts/verification/post-pack" "$PWD/artifacts/verification/advisories/installed"
            """,
        ["install/dependency_audit_installed"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll dependency-audit-installed-set "$PWD/artifacts/local-cohort" "$PWD/artifacts/verification/post-pack" "$PWD/artifacts/verification/advisories/installed"
            """,
        ["demos/dependency_audit_installed"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll dependency-audit-installed-set "$PWD/artifacts/local-cohort" "$PWD/artifacts/verification/post-pack" "$PWD/artifacts/verification/advisories/installed"
            """,
        ["offline/demo_tests"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification post-pack "$PWD/artifacts/local-cohort" "$PWD/artifacts/verification/post-pack"
            """,
        ["offline/metadata"] = """
            mkdir -p artifacts/verification
            printf 'purpose=%s\nsource=%s\nversion=%s\nrestore=%s\nbuild=%s\npack=%s\ntests=%s\nsamples=%s\n' "$PURPOSE" "$SOURCE" "$SECRETKIT_CANDIDATE_VERSION" "$RESTORE_RESULT" "$BUILD_RESULT" "$PACK_RESULT" "$TEST_RESULT" "$SAMPLE_RESULT" > artifacts/verification/checks.txt
            dotnet --version > artifacts/verification/sdk.txt
            for archive in "$SECRETKIT_CANDIDATE_DIRECTORY"/*.nupkg; do
              [[ -f "$archive" ]] || continue
              sha256sum "$archive" >> artifacts/verification/packages.sha256
            done
            """,
        ["install/restore"] = """
            dotnet restore SecretKit.slnx --locked-mode
            """,
        ["install/build"] = """
            dotnet build SecretKit.slnx --configuration Release --no-restore
            """,
        ["install/test"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification post-pack "$PWD/artifacts/local-cohort" "$PWD/artifacts/verification/post-pack"
            """,
        ["demos/build"] = """
            dotnet restore SecretKit.slnx --locked-mode
            dotnet build SecretKit.slnx --configuration Release --no-restore
            """,
        ["demos/check"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification check "$PWD/artifacts/local-cohort"
            """,
        ["demos/test"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification post-pack "$PWD/artifacts/local-cohort" "$PWD/artifacts/verification/post-pack"
            """,
        ["prerequisites/bootstrap"] = """
            dotnet restore tools/SecretKit.Release/SecretKit.Release.csproj --locked-mode
            dotnet build tools/SecretKit.Release/SecretKit.Release.csproj --configuration Release --no-restore
            """,
        ["prerequisites/preparation"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-preparation inputs preparation
            """,
        ["native/job"] = """
            gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT/jobs?per_page=100" > jobs.json
            id=$(jq -er --arg name "$REPORT_JOB_NAME" '[.[].jobs[] | select(.name == $name and .status == "in_progress")] | if length == 1 then .[0].id else error("ambiguous-report-job") end' jobs.json)
            printf 'id=%s\n' "$id" >> "$GITHUB_OUTPUT"
            printf 'SECRETKIT_REPORT_JOB_ID=%s\n' "$id" >> "$GITHUB_ENV"
            """,
        ["native/harness"] = """
            test -n "$SECRETKIT_NATIVE_SETTINGS"
            test -f tests/fixtures/SecretKit.TestHarness/NativeObservationReport.cs || { printf 'native-harness-unavailable\n' >&2; exit 1; }
            for provider in Infisical AzureKeyVault; do
              project="tests/SecretKit.$provider.Conformance.Tests/SecretKit.$provider.Conformance.Tests.csproj"
              test -f "$project" || { printf 'native-host-unavailable\n' >&2; exit 1; }
              dotnet restore "$project" --locked-mode
              dotnet build "$project" --configuration Release --no-restore
            done
            dotnet restore tools/SecretKit.Release/SecretKit.Release.csproj --locked-mode
            dotnet build tools/SecretKit.Release/SecretKit.Release.csproj --configuration Release --no-restore
            mkdir -p observations
            for provider in Infisical AzureKeyVault; do
              export SECRETKIT_NATIVE_REPORT="$GITHUB_WORKSPACE/observations/$provider.json"
              dotnet "tests/SecretKit.$provider.Conformance.Tests/bin/Release/net10.0/SecretKit.$provider.Conformance.Tests.dll" --minimum-expected-tests 1 --zero-tests-policy strict
            done
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-measure inputs "$SECRETKIT_NATIVE_KIND" "$SECRETKIT_NATIVE_PLATFORM" observations report
            """,
        ["compatibility/job"] = """
            gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT/jobs?per_page=100" > jobs.json
            id=$(jq -er --arg name "$REPORT_JOB_NAME" '[.[].jobs[] | select(.name == $name and .status == "in_progress")] | if length == 1 then .[0].id else error("ambiguous-report-job") end' jobs.json)
            printf 'id=%s\n' "$id" >> "$GITHUB_OUTPUT"
            printf 'SECRETKIT_REPORT_JOB_ID=%s\n' "$id" >> "$GITHUB_ENV"
            """,
        ["compatibility/measured_install"] = """
            dotnet restore tests/SecretKit.Package.Tests/SecretKit.Package.Tests.csproj --locked-mode
            dotnet build tests/SecretKit.Package.Tests/SecretKit.Package.Tests.csproj --configuration Release --no-restore
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification public-install
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-measure inputs compatibility-install "${{ matrix.platform }}" observations report
            """,
        ["archive_evidence/job"] = """
            gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT/jobs?per_page=100" > jobs.json
            id=$(jq -er --arg name "$REPORT_JOB_NAME" '[.[].jobs[] | select(.name == $name and .status == "in_progress")] | if length == 1 then .[0].id else error("ambiguous-report-job") end' jobs.json)
            printf 'id=%s\n' "$id" >> "$GITHUB_OUTPUT"
            printf 'SECRETKIT_REPORT_JOB_ID=%s\n' "$id" >> "$GITHUB_ENV"
            """,
        ["archive_evidence/measure"] = """
            dotnet restore tools/SecretKit.Release/SecretKit.Release.csproj --locked-mode
            dotnet build tools/SecretKit.Release/SecretKit.Release.csproj --configuration Release --no-restore
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-measure inputs "${{ matrix.kind }}" none . report
            """,
        ["candidate/runner"] = """
            dotnet restore tools/SecretKit.Release/SecretKit.Release.csproj --locked-mode
            dotnet build tools/SecretKit.Release/SecretKit.Release.csproj --configuration Release --no-restore
            """,
        ["candidate/collect"] = """
            test -n "$SECRETKIT_REVIEWED_EVIDENCE_INDEX"
            [[ "$SECRETKIT_REVIEWED_EVIDENCE_SHA256" =~ ^[0-9a-f]{64}$ ]]
            mkdir independent archives
            printf '%s' "$SECRETKIT_REVIEWED_EVIDENCE_INDEX" > independent/evidence-index.json
            printf '%s  independent/evidence-index.json\n' "$SECRETKIT_REVIEWED_EVIDENCE_SHA256" | sha256sum --check --status
            jq -e --arg source "$GITHUB_SHA" --argjson run "$GITHUB_RUN_ID" --argjson attempt "$GITHUB_RUN_ATTEMPT" '.sourceCommit == $source and .runId == $run and .runAttempt == $attempt and (.reports | length == 8) and (.attestations | length == 4)' independent/evidence-index.json > /dev/null
            gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT" > independent/run-metadata.json
            for file in infisical.json azure-key-vault.json; do
              gh api -H 'Accept: application/vnd.github.raw+json' "repos/$GITHUB_REPOSITORY/contents/docs/internal/releases/admission/$file?ref=$GITHUB_SHA" > "independent/$file"
            done
            gh api -H 'Accept: application/vnd.github.raw+json' "repos/$GITHUB_REPOSITORY/contents/THIRD-PARTY-NOTICES.md?ref=$GITHUB_SHA" > independent/THIRD-PARTY-NOTICES.md
            jq -er '.reports[] | [.jobId, .artifactId, .artifactDigest] | @tsv' independent/evidence-index.json > origins.tsv
            while IFS=$'\t' read -r job artifact digest; do
              [[ "$job" =~ ^[1-9][0-9]*$ && "$artifact" =~ ^[1-9][0-9]*$ && "$digest" =~ ^[0-9a-f]{64}$ ]]
              gh api "repos/$GITHUB_REPOSITORY/actions/jobs/$job" > "independent/$job-job.json"
              gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact" > "independent/$artifact-artifact.json"
              gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact/zip" > "archives/$artifact.zip"
              dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll extract-report archives "$artifact" "$digest" independent
            done < origins.tsv
            """,
        ["candidate/content"] = """
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-assemble inputs independent preparation candidate
            dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll candidate-check candidate independent
            """,
    };

    private static readonly IReadOnlyDictionary<string, string[]> StepOrder = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["format"] = ["checkout", "sdk", "run/format"],
        ["offline"] = ["checkout", "sdk", "run/proposal", "run/restore", "run/build", "run/offline_conformance_guards", "run/dependency_audit", "run/pack", "upload/offline-originals-${{ github.run_id }}-${{ github.run_attempt }}", "run/tests", "run/candidate_inputs", "upload/candidate-inputs-${{ github.run_id }}-${{ github.run_attempt }}", "run/local_directory", "run/local_install", "run/demo_inputs", "upload/local-cohort-${{ github.run_id }}-${{ github.run_attempt }}", "run/demo_tests", "run/dependency_audit_installed", "run/metadata", "upload/offline-verification-${{ github.run_id }}-${{ github.run_attempt }}"],
        ["install"] = ["checkout", "sdk", "download/artifacts/local-cohort", "run/restore", "run/build", "run/test", "run/dependency_audit_installed", "upload/offline-install-${{ matrix.platform }}-${{ github.run_id }}-${{ github.run_attempt }}"],
        ["demos"] = ["checkout", "sdk", "download/artifacts/local-cohort", "run/build", "run/check", "run/test", "run/dependency_audit_installed", "upload/demo-observations-${{ matrix.platform }}-${{ github.run_id }}-${{ github.run_attempt }}"],
        ["prerequisites"] = ["checkout", "sdk", "download/inputs", "run/bootstrap", "run/preparation", "upload/candidate-preparation-${{ github.run_id }}-${{ github.run_attempt }}"],
        ["native"] = ["checkout", "sdk", "download/inputs", "download/preparation", "run/job", "run/harness", "upload/secretkit-report-${{ steps.job.outputs.id }}"],
        ["compatibility"] = ["checkout", "sdk", "download/inputs", "run/job", "run/measured_install", "upload/secretkit-report-${{ steps.job.outputs.id }}"],
        ["archive_evidence"] = ["checkout", "sdk", "download/inputs", "run/job", "run/measure", "upload/secretkit-report-${{ steps.job.outputs.id }}"],
        ["candidate"] = ["checkout", "sdk", "download/inputs", "download/preparation", "run/runner", "run/collect", "run/content", "upload/candidate-independent-evidence-${{ github.run_id }}-${{ github.run_attempt }}", "upload/secretkit-candidate-${{ github.run_id }}-${{ github.run_attempt }}"],
    };

    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Environments =
        new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal)
        {
            ["offline"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["SECRETKIT_CANDIDATE_VERSION"] = "0.1.0-preview.1",
                ["SECRETKIT_CANDIDATE_DIRECTORY"] = "${{ github.workspace }}/artifacts/packages",
                ["SECRETKIT_TEST_HOSTS"] = "SecretKit.Core.Tests SecretKit.Infisical.Tests SecretKit.AzureKeyVault.Tests SecretKit.Consumer.Tests SecretKit.Assessment.Tests SecretKit.Configuration.Tests SecretKit.Hosting.Tests SecretKit.Infisical.Management.Tests SecretKit.AzureKeyVault.Management.Tests SecretKit.Release.Tests SecretKit.ProviderContract.Tests",
            },
            ["offline/checkout"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["GIT_CONFIG_COUNT"] = "1",
                ["GIT_CONFIG_KEY_0"] = "core.autocrlf",
                ["GIT_CONFIG_VALUE_0"] = "false",
            },
            ["offline/proposal"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["QUALIFYING_SOURCE"] = "${{ github.event_name == 'push' && github.repository == 'islamu-ngo/SecretKit' && github.ref == 'refs/heads/main' && github.ref_protected }}",
            },
            ["offline/metadata"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["PURPOSE"] = "offline-verification",
                ["SOURCE"] = "${{ github.sha }}",
                ["RESTORE_RESULT"] = "${{ steps.restore.outcome }}",
                ["BUILD_RESULT"] = "${{ steps.build.outcome }}",
                ["PACK_RESULT"] = "${{ steps.pack.outcome }}",
                ["TEST_RESULT"] = "${{ steps.tests.outcome }}",
                ["SAMPLE_RESULT"] = "${{ steps.tests.outcome }}",
            },
            ["install/checkout"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["GIT_CONFIG_COUNT"] = "1",
                ["GIT_CONFIG_KEY_0"] = "core.autocrlf",
                ["GIT_CONFIG_VALUE_0"] = "false",
            },
            ["demos/checkout"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["GIT_CONFIG_COUNT"] = "1",
                ["GIT_CONFIG_KEY_0"] = "core.autocrlf",
                ["GIT_CONFIG_VALUE_0"] = "false",
            },
            ["prerequisites/preparation"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["SECRETKIT_REVIEWED_PREPARATION"] = "${{ secrets.SECRETKIT_REVIEWED_PREPARATION }}",
            },
            ["native"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["SECRETKIT_CANDIDATE_VERSION"] = "${{ needs.offline.outputs.version }}",
                ["SECRETKIT_CANDIDATE_DIRECTORY"] = "${{ github.workspace }}/inputs",
                ["SECRETKIT_NATIVE_INPUTS"] = "${{ github.workspace }}/inputs/candidate-inputs.json",
                ["SECRETKIT_NATIVE_KIND"] = "${{ matrix.kind }}",
                ["SECRETKIT_NATIVE_PLATFORM"] = "${{ matrix.platform }}",
            },
            ["native/job"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["GH_TOKEN"] = "${{ github.token }}",
                ["REPORT_JOB_NAME"] = "${{ matrix.kind }}-${{ matrix.platform }}",
            },
            ["native/harness"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["SECRETKIT_NATIVE_SETTINGS"] = "${{ secrets.SECRETKIT_NATIVE_SETTINGS }}",
            },
            ["compatibility"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["SECRETKIT_CANDIDATE_VERSION"] = "${{ needs.offline.outputs.version }}",
                ["SECRETKIT_CANDIDATE_DIRECTORY"] = "${{ github.workspace }}/inputs",
                ["SECRETKIT_PLATFORM_OBSERVATION"] = "${{ github.workspace }}/observations/installation.json",
            },
            ["compatibility/job"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["GH_TOKEN"] = "${{ github.token }}",
                ["REPORT_JOB_NAME"] = "compatibility-install-${{ matrix.platform }}",
            },
            ["archive_evidence/job"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["GH_TOKEN"] = "${{ github.token }}",
                ["REPORT_JOB_NAME"] = "${{ matrix.kind }}-none",
            },
            ["candidate/collect"] = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["GH_TOKEN"] = "${{ github.token }}",
                ["SECRETKIT_REVIEWED_EVIDENCE_INDEX"] = "${{ secrets.SECRETKIT_REVIEWED_EVIDENCE_INDEX }}",
                ["SECRETKIT_REVIEWED_EVIDENCE_SHA256"] = "${{ secrets.SECRETKIT_REVIEWED_EVIDENCE_SHA256 }}",
            },
        };

    private static JsonElement Step(JsonElement[] steps, string id) =>
        steps.Single(s => s.TryGetProperty("id", out JsonElement value) && value.GetString() == id);

    // JSON is a YAML 1.2 subset. The workflow intentionally uses it so the BCL
    // can inspect actual machine values without a YAML dependency or text pins.
    public static void Validate(byte[] bytes)
    {
        JsonElement root = Manifest.Parse<JsonElement>(bytes);
        Manifest.ExactSet(root.GetProperty("on").EnumerateObject().Select(p => p.Name), ["workflow_dispatch"], "workflow-trigger");
        Permissions(root.GetProperty("permissions"), publish: false);
        Guard.Require(!root.TryGetProperty("env", out _), "workflow-root-environment");
        JsonElement inputs = root.GetProperty("on").GetProperty("workflow_dispatch").GetProperty("inputs");
        Manifest.ExactSet(inputs.EnumerateObject().Select(p => p.Name),
            ["source_run_id", "artifact_id", "manifest_sha256", "journal_run_id", "journal_artifact_id", "mode", "package_id", "execute"],
            "workflow-inputs");
        JsonElement mode = inputs.GetProperty("mode");
        Guard.Require(mode.GetProperty("type").GetString() == "choice" && mode.GetProperty("required").GetBoolean() &&
            mode.GetProperty("default").GetString() == "initial-admission", "workflow-purpose");
        Manifest.ExactSet(mode.GetProperty("options").EnumerateArray().Select(p => p.GetString()!),
            ["initial-admission", "read-only-recovery", "publish-one"], "workflow-purpose");
        JsonElement package = inputs.GetProperty("package_id");
        Guard.Require(package.GetProperty("type").GetString() == "choice" && package.GetProperty("required").GetBoolean(),
            "workflow-package-selection");
        Manifest.ExactSet(package.GetProperty("options").EnumerateArray().Select(p => p.GetString()!),
            Manifest.PackageIds.ToArray(), "workflow-package-selection");
        Guard.Require(inputs.GetProperty("execute").GetProperty("type").GetString() == "boolean" &&
            !inputs.GetProperty("execute").GetProperty("default").GetBoolean(), "workflow-execute-input");
        Guard.Require(root.GetProperty("concurrency").GetProperty("group").GetString() == "secretkit-nuget-publication" &&
            !root.GetProperty("concurrency").GetProperty("cancel-in-progress").GetBoolean(), "workflow-concurrency");
        JsonElement jobs = root.GetProperty("jobs");
        Manifest.ExactSet(jobs.EnumerateObject().Select(p => p.Name), ["verify", "observe", "publish_one"], "workflow-jobs");
        JsonElement verify = jobs.GetProperty("verify");
        Guard.Require(!verify.TryGetProperty("environment", out _) && !verify.TryGetProperty("permissions", out _) &&
            !verify.TryGetProperty("env", out _), "workflow-verify-authority");
        const string canonical = "github.repository == 'islamu-ngo/SecretKit' && github.ref == 'refs/heads/main' && github.ref_protected";
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
            bool mutation = job.Name == "publish_one";
            Guard.Require(job.Value.GetProperty("runs-on").GetString() == "ubuntu-24.04" &&
                job.Value.GetProperty("timeout-minutes").GetInt32() is > 0 and <= 45 &&
                job.Value.GetProperty("defaults").GetProperty("run").GetProperty("shell").GetString() == "bash" &&
                !job.Value.TryGetProperty("continue-on-error", out _) &&
                !job.Value.TryGetProperty("strategy", out _), "workflow-runner");
            if (job.Name == "observe")
                Guard.Require(!job.Value.TryGetProperty("permissions", out _), "workflow-observation-authority");
            if (mutation)
                Permissions(job.Value.GetProperty("permissions"), publish: true);
            if (job.Name != "verify")
            {
                Guard.Require(job.Value.GetProperty("environment").GetString() == "release" &&
                    job.Value.GetProperty("needs").GetString() == "verify" &&
                    job.Value.GetProperty("if").GetString() == (mutation
                        ? "${{ inputs.mode == 'publish-one' && inputs.execute && github.run_attempt == 1 && " + canonical + " }}"
                        : "${{ (inputs.mode == 'initial-admission' || inputs.mode == 'read-only-recovery') && " + canonical + " }}"),
                    "workflow-purpose-guard");
                JsonElement environment = job.Value.GetProperty("env");
                string[] common = ["SECRETKIT_APPROVED_MANIFEST_SHA256", "SECRETKIT_APPROVED_SOURCE_COMMIT",
                    "SECRETKIT_APPROVED_VERSION", "SECRETKIT_APPROVED_SOURCE_RUN_ID", "SECRETKIT_APPROVED_ARTIFACT_ID",
                    "SECRETKIT_APPROVED_ARTIFACT_DIGEST", "SECRETKIT_APPROVED_SCOPE_SHA256", "SECRETKIT_APPROVED_EVIDENCE_SHA256",
                    "SECRETKIT_EVIDENCE_DIRECTORY", "SECRETKIT_NUGET_USER", "SECRETKIT_NUGET_OWNER",
                    "SECRETKIT_NUGET_REPOSITORY_CERT_SHA256", "SECRETKIT_APPROVED_JOURNAL_HEAD", "SECRETKIT_ENVIRONMENT_PROTECTED",
                    "SECRETKIT_ENVIRONMENT", "SECRETKIT_ORIGINAL_ADMISSION_FILE", "SECRETKIT_APPROVED_ORIGINAL_ADMISSION_SHA256",
                    "SECRETKIT_VERIFY_PURPOSE"];
                Manifest.ExactSet(environment.EnumerateObject().Select(p => p.Name), mutation
                    ? [.. common, "SECRETKIT_ACTION_AUTHORIZATION_FILE", "SECRETKIT_APPROVED_ACTION_AUTHORIZATION_SHA256", "SECRETKIT_EXECUTE"]
                    : common, "workflow-authorization-inputs");
                foreach (JsonProperty value in environment.EnumerateObject())
                {
                    string expected = value.Name switch
                    {
                        "SECRETKIT_ENVIRONMENT" => "release",
                        "SECRETKIT_EVIDENCE_DIRECTORY" => "independent-evidence",
                        "SECRETKIT_ORIGINAL_ADMISSION_FILE" => "authorization/original-admission.json",
                        "SECRETKIT_ACTION_AUTHORIZATION_FILE" => "authorization/action.json",
                        "SECRETKIT_VERIFY_PURPOSE" => mutation ? "read-only-recovery" : "${{ inputs.mode }}",
                        "SECRETKIT_EXECUTE" => "${{ inputs.execute }}",
                        _ => "${{ vars." + value.Name + " }}"
                    };
                    Guard.Require(value.Value.GetString() == expected, "workflow-protected-value");
                }
            }
            foreach (JsonElement step in job.Value.GetProperty("steps").EnumerateArray())
            {
                Guard.Require(!step.TryGetProperty("continue-on-error", out _), "workflow-ignored-failure");
                if (step.TryGetProperty("uses", out JsonElement uses))
                {
                    string[] action = uses.GetString()!.Split('@');
                    Guard.Require(action.Length == 2 && pins.TryGetValue(action[0], out string? pin) && pin == action[1],
                        "workflow-action-pin");
                    if (action[0] == "actions/checkout")
                        Guard.Require(job.Name == "verify" && !step.GetProperty("with").GetProperty("persist-credentials").GetBoolean() &&
                            step.GetProperty("with").GetProperty("ref").GetString() == "${{ github.sha }}", "workflow-checkout");
                    if (action[0] == "NuGet/login")
                    {
                        Manifest.ExactSet(step.GetProperty("with").EnumerateObject().Select(p => p.Name), ["user"], "workflow-login-endpoint");
                        Guard.Require(mutation && step.GetProperty("id").GetString() == "login" &&
                            step.GetProperty("with").GetProperty("user").GetString() == "${{ vars.SECRETKIT_NUGET_USER }}", "workflow-login");
                    }
                    if (action[0] == "actions/download-artifact")
                        Guard.Require(step.GetProperty("with").GetProperty("merge-multiple").GetBoolean() &&
                            !step.GetProperty("with").TryGetProperty("name", out _) &&
                            !step.GetProperty("with").TryGetProperty("pattern", out _), "workflow-artifact-selection");
                }
                if (job.Name != "verify" && step.TryGetProperty("run", out JsonElement run))
                {
                    string script = run.GetString()!;
                    Guard.Require(!script.Contains("dotnet build", StringComparison.Ordinal) &&
                        !script.Contains("dotnet pack", StringComparison.Ordinal) &&
                        !script.Contains("dotnet restore", StringComparison.Ordinal) &&
                        !script.Contains("--skip-duplicate", StringComparison.Ordinal) &&
                        !script.Contains("GITHUB_ENV", StringComparison.Ordinal), "workflow-rebuild-or-renewal");
                    Guard.Require(mutation || !script.Contains(" dispatch ", StringComparison.Ordinal) &&
                        !script.Contains(" prepare ", StringComparison.Ordinal) && !script.Contains("NUGET_API_KEY", StringComparison.Ordinal),
                        "workflow-observation-mutation");
                }
                if (!mutation)
                    Guard.Require(!step.GetRawText().Contains("NUGET_API_KEY", StringComparison.Ordinal), "workflow-key-boundary");
                else if (!step.TryGetProperty("id", out JsonElement keyStep) || keyStep.GetString() != "dispatch")
                    Guard.Require(!step.GetRawText().Contains("NUGET_API_KEY", StringComparison.Ordinal), "workflow-key-boundary");
            }
        }

        foreach (string name in new[] { "observe", "publish_one" })
        {
            bool mutation = name == "publish_one";
            JsonElement[] steps = jobs.GetProperty(name).GetProperty("steps").EnumerateArray().ToArray();
            string[] ids = steps.Select(s => s.TryGetProperty("id", out JsonElement id) ? id.GetString()! : "").ToArray();
            string[] common = ["input_gate", "original_admission", "", "runner_download", "runner_integrity", "artifact_download",
                "artifact_metadata", "producer_job", "journal_download", "journal_metadata", "verify_artifacts"];
            Guard.Require(ids.SequenceEqual(mutation
                ? [.. common, "action_authorization", "prepare", "before", "checkpoint_metadata", "login", "dispatch", "after"]
                : [.. common, "initialize", "reconcile", "observed_journal"]), "workflow-transaction-order");
            JsonElement Step(string id) => steps.Single(s => s.TryGetProperty("id", out JsonElement value) && value.GetString() == id);
            string Script(string id) => Step(id).GetProperty("run").GetString()!;
            foreach (string id in common.Where(id => id.Length > 0 && id is not "journal_download" and not "journal_metadata"))
                Guard.Require(!Step(id).TryGetProperty("if", out _), "workflow-required-verification");
            Guard.Require(Step("journal_metadata").GetProperty("if").GetString() == "${{ inputs.mode != 'initial-admission' }}",
                "workflow-journal-metadata-gate");
            Guard.Require(Script("input_gate").Contains("if [[ \"$MODE\" == initial-admission ]]; then", StringComparison.Ordinal) &&
                Script("input_gate").Contains("\"$SECRETKIT_APPROVED_JOURNAL_HEAD\" =~ ^[0-9a-f]{64}$", StringComparison.Ordinal) &&
                Step("input_gate").GetProperty("env").GetProperty("MODE").GetString() == "${{ inputs.mode }}", "workflow-existing-approved-head");
            Guard.Require(Script("original_admission").Contains("sha256sum --check --status", StringComparison.Ordinal) &&
                Step("original_admission").GetProperty("env").GetProperty("ORIGINAL_ADMISSION").GetString() ==
                    "${{ secrets.SECRETKIT_ORIGINAL_ADMISSION }}", "workflow-original-approval");
            JsonElement artifact = Step("artifact_download").GetProperty("with");
            Guard.Require(artifact.GetProperty("artifact-ids").GetString() == "${{ inputs.artifact_id }}" &&
                artifact.GetProperty("run-id").GetString() == "${{ inputs.source_run_id }}" &&
                artifact.GetProperty("repository").GetString() == Manifest.RepositoryName, "workflow-artifact-source");
            Guard.Require(Step("runner_download").GetProperty("with").GetProperty("artifact-ids").GetString() ==
                    "${{ needs.verify.outputs.runner_artifact_id }}" &&
                Step("runner_integrity").GetProperty("env").GetProperty("RUNNER_HASH").GetString() ==
                    "${{ needs.verify.outputs.runner_sha256 }}" &&
                Script("runner_integrity").Contains("sha256sum --check --status", StringComparison.Ordinal), "workflow-runner-integrity");
            string collector = Script("artifact_metadata");
            foreach (string required in new[] { "sha256sum --check --status", "/attempts/$attempt", "?ref=$SOURCE_COMMIT",
                "actions/jobs/$job", "actions/artifacts/$artifact/zip", "extract-report report-archives", "done < report-archives/fetch.tsv" })
                Guard.Require(collector.Contains(required, StringComparison.Ordinal), "workflow-independent-evidence");
            foreach (string required in new[] { "/attempts/$attempt/jobs", ".name == \"candidate\"", ".run_attempt == $attempt",
                ".head_sha == $sha", ".conclusion == \"success\"", "if length == 1", "actions/jobs/$job", "producer-job.json" })
                Guard.Require(Script("producer_job").Contains(required, StringComparison.Ordinal), "workflow-producer-completion");
            JsonElement journal = Step("journal_download").GetProperty("with");
            Guard.Require(Step("journal_download").GetProperty("if").GetString() == "${{ inputs.mode != 'initial-admission' }}" &&
                journal.GetProperty("artifact-ids").GetString() == "${{ inputs.journal_artifact_id }}" &&
                journal.GetProperty("run-id").GetString() == "${{ inputs.journal_run_id }}" &&
                journal.GetProperty("repository").GetString() == Manifest.RepositoryName &&
                Script("journal_metadata").Contains(".digest == $digest and .workflow_run.id == $run and .workflow_run.head_sha == $sha", StringComparison.Ordinal) &&
                Script("journal_metadata").Contains("sha256sum --check --status", StringComparison.Ordinal), "workflow-original-journal");
            if (!mutation)
            {
                Guard.Require(Script("verify_artifacts").Contains("dotnet runner/SecretKit.Release.dll verify bundle journal", StringComparison.Ordinal) &&
                    Script("verify_artifacts").Contains("dotnet runner/SecretKit.Release.dll verify bundle\n", StringComparison.Ordinal) &&
                    Script("initialize") == "dotnet runner/SecretKit.Release.dll initialize bundle journal" &&
                    Step("initialize").GetProperty("if").GetString() == "${{ inputs.mode == 'initial-admission' }}" &&
                    Script("reconcile") == "dotnet runner/SecretKit.Release.dll reconcile bundle journal" &&
                    Step("reconcile").GetProperty("if").GetString() == "${{ inputs.mode == 'read-only-recovery' }}", "workflow-observation-purpose");
            }
            else
            {
                const string ready = "${{ steps.prepare.outputs.ready == 'true' }}";
                Guard.Require(Script("verify_artifacts") == "dotnet runner/SecretKit.Release.dll verify bundle journal" &&
                    Script("prepare") == "dotnet runner/SecretKit.Release.dll prepare bundle journal \"$PACKAGE_ID\"" &&
                    Script("dispatch") == "dotnet runner/SecretKit.Release.dll dispatch bundle journal \"$PACKAGE_ID\" --execute" &&
                    Step("prepare").GetProperty("env").GetProperty("PACKAGE_ID").GetString() == "${{ inputs.package_id }}" &&
                    Step("dispatch").GetProperty("env").GetProperty("PACKAGE_ID").GetString() == "${{ inputs.package_id }}",
                    "workflow-single-package");
                foreach (string id in new[] { "before", "checkpoint_metadata", "login", "dispatch" })
                    Guard.Require(Step(id).GetProperty("if").GetString() == ready, "workflow-uninterrupted-transaction");
                Guard.Require(Script("action_authorization").Contains("sha256sum --check --status", StringComparison.Ordinal) &&
                    Step("action_authorization").GetProperty("env").GetProperty("ACTION_AUTHORIZATION").GetString() ==
                        "${{ secrets.SECRETKIT_ACTION_AUTHORIZATION }}", "workflow-action-approval");
                foreach (string required in new[] { "actions/artifacts/$CHECKPOINT_ID", ".workflow_run.id == $run", ".workflow_run.head_sha == $sha",
                    ".digest == $digest", ".name == $name", "publication-checkpoint-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-before",
                    "authorization/checkpoint.zip", "sha256sum --check --status" })
                    Guard.Require(Script("checkpoint_metadata").Contains(required, StringComparison.Ordinal), "workflow-checkpoint-proof");
                JsonElement dispatch = Step("dispatch").GetProperty("env");
                Manifest.ExactSet(dispatch.EnumerateObject().Select(p => p.Name), ["PACKAGE_ID", "NUGET_API_KEY",
                    "SECRETKIT_CHECKPOINT_ARTIFACT_ID", "SECRETKIT_CHECKPOINT_ARTIFACT_DIGEST", "SECRETKIT_CHECKPOINT_HEAD",
                    "SECRETKIT_CHECKPOINT_METADATA_FILE"], "workflow-dispatch-environment");
                Guard.Require(dispatch.GetProperty("NUGET_API_KEY").GetString() == "${{ steps.login.outputs.NUGET_API_KEY }}" &&
                    dispatch.GetProperty("SECRETKIT_CHECKPOINT_ARTIFACT_ID").GetString() == "${{ steps.before.outputs.artifact-id }}" &&
                    dispatch.GetProperty("SECRETKIT_CHECKPOINT_ARTIFACT_DIGEST").GetString() == "${{ steps.before.outputs.artifact-digest }}" &&
                    dispatch.GetProperty("SECRETKIT_CHECKPOINT_HEAD").GetString() == "${{ steps.prepare.outputs.head }}" &&
                    dispatch.GetProperty("SECRETKIT_CHECKPOINT_METADATA_FILE").GetString() == "authorization/checkpoint-artifact.json",
                    "workflow-dispatch-checkpoint");
            }
            foreach (string id in mutation ? new[] { "before", "after" } : ["observed_journal"])
            {
                JsonElement upload = Step(id);
                JsonElement options = upload.GetProperty("with");
                Guard.Require(upload.GetProperty("uses").GetString() == "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" &&
                    options.GetProperty("path").GetString() == "journal/" && options.GetProperty("if-no-files-found").GetString() == "error" &&
                    options.GetProperty("retention-days").GetInt32() == 120 && options.GetProperty("name").GetString() ==
                    (id == "before" ? "publication-checkpoint-" : "journal-") +
                    "${{ github.run_id }}-${{ github.run_attempt }}-" + (id == "observed_journal" ? "observed" : id),
                    "workflow-immutable-checkpoint");
            }
            Guard.Require(Step(mutation ? "after" : "observed_journal").GetProperty("if").GetString() == (mutation
                ? "${{ always() && steps.dispatch.outcome != 'skipped' && steps.prepare.outputs.ready == 'true' }}"
                : "${{ always() && (steps.initialize.outcome == 'success' || steps.reconcile.outcome == 'success' || steps.reconcile.outcome == 'failure') }}"),
                "workflow-result-retention");
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
