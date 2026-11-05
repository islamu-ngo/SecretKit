using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace SecretKit.Release;

public sealed record DependencyAuditFinding(string Project, string Framework, string Package,
    string Version, string Advisory, string Severity, bool Transitive);

public sealed record DependencyAuditDecision(bool Cleared, string[] Failures,
    DependencyAuditFinding[] Findings, int MatchedExceptions);

public sealed record DependencyAuditRisk(string Project, string Framework, string Package, string Version,
    string Advisory, string Owner, string Rationale, string Evidence, string ExpiresAt);
public sealed record DependencyAuditRegistry(int SchemaVersion, DependencyAuditRisk[] Exceptions);
public sealed record InstalledAuditGraph(string Project, string Assets, string Packages,
    string Version, string? Mode, FileDigest[] Files);
internal sealed record InstalledAuditInventory(int SchemaVersion, string Kind, string CohortSha256,
    string Platform, FileDigest[] Graphs, FileDigest[] Installations);

public static class DependencyAudit
{
    // Only real restore metadata is recorded. Synthetic package-verifier
    // fixtures exercise a smaller contract and are not native graph evidence.
    public static void RecordInstalledGraph(string assetsPath, JsonElement assets)
    {
        string? directory = Environment.GetEnvironmentVariable("SECRETKIT_DEPENDENCY_AUDIT_GRAPHS");
        if (directory is null || !assets.TryGetProperty("project", out var project) ||
            !project.TryGetProperty("restore", out _)) return;
        Guard.Require(Path.IsPathFullyQualified(directory), "audit-graph-directory");
        CheckOutputPath(directory);
        Directory.CreateDirectory(directory);
        InstalledAuditGraph graph = InstalledGraph(assetsPath,
            Manifest.Parse<JsonElement>(Manifest.ReadLocalFile(assetsPath, MaximumBytes), MaximumBytes));
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(graph, Manifest.JsonOptions);
        string name = Manifest.Hash(Encoding.UTF8.GetBytes(graph.Assets)) + ".json";
        string installations = Path.Combine(Path.GetDirectoryName(directory)!, "installations");
        CheckOutputPath(installations);
        Directory.CreateDirectory(installations);
        byte[] receipt = JsonSerializer.SerializeToUtf8Bytes(new FileDigest(name, Manifest.Hash(bytes)), Manifest.JsonOptions);
        foreach ((string destination, byte[] content) in new[]
            { (Path.Combine(directory, name), bytes), (Path.Combine(installations, name), receipt) })
        {
            if (File.Exists(destination))
            {
                Guard.Require(Manifest.ReadLocalFile(destination, 131072).AsSpan().SequenceEqual(content),
                    "audit-graph-replaced");
                continue;
            }
            using var stream = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(content);
            stream.Flush(flushToDisk: true);
        }
    }

    internal static void SealInstalledGraphs(string observations, string cohortSha256, string platform)
    {
        Guard.Require(Manifest.IsHash(cohortSha256) && platform is "linux-x64" or "windows-x64",
            "audit-inventory-binding");
        var files = ReadInstalledInventory(observations);
        foreach (FileDigest file in files.Graphs)
        {
            var graph = Manifest.Parse<InstalledAuditGraph>(
                Manifest.ReadFile(Path.Combine(observations, "graphs"), file.File, 131072), 131072);
            Guard.Require(graph.Files is { Length: > 0 } &&
                graph.Files.Any(selected => selected.File == graph.Assets) &&
                graph.Files.All(selected => Manifest.IsHash(selected.Sha256) &&
                    Manifest.Hash(Manifest.ReadLocalFile(selected.File, MaximumBytes)) == selected.Sha256),
                "audit-installed-selection");
        }
        var inventory = new InstalledAuditInventory(1, "installed-graph-inventory", cohortSha256,
            platform, files.Graphs, files.Installations);
        using var stream = new FileStream(Path.Combine(observations, "installed-graphs.json"),
            FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(JsonSerializer.SerializeToUtf8Bytes(inventory, Manifest.JsonOptions));
        stream.Flush(flushToDisk: true);
    }

    internal static string[] ValidateInstalledInventory(string observations, string cohortSha256, string platform)
    {
        var inventory = Manifest.Parse<InstalledAuditInventory>(
            Manifest.ReadFile(observations, "installed-graphs.json", MaximumBytes), MaximumBytes);
        Guard.Require(inventory.SchemaVersion == 1 && inventory.Kind == "installed-graph-inventory" &&
            inventory.CohortSha256 == cohortSha256 && inventory.Platform == platform, "audit-inventory-binding");
        var files = ReadInstalledInventory(observations);
        Guard.Require(inventory.Graphs.SequenceEqual(files.Graphs) &&
            inventory.Installations.SequenceEqual(files.Installations), "audit-inventory-changed");
        return files.Graphs.Select(file => Path.Combine(observations, "graphs", file.File)).ToArray();
    }

    private static (FileDigest[] Graphs, FileDigest[] Installations) ReadInstalledInventory(string observations)
    {
        string graphs = Path.Combine(observations, "graphs");
        string installations = Path.Combine(observations, "installations");
        FileDigest[] graphFiles = Read(graphs), receipts = Read(installations);
        Manifest.ExactSet(graphFiles.Select(file => file.File), receipts.Select(file => file.File),
            "audit-graph-coverage");
        foreach (FileDigest receipt in receipts)
        {
            var reference = Manifest.Parse<FileDigest>(Manifest.ReadFile(installations, receipt.File, 131072), 131072);
            Guard.Require(reference == graphFiles.Single(file => file.File == receipt.File), "audit-graph-receipt");
        }
        return (graphFiles, receipts);

        static FileDigest[] Read(string directory)
        {
            CheckOutputPath(directory);
            string[] paths = Directory.GetFiles(directory, "*.json").Order(StringComparer.Ordinal).ToArray();
            Guard.Require(paths.Length > 0 &&
                Directory.EnumerateFileSystemEntries(directory).Count() == paths.Length, "audit-graph-coverage");
            return paths.Select(path => new FileDigest(Path.GetFileName(path),
                Manifest.Hash(Manifest.ReadLocalFile(path, 131072)))).ToArray();
        }
    }

    public static Task<int> RunInstalledAsync(string source, string assetsPath, string output)
    {
        assetsPath = Path.GetFullPath(assetsPath);
        InstalledAuditGraph graph = InstalledGraph(assetsPath,
            Manifest.Parse<JsonElement>(Manifest.ReadLocalFile(assetsPath, MaximumBytes), MaximumBytes));
        return RunAsync(source, graph.Project, output, graph.Version, graph);
    }

    private static InstalledAuditGraph InstalledGraph(string assetsPath, JsonElement assets)
    {
        assetsPath = Path.GetFullPath(assetsPath);
        JsonElement restore = assets.GetProperty("project").GetProperty("restore");
        string project = Path.GetFullPath(Text(restore, "projectPath"));
        string packages = Path.GetFullPath(Text(restore, "packagesPath"));
        Guard.Require(project.EndsWith(".csproj", StringComparison.Ordinal) &&
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(Text(restore, "outputPath"))) ==
                Path.GetDirectoryName(assetsPath), "audit-installed-paths");
        Guard.Require(restore.GetProperty("frameworks").EnumerateObject().All(framework =>
            !framework.Value.TryGetProperty("projectReferences", out var references) ||
                !references.EnumerateObject().Any()), "audit-installed-project-references");
        string[] product = assets.GetProperty("libraries").EnumerateObject()
            .Where(library => library.Name.StartsWith("SecretKit.", StringComparison.Ordinal))
            .Select(library => library.Name).ToArray();
        Guard.Require(product.Length > 0 && product.All(library =>
            library.Contains('/') && Manifest.PackageIds.Contains(library[..library.IndexOf('/')], StringComparer.Ordinal)),
            "audit-installed-products");
        string[] versions = product.Select(library => library[(library.IndexOf('/') + 1)..])
            .Distinct(StringComparer.Ordinal).ToArray();
        Guard.Require(versions.Length == 1 && ValidText(versions[0]) &&
            versions[0].All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-'),
            "audit-installed-version");
        string? mode = null;
        if (Path.GetFileName(project) == "SecretKit.InfisicalConsumer.csproj")
        {
            bool configuration = product.Any(library => library.StartsWith("SecretKit.Extensions.Configuration/", StringComparison.Ordinal));
            bool hosting = product.Any(library => library.StartsWith("SecretKit.Extensions.Hosting/", StringComparison.Ordinal));
            mode = (configuration, hosting) switch
            {
                (true, true) => "full",
                (true, false) => "configuration",
                (false, true) => "hosting",
                _ => "minimal"
            };
        }
        var files = new List<string> { project, assetsPath };
        if (restore.TryGetProperty("restoreLockProperties", out var properties) &&
            properties.TryGetProperty("restorePackagesWithLockFile", out var locked) &&
            locked.GetString() == "true")
        {
            files.Add(properties.TryGetProperty("nuGetLockFilePath", out var lockPath)
                ? Path.GetFullPath(lockPath.GetString()!)
                : Path.Combine(Path.GetDirectoryName(project)!, "packages.lock.json"));
        }
        return new(project, assetsPath, packages, versions[0], mode,
            files.Order(StringComparer.Ordinal).Select(file =>
                new FileDigest(file, Manifest.Hash(Manifest.ReadLocalFile(file, MaximumBytes)))).ToArray());
    }

    private static void CheckOutputPath(string path)
    {
        for (DirectoryInfo? part = new(Path.GetFullPath(path)); part is not null; part = part.Parent)
            Guard.Require(part.LinkTarget is null && (!part.Exists ||
                (part.Attributes & FileAttributes.ReparsePoint) == 0), "audit-directory-link");
    }

    private const int MaximumBytes = 4 * 1024 * 1024;
    private const string RegistryPath = "docs/internal/dependency-advisory-exceptions.json";
    private const string NuGetSource = "https://api.nuget.org/v3/index.json";

    public static DependencyAuditDecision Evaluate(byte[] report, byte[] graph, byte[] registry,
        string[] projects, string[] auditSources, int restoreExit, int graphExit, int reportExit,
        DateTimeOffset observedAt, string? projectRoot = null)
    {
        var failures = new List<string>();
        var findings = new List<DependencyAuditFinding>();
        int matched = 0;
        if (restoreExit != 0 || graphExit != 0 || reportExit != 0) failures.Add("audit-native-failure");
        string root = Path.GetFullPath(projectRoot ?? Directory.GetCurrentDirectory());
        try
        {
            string Project(string path) => Path.GetFullPath(path, root);
            var expected = projects.Select(Project).ToHashSet(StringComparer.Ordinal);
            Guard.Require(expected.Count == projects.Length && expected.Count > 0, "audit-projects");
            Guard.Require(auditSources.Length > 0 && auditSources.Distinct(StringComparer.Ordinal).Count() == auditSources.Length,
                "audit-sources");
            JsonElement resolved = Header(graph, false);
            var packages = new Dictionary<(string Project, string Framework, string Package, bool Transitive), string>();
            var frameworks = new HashSet<(string Project, string Framework)>();
            ReadProjects(resolved, project =>
            {
                string path = Project(Text(project, "path"));
                Guard.Require(project.TryGetProperty("frameworks", out var list) &&
                    list.ValueKind == JsonValueKind.Array && list.GetArrayLength() > 0, "audit-graph-frameworks");
                foreach (JsonElement framework in list.EnumerateArray())
                {
                    Closed(framework, "framework", "topLevelPackages", "transitivePackages");
                    string name = Text(framework, "framework");
                    Guard.Require(frameworks.Add((path, name)), "audit-graph-duplicate");
                    ReadPackages(framework, (package, transitive) =>
                    {
                        Closed(package, "id", "requestedVersion", "resolvedVersion", "autoReferenced");
                        Guard.Require(packages.TryAdd((path, name, Text(package, "id").ToUpperInvariant(), transitive),
                            Text(package, "resolvedVersion")), "audit-graph-duplicate");
                    });
                }
            });

            JsonElement vulnerable = Header(report, true);
            Guard.Require(vulnerable.TryGetProperty("sources", out var sources) && sources.ValueKind == JsonValueKind.Array,
                "audit-sources");
            Manifest.ExactSet(sources.EnumerateArray().Select(s => s.GetString()!), auditSources, "audit-sources");
            var seenFindings = new HashSet<(string Project, string Framework, string Package, string Advisory)>();
            ReadProjects(vulnerable, project =>
            {
                string path = Project(Text(project, "path"));
                Guard.Require(project.TryGetProperty("frameworks", out var list) &&
                    list.ValueKind == JsonValueKind.Array && list.GetArrayLength() > 0, "audit-report-frameworks");
                var seenFrameworks = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonElement framework in list.EnumerateArray())
                {
                    Closed(framework, "framework", "topLevelPackages", "transitivePackages");
                    string name = Text(framework, "framework");
                    Guard.Require(frameworks.Contains((path, name)) && seenFrameworks.Add(name), "audit-report-framework");
                    int count = 0;
                    ReadPackages(framework, (package, transitive) =>
                    {
                        Closed(package, "id", "requestedVersion", "resolvedVersion", "autoReferenced", "vulnerabilities");
                        string id = Text(package, "id"), version = Text(package, "resolvedVersion");
                        Guard.Require(packages.TryGetValue((path, name, id.ToUpperInvariant(), transitive), out string? selected) &&
                            selected == version, "audit-report-package");
                        Guard.Require(package.TryGetProperty("vulnerabilities", out var advisories) &&
                            advisories.ValueKind == JsonValueKind.Array && advisories.GetArrayLength() > 0, "audit-report-advisories");
                        foreach (JsonElement advisory in advisories.EnumerateArray())
                        {
                            Closed(advisory, "severity", "advisoryurl");
                            string severity = Text(advisory, "severity"), url = Text(advisory, "advisoryurl");
                            Guard.Require(severity is "Low" or "Moderate" or "High" or "Critical", "audit-severity");
                            Guard.Require(Https(url) && seenFindings.Add((path, name, id.ToUpperInvariant(), url)),
                                "audit-report-advisory");
                            findings.Add(new(path, name, id, version, url, severity, transitive));
                        }
                        count++;
                    });
                    // SDK 10 emits an explicit empty top-level array for a
                    // framework with no advisories, including transitive ones.
                    Guard.Require(count > 0 || framework.TryGetProperty("topLevelPackages", out var empty) &&
                        empty.ValueKind == JsonValueKind.Array && empty.GetArrayLength() == 0,
                        "audit-report-empty-framework");
                }
                Manifest.ExactSet(seenFrameworks, frameworks.Where(item => item.Project == path)
                    .Select(item => item.Framework), "audit-report-frameworks");
            });

            void ReadProjects(JsonElement document, Action<JsonElement> read)
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                Guard.Require(document.TryGetProperty("projects", out var list) && list.ValueKind == JsonValueKind.Array,
                    "audit-projects");
                foreach (JsonElement project in list.EnumerateArray())
                {
                    Closed(project, "path", "frameworks");
                    string path = Project(Text(project, "path"));
                    Guard.Require(expected.Contains(path) && seen.Add(path), "audit-projects");
                    read(project);
                }
                Guard.Require(seen.SetEquals(expected), "audit-projects");
            }
        }
        catch (Exception error) when (error is ReleaseException or InvalidOperationException or KeyNotFoundException or
            ArgumentException or FormatException)
        {
            failures.Add("audit-report");
        }

        try
        {
            DependencyAuditRegistry risks = Manifest.Parse<DependencyAuditRegistry>(registry, MaximumBytes);
            Guard.Require(risks.SchemaVersion == 1 && observedAt.Offset == TimeSpan.Zero, "audit-exception");
            var seen = new HashSet<(string Project, string Framework, string Package, string Version, string Advisory)>();
            foreach (DependencyAuditRisk risk in risks.Exceptions)
            {
                string[] scope = [risk.Project, risk.Framework, risk.Package, risk.Version, risk.Advisory];
                Guard.Require(scope.All(value => ValidText(value) && !value.Contains('*') && !value.Contains('?')) &&
                    ValidText(risk.Owner) && ValidText(risk.Rationale) && ValidText(risk.Evidence) && Https(risk.Advisory) &&
                    risk.ExpiresAt.EndsWith('Z') &&
                    DateTimeOffset.TryParse(risk.ExpiresAt, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expiry) &&
                    expiry.Offset == TimeSpan.Zero && expiry > observedAt, "audit-exception");
                string project = Path.GetFullPath(risk.Project, root);
                Guard.Require(seen.Add((project, risk.Framework, risk.Package.ToUpperInvariant(), risk.Version, risk.Advisory)) &&
                    findings.Any(f => f.Project == project && f.Framework == risk.Framework &&
                        string.Equals(f.Package, risk.Package, StringComparison.OrdinalIgnoreCase) &&
                        f.Version == risk.Version && f.Advisory == risk.Advisory), "audit-exception");
                matched++;
            }
        }
        catch (Exception error) when (error is ReleaseException or ArgumentException or InvalidOperationException or NullReferenceException)
        {
            failures.Add("audit-exception");
        }
        // Risk records do not waive the native gate or turn a vulnerable graph into clearance.
        if (findings.Count > 0) failures.Add("audit-vulnerable");
        return new(failures.Count == 0, failures.Distinct(StringComparer.Ordinal).ToArray(), findings.ToArray(), matched);
    }

    public static async Task<int> RunAsync(string source, string target, string output,
        string? candidateVersion = null, InstalledAuditGraph? installed = null)
    {
        source = Path.GetFullPath(source);
        target = Path.GetFullPath(target, source);
        output = Path.GetFullPath(output, source);
        bool solution = target == Path.Combine(source, "SecretKit.slnx") ||
            target == Path.Combine(source, "SecretKit.Conformance.slnx");
        CheckOutputPath(output);
        Guard.Require(solution || installed is not null && target.EndsWith(".csproj", StringComparison.Ordinal), "audit-target");
        Guard.Require(!Directory.Exists(output) && !File.Exists(output), "audit-output-exists");
        Guard.Require(candidateVersion is null || !solution && ValidText(candidateVersion) &&
            candidateVersion.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-'), "audit-candidate-version");
        string[] projects = solution
            ? XDocument.Load(target).Descendants("Project").Select(p => Path.GetFullPath(p.Attribute("Path")!.Value,
                Path.GetDirectoryName(target)!)).ToArray()
            : [target];
        string[] auditSources = XDocument.Load(Path.Combine(source, "NuGet.Config")).Root!
            .Element("auditSources")?.Elements("add").Select(e => e.Attribute("value")!.Value).ToArray() ?? [];
        Guard.Require(auditSources.SequenceEqual([NuGetSource]), "audit-sources");
        Directory.CreateDirectory(output);
        LocalSourceSnapshot sourceBefore = LocalQualification.CaptureSource(source);
        byte[] registry = Manifest.ReadLocalFile(Path.Combine(source, RegistryPath), MaximumBytes);
        await Write("exceptions.json", registry);
        var steps = new List<NativeStep>();
        NativeStep sdk = await Run("sdk", ["--version"]);
        string selectedSdk = Manifest.Parse<JsonElement>(Manifest.ReadFile(source, "global.json", 65536))
            .GetProperty("sdk").GetProperty("version").GetString()!;
        bool sdkMatches = sdk.ExitCode == 0 && sdk.Output.Trim() == selectedSdk;

        // Source restores are connected audit gates. Installed graphs are already
        // selected by their installation owner: never restore/rewrite that evidence.
        NativeStep? restore = solution ? await Run("restore",
            ["restore", target, "--locked-mode", "--force", "--no-http-cache",
             "-p:NuGetAudit=true", "-p:NuGetAuditMode=all", "-p:NuGetAuditLevel=low",
             "-p:TreatWarningsAsErrors=true", "-p:UseSharedCompilation=false"]) : null;
        FileDigest[] before = CaptureGraphs(projects, installed);
        NativeStep graph = await Run("graph",
            ["package", "list", "--project", target, "--include-transitive", "--format", "json", "--output-version", "1", "--no-restore"]);
        NativeStep report = await Run("vulnerabilities",
            ["package", "list", "--project", target, "--vulnerable", "--include-transitive", "--format", "json",
             "--output-version", "1", "--no-restore", "--source", NuGetSource]);
        DateTimeOffset observedAt = DateTimeOffset.UtcNow;
        DependencyAuditDecision decision = Evaluate(Encoding.UTF8.GetBytes(report.Output), Encoding.UTF8.GetBytes(graph.Output),
            registry, projects, auditSources, restore?.ExitCode ?? 0, graph.ExitCode, report.ExitCode, observedAt, source);
        FileDigest[] after = CaptureGraphs(projects, installed);
        LocalSourceSnapshot sourceAfter = LocalQualification.CaptureSource(source);
        var errors = decision.Failures.ToList();
        if (!sdkMatches) errors.Add("audit-sdk");
        if (!before.SequenceEqual(after)) errors.Add("audit-graph-changed");
        if (sourceBefore.Sha256 != sourceAfter.Sha256) errors.Add("audit-source-changed");
        if (steps.Any(step => step.Error.Length != 0)) errors.Add("audit-native-stderr");
        decision = decision with { Cleared = errors.Count == 0, Failures = errors.Distinct(StringComparer.Ordinal).ToArray() };
        await Write("audit.json", JsonSerializer.SerializeToUtf8Bytes(new
        {
            SchemaVersion = 1,
            Kind = solution ? "source-solution-advisory-observation" : "installed-graph-advisory-observation",
            Target = target,
            Sdk = sdk.Output.Trim(),
            ObservedAt = observedAt,
            Source = sourceBefore,
            SourceAfterSha256 = sourceAfter.Sha256,
            AuditSources = auditSources,
            Graphs = before,
            GraphsAfter = after,
            RegistrySha256 = Manifest.Hash(registry),
            Native = steps.Select(step => new
            {
                step.Name,
                step.ExitCode,
                step.Arguments,
                StdoutSha256 = Manifest.Hash(Encoding.UTF8.GetBytes(step.Output)),
                StderrSha256 = Manifest.Hash(Encoding.UTF8.GetBytes(step.Error))
            }),
            RestorePerformed = restore is not null,
            CandidateVersion = candidateVersion,
            InstalledGraph = installed,
            Decision = decision
        }, Manifest.JsonOptions));
        Console.WriteLine(decision.Cleared ? "dependency-audit-clear-for-recorded-graph" : "dependency-audit-not-cleared");
        foreach (string error in decision.Failures) Console.WriteLine(error);
        return decision.Cleared ? 0 : 1;

        async Task<NativeStep> Run(string name, string[] arguments)
        {
            NativeStep result = await NativeAsync(source, name, arguments, candidateVersion, installed);
            steps.Add(result);
            await Write(name + ".stdout", Encoding.UTF8.GetBytes(result.Output));
            await Write(name + ".stderr", Encoding.UTF8.GetBytes(result.Error));
            return result;
        }
        async Task Write(string name, byte[] bytes)
        {
            using var stream = new FileStream(Path.Combine(output, name), FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await stream.WriteAsync(bytes);
        }
    }

    private sealed record NativeStep(string Name, string[] Arguments, int ExitCode, string Output, string Error);

    private static async Task<NativeStep> NativeAsync(string source, string name, string[] arguments,
        string? candidateVersion, InstalledAuditGraph? installed)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = source,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        foreach (string key in start.Environment.Keys.Where(key =>
            key.StartsWith("SECRETKIT_", StringComparison.Ordinal) ||
            key.StartsWith("NuGetPackageSourceCredentials_", StringComparison.OrdinalIgnoreCase) ||
            key is "NUGET_API_KEY" or "NUGET_AUTH_TOKEN").ToArray())
            start.Environment.Remove(key);
        start.Environment["MSBUILDTERMINALLOGGER"] = "off";
        start.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        if (installed is not null)
        {
            string intermediate = Path.GetDirectoryName(installed.Assets)! + Path.DirectorySeparatorChar;
            start.Environment["MSBuildProjectExtensionsPath"] = intermediate;
            start.Environment["BaseIntermediateOutputPath"] = intermediate;
            start.Environment["NUGET_PACKAGES"] = installed.Packages;
            start.Environment["RestorePackagesPath"] = installed.Packages;
            if (installed.Mode is not null) start.Environment["LocalConsumerMode"] = installed.Mode;
        }
        if (candidateVersion is not null) start.Environment["SecretKitCandidateVersion"] = candidateVersion;
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        using Process process = Process.Start(start) ?? throw new ReleaseException("audit-native-launch");
        Task<string> stdout = Read(process.StandardOutput), stderr = Read(process.StandardError);
        try
        {
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token));
            return new(name, arguments, process.ExitCode, await stdout, await stderr);
        }
        catch (Exception error) when (error is OperationCanceledException or ReleaseException)
        {
            return new(name, arguments, -1, "", "audit-native-incomplete");
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        async Task<string> Read(StreamReader reader)
        {
            var text = new StringBuilder();
            char[] buffer = new char[4096];
            int length;
            while ((length = await reader.ReadAsync(buffer, deadline.Token)) > 0)
            {
                if (text.Length > MaximumBytes - length)
                {
                    deadline.Cancel();
                    throw new ReleaseException("audit-native-size");
                }
                text.Append(buffer, 0, length);
            }
            return text.ToString();
        }
    }

    private static FileDigest[] CaptureGraphs(string[] projects, InstalledAuditGraph? installed = null)
    {
        if (installed is not null)
            return installed.Files.Select(file =>
                new FileDigest(file.File, Manifest.Hash(Manifest.ReadLocalFile(file.File, MaximumBytes)))).ToArray();
        var files = new List<FileDigest>();
        foreach (string project in projects)
        {
            string directory = Path.GetDirectoryName(project)!;
            foreach (string file in new[] { project, Path.Combine(directory, "obj", "project.assets.json"),
                Path.Combine(directory, "packages.lock.json") })
            {
                Guard.Require(File.Exists(file) && (File.GetAttributes(file) & FileAttributes.ReparsePoint) == 0, "audit-graph-input");
                files.Add(new(file, Manifest.Hash(File.ReadAllBytes(file))));
            }
        }
        return files.OrderBy(file => file.File, StringComparer.Ordinal).ToArray();
    }

    private static JsonElement Header(byte[] bytes, bool vulnerable)
    {
        JsonElement value = Manifest.Parse<JsonElement>(bytes, MaximumBytes);
        Closed(value, "version", "parameters", "sources", "projects", "logs");
        Guard.Require(value.GetProperty("version").GetInt32() == 1, "audit-report-version");
        string[] parameters = Text(value, "parameters").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var required = new HashSet<string>(StringComparer.Ordinal) { "--include-transitive" };
        if (vulnerable) required.Add("--vulnerable");
        for (int i = 0; i < parameters.Length; i++)
        {
            if (parameters[i] == "--source" && vulnerable)
            {
                Guard.Require(++i < parameters.Length && parameters[i] == NuGetSource, "audit-report-parameters");
                continue;
            }
            Guard.Require(required.Remove(parameters[i]), "audit-report-parameters");
        }
        Guard.Require(required.Count == 0, "audit-report-parameters");
        if (value.TryGetProperty("logs", out var logs))
            Guard.Require(logs.ValueKind == JsonValueKind.Array && logs.GetArrayLength() == 0, "audit-unavailable");
        return value;
    }

    private static void ReadPackages(JsonElement framework, Action<JsonElement, bool> read)
    {
        foreach ((string field, bool transitive) in new[] { ("topLevelPackages", false), ("transitivePackages", true) })
            if (framework.TryGetProperty(field, out var packages))
            {
                Guard.Require(packages.ValueKind == JsonValueKind.Array, "audit-packages");
                foreach (JsonElement package in packages.EnumerateArray()) read(package, transitive);
            }
    }

    private static void Closed(JsonElement value, params string[] fields) =>
        Guard.Require(value.ValueKind == JsonValueKind.Object &&
            value.EnumerateObject().All(property => fields.Contains(property.Name, StringComparer.Ordinal)), "audit-report-shape");
    private static string Text(JsonElement value, string name)
    {
        Guard.Require(value.TryGetProperty(name, out var field) && field.ValueKind == JsonValueKind.String &&
            ValidText(field.GetString()!), "audit-report-field");
        return field.GetString()!;
    }
    private static bool ValidText(string value) => !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 4096 && !value.Any(char.IsControl);
    private static bool Https(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0;
}
