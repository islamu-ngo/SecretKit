using SecretKit.Core;

namespace SecretKit.LiveProvisioner;

internal static class Program
{
    private const string Usage = """
        SecretKit.LiveProvisioner [--mode local|remote] status|provision|reset|clean [--project <slug>|--project-id <id>] [--apply]
        SecretKit.LiveProvisioner [--mode local|remote] run <scenario> [--candidate <path>] [--request <path>] [--settings-template <path>]
        SecretKit.LiveProvisioner bootstrap-local --origin <loopback-origin> --owner <sandbox-owner> --email <email> --organization <name>
          bootstrap-local reads the initial password from stdin and refuses to overwrite .env.
          clean previews by default; --apply requires an explicit --project-id.
        """;

    private static async Task<int> Main(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            return await ExecuteAsync(args, cancellation.Token);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            await Console.Error.WriteLineAsync("Provisioner canceled; dispatched changes may already have applied.");
            return 130;
        }
        catch (ProvisioningException exception)
        {
            await Console.Error.WriteLineAsync(exception.Message);
            return 1;
        }
        catch (Exception)
        {
            // Provider, operating system, and parsing messages may carry coordinates or credentials.
            await Console.Error.WriteLineAsync("Provisioner failed; verify local inputs and provider state before retrying.");
            return 1;
        }
        finally
        {
            Console.CancelKeyPress -= cancel;
        }
    }

    private static async Task<int> ExecuteAsync(string[] args, CancellationToken ct)
    {
        if (args is [] or ["--help"])
        {
            await Console.Out.WriteLineAsync(Usage);
            return 0;
        }

        LiveTarget? mode = null;
        if (args is ["--mode", var selected, .. var rest])
        {
            mode = selected switch
            {
                "local" => LiveTarget.Local,
                "remote" => LiveTarget.Remote,
                _ => throw new ProvisioningException("Expected --mode local or remote.")
            };
            args = rest;
        }
        string directory = Directory.GetCurrentDirectory();
        if (args is ["bootstrap-local", .. var bootstrap] && mode is null or LiveTarget.Local)
        {
            var inputs = ReadOptions(bootstrap, "--origin", "--owner", "--email", "--organization");
            string Required(string key) => inputs.GetValueOrDefault(key) ?? throw new ProvisioningException($"Missing bootstrap option {key}.");
            string origin = Required("--origin"), owner = Required("--owner"), email = Required("--email"), org = Required("--organization");
            if (!Console.IsInputRedirected)
                throw new ProvisioningException("Supply the initial bootstrap password via redirected stdin.");
            if (await Console.In.ReadLineAsync(ct) is not { Length: > 0 and <= 1024 } password)
                throw new ProvisioningException("Missing or invalid bootstrap password on stdin.");
            using var material = SecretMaterial.FromText(password);
            await LocalBootstrap.RunAsync(directory, origin, owner, email, org, material, ct);
            await Console.Out.WriteLineAsync("Local bootstrap completed; automation Universal Auth stored in private .env.");
            return 0;
        }
        if (args is ["run", var scenario, .. var launch])
        {
            var options = ReadOptions(launch, "--candidate", "--request", "--settings-template");
            using var config = LiveEnvConfig.Load(directory, mode);
            return await LiveRunner.RunAsync(config, scenario, options.GetValueOrDefault("--candidate"),
                options.GetValueOrDefault("--request"), options.GetValueOrDefault("--settings-template"), ct);
        }
        if (args is ["clean", .. var cleanup])
        {
            bool apply = cleanup.Contains("--apply", StringComparer.Ordinal);
            if (cleanup.Count(option => option == "--apply") > 1)
                throw new ProvisioningException("Duplicate cleanup flag.");
            var options = ReadOptions(cleanup.Where(option => option != "--apply").ToArray(), "--project", "--project-id");
            using var config = LiveEnvConfig.Load(directory, mode);
            int count = await new ResourceCleaner().CleanAsync(config, options.GetValueOrDefault("--project"),
                options.GetValueOrDefault("--project-id"), apply, ct);
            await Console.Out.WriteLineAsync($"cleanup: {(apply ? "deleted" : "dry-run candidates")}={count}");
            return 0;
        }
        if (args is ["status"] or ["provision"] or ["reset"])
        {
            using var config = LiveEnvConfig.Load(directory, mode);
            await ProviderStatus.ReportAsync(config, Console.Out, ct);
            if (args[0] != "status")
            {
                using var fixtures = await new FixtureReconciler().ReconcileAsync(config, ct, issueCredentials: false);
                await Console.Out.WriteLineAsync("Fixture reconciliation applied.");
            }
            return 0;
        }
        throw new ProvisioningException("Unknown command or invalid arguments; see --help.");
    }

    private static Dictionary<string, string> ReadOptions(string[] args, params string[] allowed)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i < args.Length; i += 2)
        {
            if (i + 1 >= args.Length || !allowed.Contains(args[i], StringComparer.Ordinal) ||
                args[i + 1].Length == 0 || args[i + 1].StartsWith("--", StringComparison.Ordinal) ||
                !options.TryAdd(args[i], args[i + 1]))
                throw new ProvisioningException("Unknown, incomplete, or duplicate command option; see --help.");
        }
        return options;
    }
}
