using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace SecretKit.LiveProvisioner;

internal sealed record LiveCommand(ProcessStartInfo Start, IReadOnlyDictionary<string, string> Environment,
    Action<Utf8JsonWriter>? Settings = null, bool RequireInstalledMarkers = false)
{
    public override string ToString() => "[LiveCommand]";
}

internal static class LiveProcess
{
    private const string NativePassed = "INSTALLED_NATIVE_READ_WRITE_INVENTORY_AND_IDENTITIES_PASSED";
    private const string BootstrapPassed = "INSTALLED_BOOTSTRAP_CONFIGURATION_AND_ASSESSMENT_PASSED";
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal static string ArtifactDirectory(string root)
    {
        string artifacts = Path.Combine(root, "artifacts");
        string live = Path.Combine(artifacts, "live");
        NativeLiveInputs.RequireUnlinked(root);
        Directory.CreateDirectory(artifacts);
        NativeLiveInputs.RequireUnlinked(artifacts);
        Directory.CreateDirectory(live);
        NativeLiveInputs.RequireUnlinked(live);
        return live;
    }

    internal static string PrivateDirectory(string parent, string prefix)
    {
        string path = Path.Combine(parent, prefix + Guid.NewGuid().ToString("N"));
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        Directory.CreateDirectory(path, PrivateFile | UnixFileMode.UserExecute);
        return path;
    }

    internal static FileStream OpenPrivate(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = PrivateFile
        });
    }

    internal static ProcessStartInfo Command(string root, string executable, string[] arguments)
    {
        var start = new ProcessStartInfo(executable) { WorkingDirectory = root };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        return start;
    }

    internal static async Task<int> RunAsync(string root, LiveCommand command, CancellationToken token,
        Func<ProcessStartInfo, Action<string>, CancellationToken, Task<int>>? execute = null)
    {
        string output = ArtifactDirectory(root);
        string run = Guid.NewGuid().ToString("N");
        string? settings = null;
        string logPath = Path.Combine(output, run + ".log");
        using var log = new StreamWriter(OpenPrivate(logPath));
        var markers = new HashSet<string>(StringComparer.Ordinal);
        void Record(string marker)
        {
            // Never persist arbitrary child lines or exception messages, even when only partial material is printed.
            if (marker is not (NativePassed or BootstrapPassed or
                "LIVE_INFISICAL_PROJECT_WRITE_FRESH_READ_PASSED" or "LIVE_INFISICAL_RUNTIME_IDENTITY_SEPARATION_UNVERIFIED"))
                return;
            lock (markers)
                if (markers.Add(marker)) log.WriteLine(marker);
        }

        try
        {
            token.ThrowIfCancellationRequested();
            var start = command.Start;
            start.Environment.Clear();
            foreach (string key in new[] { "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR",
                "TEMP", "TMP", "TMPDIR", "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_CLI_HOME",
                "XDG_RUNTIME_DIR" })
                if (Environment.GetEnvironmentVariable(key) is string value)
                    start.Environment[key] = value;
            start.Environment["MSBUILDTERMINALLOGGER"] = "off";
            start.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
            foreach (var selection in command.Environment)
                start.Environment[selection.Key] = selection.Value;

            if (command.Settings is not null)
            {
                string path = Path.Combine(output, run + ".settings.json");
                using FileStream stream = OpenPrivate(path);
                settings = path;
                using (var writer = new Utf8JsonWriter(stream))
                    command.Settings(writer);
                start.Environment["SECRETKIT_NATIVE_SETTINGS"] = path;
            }

            int exit = await (execute ?? StartAsync)(start, Record, token);
            if (command.RequireInstalledMarkers && exit == 0 &&
                (!markers.Contains(NativePassed) || !markers.Contains(BootstrapPassed)))
                exit = 1;
            log.WriteLine($"Child exit code: {exit}");
            if (exit == 0)
                foreach (string marker in markers) Console.WriteLine(marker);
            return exit;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            log.WriteLine("Child canceled.");
            throw new OperationCanceledException(token);
        }
        catch (Exception)
        {
            log.WriteLine("Child execution failed; protected diagnostics withheld.");
            throw new ProvisioningException("Live child execution failed; protected diagnostics withheld.");
        }
        finally
        {
            if (settings is not null)
            {
                command.Start.Environment.Remove("SECRETKIT_NATIVE_SETTINGS");
                File.Delete(settings);
            }
            foreach (string key in command.Environment.Keys)
                command.Start.Environment.Remove(key);
            Console.WriteLine($"Live evidence: artifacts/live/{run}.log");
        }
    }

    internal static async Task<int> StartAsync(ProcessStartInfo start, Action<string> evidence, CancellationToken token)
    {
        start.UseShellExecute = false;
        start.RedirectStandardInput = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        token.ThrowIfCancellationRequested();
        using Process process = Process.Start(start) ?? throw new InvalidOperationException();
        process.StandardInput.Close();
        Task stdout = CaptureAsync(process.StandardOutput, evidence, token);
        Task stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, token);
        try
        {
            await process.WaitForExitAsync(token);
            await Task.WhenAll(stdout, stderr);
            return process.ExitCode;
        }
        finally
        {
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); }
                catch (InvalidOperationException) when (process.HasExited) { }
                await process.WaitForExitAsync(CancellationToken.None);
            }
            try { await Task.WhenAll(stdout, stderr); }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        }
    }

    private static async Task CaptureAsync(StreamReader reader, Action<string> evidence, CancellationToken token)
    {
        char[] buffer = new char[1024];
        var line = new StringBuilder(128);
        bool overflow = false;
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) != 0)
        {
            for (int i = 0; i < count; i++)
            {
                char value = buffer[i];
                if (value == '\n')
                {
                    if (!overflow) evidence(line.ToString().TrimEnd('\r'));
                    overflow = false;
                    line.Clear();
                }
                else if (line.Length < 128) line.Append(value);
                else overflow = true;
            }
        }
        if (!overflow && line.Length > 0) evidence(line.ToString().TrimEnd('\r'));
    }
}
