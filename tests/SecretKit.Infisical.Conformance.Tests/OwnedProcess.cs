using System.Diagnostics;
using System.Text;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class OwnedProcess
{
    internal static async Task<(int ExitCode, string Output)> RunAsync(string executable,
        IReadOnlyList<string> arguments, string workingDirectory,
        IReadOnlyDictionary<string, string>? injection = null, CancellationToken cancellationToken = default)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            {
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            },
            EnableRaisingEvents = true
        };
        process.StartInfo.Environment.Clear();
        foreach (string name in new[] { "PATH", "HOME", "XDG_RUNTIME_DIR", "DOTNET_ROOT" })
            if (Environment.GetEnvironmentVariable(name) is { } value)
                process.StartInfo.Environment[name] = value;
        process.StartInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        if (injection is not null)
            foreach (var (name, value) in injection) process.StartInfo.Environment[name] = value;
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        process.Exited += (_, _) => exited.TrySetResult();
        process.Start();
        Task<string> output = CaptureAsync(process.StandardOutput, true, cancellationToken);
        Task<string> error = CaptureAsync(process.StandardError, false, cancellationToken);
        try
        {
            await exited.Task.WaitAsync(TimeSpan.FromMinutes(2), cancellationToken);
            string captured = await output;
            _ = await error; // Child diagnostics may contain protected values; never publish them.
            return (process.ExitCode, captured);
        }
        catch
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None);
            }
            throw;
        }
    }

    private static async Task<string> CaptureAsync(StreamReader reader, bool retain, CancellationToken cancellationToken)
    {
        char[] buffer = new char[4096];
        var result = new StringBuilder();
        int count;
        bool overflow = false;
        try
        {
            while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) != 0)
            {
                if (!retain) continue;
                if (result.Length + count > 65536) overflow = true;
                else if (!overflow) result.Append(buffer, 0, count);
            }
            if (overflow) throw new InvalidOperationException("Owned process output exceeded its evidence budget.");
            return result.ToString();
        }
        finally { Array.Clear(buffer); }
    }
}
