using System.Diagnostics;
using System.Globalization;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class ProcessLifetimeTests
{
    [Test]
    public async Task CancellationDrainsTheActualChildWithBlockedInput()
    {
        DirectoryInfo directory = Directory.CreateTempSubdirectory("secretkit-process-drain-");
        string readyPath = Path.Combine(directory.FullName, "ready");
        using var cancellation = new CancellationTokenSource();
        using var watcher = new FileSystemWatcher(directory.FullName, "ready");
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        watcher.Created += (_, _) => ready.TrySetResult();
        watcher.Renamed += (_, _) => ready.TrySetResult();
        watcher.EnableRaisingEvents = true;
        var pending = OwnedProcess.RunAsync("/bin/sh",
            ["-c", "mkfifo \"$SECRETKIT_TEST_PIPE\" && printf '%s' \"$$\" > \"$SECRETKIT_TEST_READY_TEMP\" && " +
                "mv \"$SECRETKIT_TEST_READY_TEMP\" \"$SECRETKIT_TEST_READY\" && IFS= read -r value < \"$SECRETKIT_TEST_PIPE\""],
            AppContext.BaseDirectory, new Dictionary<string, string>
            {
                ["SECRETKIT_TEST_PIPE"] = Path.Combine(directory.FullName, "blocked-pipe"),
                ["SECRETKIT_TEST_READY_TEMP"] = readyPath + ".tmp",
                ["SECRETKIT_TEST_READY"] = readyPath
            }, cancellation.Token, new string('x', 8 * 1024 * 1024));
        Process? child = null;
        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(5));
            child = Process.GetProcessById(int.Parse(await File.ReadAllTextAsync(readyPath), CultureInfo.InvariantCulture));
            var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            child.Exited += (_, _) => exited.TrySetResult();
            child.EnableRaisingEvents = true;
            cancellation.Cancel();

            await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)))
                .Throws<OperationCanceledException>();
            await exited.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(child.HasExited).IsTrue();
        }
        finally
        {
            cancellation.Cancel();
            try { await pending.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
            finally
            {
                child?.Dispose();
                watcher.EnableRaisingEvents = false;
                directory.Delete(recursive: true);
            }
        }
    }

    [Test]
    public async Task PrivateInputReachesStdinWithoutLeakingChildDiagnostics()
    {
        string generated = Guid.NewGuid().ToString("N");
        var result = await OwnedProcess.RunAsync("/bin/sh",
            ["-c", "IFS= read -r value; [ \"$value\" = \"$SECRETKIT_TEST_EXPECTED\" ] && printf 'STDIN_OBSERVED\\n'; printf '%s' \"$value\" >&2"],
            AppContext.BaseDirectory, new Dictionary<string, string> { ["SECRETKIT_TEST_EXPECTED"] = generated },
            standardInput: generated + "\n");

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Output).IsEqualTo("STDIN_OBSERVED\n");
    }

    [Test]
    public async Task ExplicitProtectedInjectionReachesTheActualProcess()
    {
        string generated = Guid.NewGuid().ToString("N");
        var result = await OwnedProcess.RunAsync("/bin/sh",
            ["-c", "[ \"$SECRETKIT_TEST_VALUE\" = \"$SECRETKIT_TEST_EXPECTED\" ] && [ -n \"$SECRETKIT_TEST_VALUE\" ] && printf 'INJECTION_OBSERVED\\n'"],
            AppContext.BaseDirectory, new Dictionary<string, string>
            {
                ["SECRETKIT_TEST_VALUE"] = generated,
                ["SECRETKIT_TEST_EXPECTED"] = generated
            });
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Output).IsEqualTo("INJECTION_OBSERVED\n");
        await Assert.That(result.Output.Contains(generated, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ExitIsSubscribedBeforeLaunchAndTheLifetimeIsRetained()
    {
        var result = await OwnedProcess.RunAsync("/bin/sh", ["-c", "printf 'EXIT_OBSERVED\\n'; exit 17"],
            AppContext.BaseDirectory);
        await Assert.That(result.ExitCode).IsEqualTo(17);
        await Assert.That(result.Output).IsEqualTo("EXIT_OBSERVED\n");
    }

    [Test]
    public async Task UnselectedAmbientCredentialsDoNotReachTheChild()
    {
        // A generated marker models an ambient credential without using any real account.
        string name = "SECRETKIT_TEST_AMBIENT_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(name, Guid.NewGuid().ToString("N"));
        try
        {
            var result = await OwnedProcess.RunAsync("/bin/sh",
                ["-c", "[ -z \"$" + name + "\" ] && printf 'AMBIENT_EMPTY\\n'"],
                AppContext.BaseDirectory);
            await Assert.That(result.ExitCode).IsEqualTo(0);
            await Assert.That(result.Output).IsEqualTo("AMBIENT_EMPTY\n");
        }
        finally { Environment.SetEnvironmentVariable(name, null); }
    }
}
