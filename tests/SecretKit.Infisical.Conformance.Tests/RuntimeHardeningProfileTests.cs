using System.Diagnostics;
using System.Text.Json;
using SecretKit.Release;

namespace SecretKit.Infisical.Conformance.Tests;

// Explicit native producer. Offline CI selects only RuntimeHardeningAdmissionTests.
public sealed class RuntimeHardeningProfileTests
{
    [Test]
    public async Task SelectedNativeExecutionProducesFreshBoundRuntimeObservations()
    {
        try
        {
            NativeWorkflow.Require(Required("SECRETKIT_RUNTIME_HARDENING_AUTHORITY") ==
                "selected-runtime-read-login-renew");
            string root = RequiredPath("SECRETKIT_LOCAL_SOURCE");
            string originals = RequiredPath("SECRETKIT_LOCAL_ORIGINALS");
            string records = RequiredPath("SECRETKIT_LOCAL_RECORD");
            string reportPath = RequiredPath("SECRETKIT_RUNTIME_HARDENING_REPORT");
            NativeWorkflow.Require(!File.Exists(reportPath) && !Directory.Exists(reportPath));
            LocalNativeBinding archives = LocalProfileConformance.Freeze(root, originals, records);
            LocalQualificationRecord freeze = LocalQualification.Check(root, originals, records);
            using var admissionDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var sdk = await OwnedProcess.RunAsync("dotnet", ["--version"], root, cancellationToken: admissionDeadline.Token);
            NativeWorkflow.Require(sdk.ExitCode == 0);
            RuntimeHardeningBinding binding = RuntimeHardeningProfile.CurrentBinding(archives,
                freeze.SourceCommit, sdk.Output.Trim());
            byte[] selectionBytes = LocalProfileConformance.ReadProtectedInput(
                RequiredPath("SECRETKIT_RUNTIME_HARDENING_SELECTION"));
            RuntimeHardeningSelection selected;
            try { selected = RuntimeHardeningProfile.Admit(selectionBytes, binding); }
            finally { Array.Clear(selectionBytes); }
            byte[] inputBytes = LocalProfileConformance.ReadProtectedInput(
                RequiredPath("SECRETKIT_RUNTIME_HARDENING_INPUT"));
            try
            {
                RuntimeHardeningInput input = RuntimeHardeningProfile.AdmitInput(inputBytes, selected);
                string runId = Guid.NewGuid().ToString("N");
                RuntimeHardeningReport report = RuntimeHardeningProfile.EmptyReport(selected, runId);
                // All prerequisites are admitted and the full unavailable denominator
                // is durable before installation or the first credential dispatch.
                await PersistAsync(reportPath, report, create: true);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(input.DeadlineSeconds));
                string output = Path.Combine(root, "artifacts/runtime-hardening-native", runId);
                string childReport = Path.Combine(output, "native-report.json");
                byte[]? envelope = null;
                bool completed = false;
                try
                {
                    var installation = await LocalProfileConformance.InstallAsync(root, originals, records, output, deadline.Token);
                    NativeWorkflow.Require(LocalProfileConformance.SameBinding(archives,
                        LocalProfileConformance.Freeze(root, originals, records)));
                    envelope = JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        schemaVersion = 1,
                        profile = "runtime-hardening",
                        runId,
                        selection = selected,
                        input
                    }, NativeWorkflow.JsonOptions);
                    NativeWorkflow.Require(envelope.Length <= 131072);
                    int exitCode = await LaunchAsync(root, Path.Combine(installation.Binary,
                        "Release/net10.0/SecretKit.InfisicalConsumer.dll"), childReport, envelope, runId, deadline.Token);
                    completed = exitCode == 0;
                }
                finally
                {
                    if (envelope is not null) Array.Clear(envelope);
                    try
                    {
                        if (File.Exists(childReport))
                        {
                            byte[] result = Manifest.ReadFile(output, "native-report.json", 131072);
                            report = RuntimeHardeningProfile.ReadProduced(result, selected, runId);
                        }
                    }
                    finally
                    {
                        try
                        {
                            NativeWorkflow.Require(LocalProfileConformance.SameBinding(archives,
                                LocalProfileConformance.Freeze(root, originals, records)));
                        }
                        catch
                        {
                            report = report with { ExecutionCompleted = false };
                            throw;
                        }
                        finally
                        {
                            if (!completed) report = report with { ExecutionCompleted = false };
                            await PersistAsync(reportPath, report, create: false);
                        }
                    }
                }
                NativeWorkflow.Require(completed && RuntimeHardeningProfile.Accepts(report, selected));
            }
            finally { Array.Clear(inputBytes); }
        }
        catch { throw new InvalidOperationException("runtime-hardening-native-unqualified"); }
    }

    private static async Task<int> LaunchAsync(string root, string binary, string reportPath,
        byte[] envelope, string runId, CancellationToken token)
    {
        NativeWorkflow.Require(!File.Exists(reportPath) && !Directory.Exists(reportPath));
        using var process = new Process
        {
            StartInfo = new("dotnet")
            {
                WorkingDirectory = root,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        process.StartInfo.Environment.Clear();
        foreach (string name in new[] { "PATH", "HOME", "DOTNET_ROOT" })
            if (Environment.GetEnvironmentVariable(name) is { } value) process.StartInfo.Environment[name] = value;
        process.StartInfo.Environment["DOTNET_EnableDiagnostics"] = "0";
        foreach (string argument in new[] { binary, "runtime-hardening", "native", reportPath })
            process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        Task errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null, token);
        // Stdout is a bounded protocol, never forwarded to the test runner.
        Task output = DrainProtocolAsync(process.StandardOutput, runId, token);
        try
        {
            await process.StandardInput.BaseStream.WriteAsync(envelope, token);
            process.StandardInput.Close();
            await Task.WhenAll(process.WaitForExitAsync(token), output, errors);
            return process.ExitCode;
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None);
            }
            try { await Task.WhenAll(output, errors); } catch { /* Never render child diagnostics. */ }
        }
    }

    private static async Task DrainProtocolAsync(StreamReader reader, string runId, CancellationToken token)
    {
        char[] buffer = new char[8193];
        int length = 0, lines = 0;
        while (await reader.ReadAsync(buffer.AsMemory(length, 1), token) != 0)
        {
            NativeWorkflow.Require(length < 8192);
            if (buffer[length] != '\n') { length++; continue; }
            using var document = JsonDocument.Parse(new string(buffer, 0, length));
            JsonElement record = document.RootElement;
            NativeWorkflow.Require(++lines <= 10 && record.GetProperty("schemaVersion").GetInt32() == 1 &&
                record.GetProperty("profile").GetString() == "runtime-hardening" &&
                record.GetProperty("runId").GetString() == runId &&
                record.GetProperty("record").GetString() is "SCENARIO" or "REPORT");
            length = 0;
        }
        NativeWorkflow.Require(length == 0);
    }

    private static async Task PersistAsync(string path, RuntimeHardeningReport report, bool create)
    {
        if (create)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.Read
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            await using var stream = new FileStream(path, options);
            await JsonSerializer.SerializeAsync(stream, report, NativeWorkflow.JsonOptions);
        }
        else
        {
            string temporary = path + "." + report.RunId + ".tmp";
            await PersistAsync(temporary, report, create: true);
            File.Move(temporary, path, overwrite: true);
        }
    }

    private static string RequiredPath(string name)
    {
        string path = Required(name);
        NativeWorkflow.Require(Path.IsPathFullyQualified(path));
        return path;
    }

    private static string Required(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value :
            throw new InvalidOperationException("runtime-hardening-input-missing");
}
