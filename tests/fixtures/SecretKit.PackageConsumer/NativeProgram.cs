using System.Runtime.InteropServices;
using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests;
using SecretKit.Infisical.Conformance.Tests;
using SecretKit.TestFixtures;

internal static class NativeProgram
{
    internal static async Task<int> RunAsync(string provider, string destination)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        DateTimeOffset started = DateTimeOffset.UtcNow;
        try
        {
            if (!Path.IsPathFullyQualified(destination)) throw new InvalidOperationException("native-output-path");
            NativeRunEnvelope envelope = NativeRunProtocol.Parse<NativeRunEnvelope>(
                await NativeRunProtocol.ReadBoundedAsync(Console.OpenStandardInput(), deadline.Token));
            NativeRunRequest request = envelope.Request;
            request.Validate();
            if (request.Provider != provider) throw new InvalidOperationException("native-provider-mismatch");
            var registry = new NativeCaseRegistry();
            NativeCaseResult[] cases;
            NativePrerequisiteResult[] prerequisites = request.Prerequisites.Select(p =>
                new NativePrerequisiteResult(p.Provider, p.Scope, p.Prerequisite, false)).ToArray();
            try
            {
                if (provider == "Infisical")
                {
                    using NativeEnvironment environment = NativeEnvironment.Create(envelope.FixtureSettings);
                    InfisicalNativeCases.Register(registry, environment, request.Expected);
                    cases = (await NativeCaseRunner.RunAsync(registry, request.Expected, deadline.Token)).ToArray();
                    prerequisites = environment.PrerequisiteResults(request.Prerequisites);
                }
                else
                {
                    using OwnedAzureEnvironment environment = OwnedAzureEnvironment.Create(envelope.FixtureSettings);
                    AzureNativeCases.Register(registry, environment, request.Expected);
                    cases = (await NativeCaseRunner.RunAsync(registry, request.Expected, deadline.Token)).ToArray();
                    prerequisites = environment.PrerequisiteResults(request.Prerequisites);
                }
            }
            catch (Exception error)
            {
                string reason = error is OperationCanceledException ? "deadline-exceeded" :
                    error is NativeCaseFailureException { Message: "missing-input" } ? "missing-input" :
                    error is NativeCaseFailureException { Message: "missing-prerequisite" } ? "missing-prerequisite" :
                    error is InvalidOperationException { Message: "native-missing-input" } ? "missing-input" : "unexpected-failure";
                cases = request.Expected.Select(d => new NativeCaseResult(d.Key.Provider, d.Key.Operation,
                    d.Key.Variant, d.Key.Scope, d.Key.Case, false, false, reason)).ToArray();
            }

            string os = OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsWindows() ? "windows" : "unsupported";
            var installation = new NativeInstallationResult(os,
                RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
                $"net{Environment.Version.Major}.0");
            var result = new NativeRunResult(provider, request.Kind, request.Platform, request.Version,
                request.SourceCommit, request.ScopeSha256, started, DateTimeOffset.UtcNow, cases, prerequisites, installation);
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(result, NativeRunProtocol.JsonOptions);
            if (bytes.Length > NativeRunProtocol.ResultBytes) throw new InvalidOperationException("native-output-size");
            await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await output.WriteAsync(bytes, deadline.Token);
            return cases.Any(c => !c.Passed || !c.EffectObserved) || prerequisites.Any(p => !p.Confirmed) ? 1 : 0;
        }
        catch
        {
            Console.Error.WriteLine("Native consumer failed; protected diagnostics withheld.");
            return 1;
        }
    }
}
