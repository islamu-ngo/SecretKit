namespace SecretKit.Infisical.Conformance.Tests;

public sealed class ProcessLifetimeTests
{
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
