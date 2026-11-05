namespace SecretKit.Demo.Tests;

public sealed class DemoLockInputTests
{
    [Test]
    [Arguments("missing")]
    [Arguments("empty")]
    [Arguments("link")]
    public async Task ExplicitInvalidLockSelectionNeverFallsBack(string fault)
    {
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-demo-lock-" + Guid.NewGuid().ToString("N"));
        string selection = Path.Combine(directory, "selected");
        Directory.CreateDirectory(directory);
        try
        {
            if (fault == "empty") Directory.CreateDirectory(selection);
            if (fault == "link")
            {
                string target = Path.Combine(directory, "target");
                Directory.CreateDirectory(target);
                Directory.CreateSymbolicLink(selection, target);
            }
            await Assert.That(async () => await new DemoProcess(stagedLockDirectory: selection)
                .ConsoleAsync("", "--help")).Throws<InvalidOperationException>();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Test]
    public async Task ExplicitCandidateVersionReachesFormattingAndActualExecution()
    {
        string directory = Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_DIRECTORY") ??
            throw new InvalidOperationException("Select demo originals.");
        string version = Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_VERSION") ??
            throw new InvalidOperationException("Select the verified demo cohort version.");
        DemoResult result = await new DemoProcess(candidateSelection: (directory, version))
            .ConsoleAsync("", "--help");
        await Assert.That(result.ExitCode).IsEqualTo(0);
        using var report = System.Text.Json.JsonDocument.Parse(result.Output);
        await Assert.That(report.RootElement.GetProperty("outcome").GetString()).IsEqualTo("help");
    }
}
