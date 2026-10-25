namespace SecretKit.Demo.Tests;

public sealed class DemoBoundaryTests
{
    [Test]
    [Arguments("missing-member")]
    [Arguments("extra-member")]
    [Arguments("wrong-version")]
    public async Task ExplicitInvalidCandidateCannotFallBackToOtherSources(string fault)
    {
        string originals = Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_DIRECTORY") ??
            throw new InvalidOperationException("Select exact demo originals.");
        string version = Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_VERSION") ??
            throw new InvalidOperationException("Select exact demo version.");
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string selected = Path.Combine(root, "artifacts/runtime-adoption-hardening/boundary", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(selected);
        try
        {
            foreach (string archive in Directory.GetFiles(originals, "*.nupkg"))
                File.Copy(archive, Path.Combine(selected, Path.GetFileName(archive)));
            if (fault == "missing-member")
                File.Delete(Path.Combine(selected, $"SecretKit.Extensions.Hosting.{version}.nupkg"));
            if (fault == "extra-member")
                File.Copy(Path.Combine(selected, $"SecretKit.Core.{version}.nupkg"),
                    Path.Combine(selected, $"SecretKit.Unselected.{version}.nupkg"));
            var driver = new DemoProcess(candidateSelection: (selected,
                fault == "wrong-version" ? version + "-different" : version));
            await Assert.That(async () => await driver.ConsoleAsync("", "--help"))
                .Throws<InvalidOperationException>();
        }
        finally { Directory.Delete(selected, recursive: true); }
    }
}
