namespace SecretKit.Infisical.Tests;

public sealed class SecretCoordinateTests
{
    [Test]
    [Arguments("project")]
    [Arguments("environment")]
    [Arguments("folder")]
    [Arguments("key")]
    public async Task CoordinatesRejectAmbiguousOrUnboundedInputs(string field)
    {
        string[] invalid = ["coordinate-canary\r", "coordinate-canary\n", "coordinate-canary\0",
            "coordinate-canary\\tail", "coordinate-canary%2ftail", "coordinate-canary//tail",
            new('x', 1025)];
        foreach (string value in invalid)
        {
            ArgumentException? error = await Assert.That(() => Create(field,
                field == "folder" ? "/" + value : value)).Throws<ArgumentException>();
            await Assert.That(error!.ToString().Contains("coordinate-canary", StringComparison.Ordinal)).IsFalse();
        }
        if (field == "key")
            await Assert.That(() => Create(field, "parent/child")).Throws<ArgumentException>();
    }

    [Test]
    public async Task CanonicalBoundaryCoordinatesRemainUsable()
    {
        string segment = new('a', 1024);
        string folder = "/" + new string('b', 1023);
        var address = new InfisicalSecretAddress(segment, segment, folder, segment);

        await Assert.That(address.ProjectId).IsEqualTo(segment);
        await Assert.That(address.Environment).IsEqualTo(segment);
        await Assert.That(address.Folder).IsEqualTo(folder);
        await Assert.That(address.Key).IsEqualTo(segment);
        await Assert.That(new InfisicalSecretAddress("opaque-project", "prod", "/", "key").Folder).IsEqualTo("/");
    }

    private static InfisicalSecretAddress Create(string field, string value) =>
        new(field == "project" ? value : "project",
            field == "environment" ? value : "prod",
            field == "folder" ? value : "/",
            field == "key" ? value : "key");
}
