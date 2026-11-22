using System.Xml.Linq;
using SecretKit.Build;

namespace SecretKit.Release.Tests;

public sealed class ArmContractTests
{
    private const string Member = "M:Example.Client.ListAsync(System.Threading.CancellationToken)";

    private static XElement Item(string label, string value) =>
        new("item", new XElement("term", $" {label}. "), new XElement("description", $" {value}. "));

    private static XElement Route(string path, string operation, string version) =>
        new("list", Item("Request Path", path), Item("Operation Id", operation), Item("Default Api Version", version));

    private static XDocument Doc(params XElement[] lists) =>
        new(new XElement("doc", new XElement("members",
            new XElement("member", new XAttribute("name", Member), new XElement("summary", lists)))));

    [Test]
    public async Task UpstreamRouteAndRevisionChangeWithoutRebinding()
    {
        ArmMethod Read(string path, string version) => ArmContractReader.Select(Doc(
            Route("/other", "Other_List", "1"), Route(path, "Example_List", version)), Member, "Example_List");
        await Assert.That(Read("/one/{name}", "1")).IsEqualTo(new ArmMethod("/one/{name}", "1"));
        await Assert.That(Read("/two/{name}", "2")).IsEqualTo(new ArmMethod("/two/{name}", "2"));
    }

    [Test]
    [Arguments("missing")]
    [Arguments("duplicate")]
    [Arguments("wrong-member")]
    [Arguments("incomplete")]
    public async Task MissingOrAmbiguousMetadataIsRejected(string defect)
    {
        XElement first = Route("/one", "Example_List", "1");
        if (defect == "incomplete") first.Elements().Last().Remove();
        XDocument input = defect == "duplicate" ? Doc(first, new XElement(first)) : Doc(first);
        await Assert.That(() => ArmContractReader.Select(input, defect == "wrong-member" ? "M:Other" : Member,
            defect == "missing" ? "Other_List" : "Example_List")).Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("2", "hash")]
    [Arguments("1", "other")]
    public async Task MismatchedPackageBindingIsRejected(string version, string hash)
    {
        ArmContractReader.VerifyLock("1", "hash", "1", "hash");
        await Assert.That(() => ArmContractReader.VerifyLock(version, hash, "1", "hash")).Throws<InvalidDataException>();
    }

    [Test]
    public async Task NoRewriteForIdenticalBytesButOlderTimestampDoesNotHideChange()
    {
        string file = Path.GetTempFileName();
        try
        {
            ArmContractReader.WriteChanged(file, "one\n");
            File.SetLastWriteTimeUtc(file, DateTime.UnixEpoch);
            ArmContractReader.WriteChanged(file, "one\n");
            await Assert.That(File.GetLastWriteTimeUtc(file)).IsEqualTo(DateTime.UnixEpoch);
            ArmContractReader.WriteChanged(file, "two\n");
            await Assert.That(File.ReadAllText(file)).IsEqualTo("two\n");
        }
        finally { File.Delete(file); }
    }
}
