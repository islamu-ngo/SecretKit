using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using SecretKit.Release;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class ArchitectureBoundaryTests
{
    [Test]
    [Arguments("SecretKit.Testing")]
    [Arguments("SecretKit.Testing.Infisical")]
    [Arguments("SecretKit.TestHarness")]
    [Arguments("DemoDiagnosticsHook")]
    [Arguments("SecretKit.PackageConsumer")]
    [Arguments("SecretKit.InfisicalConsumer")]
    public async Task EvaluatedFixturesAreNonpackableAndRespectDependencyBoundaries(string fixture)
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string output = await PackageInstallTests.Run(root,
        [
            "msbuild", $"tests/fixtures/{fixture}/{fixture}.csproj", "-nologo",
            "-getProperty:IsPackable,IsTestProject,OutputType", "-getItem:ProjectReference,PackageReference"
        ]);
        using JsonDocument evaluation = JsonDocument.Parse(output);
        JsonElement properties = evaluation.RootElement.GetProperty("Properties");
        await Assert.That(properties.GetProperty("IsPackable").GetString()).IsEqualTo("false");
        await Assert.That(properties.GetProperty("IsTestProject").GetString() == "true").IsFalse();
        bool consumer = fixture is "SecretKit.PackageConsumer" or "SecretKit.InfisicalConsumer";
        await Assert.That(properties.GetProperty("OutputType").GetString()).IsEqualTo(consumer ? "Exe" : "Library");
        JsonElement items = evaluation.RootElement.GetProperty("Items");
        string[] references = items.GetProperty("ProjectReference").EnumerateArray()
            .Select(item => item.GetProperty("Filename").GetString()!).Order(StringComparer.Ordinal).ToArray();
        string[] expected = fixture switch
        {
            "SecretKit.Testing" => ["SecretKit.Core"],
            "SecretKit.Testing.Infisical" => ["SecretKit.Infisical", "SecretKit.Testing"],
            "SecretKit.TestHarness" => ["SecretKit.Release"],
            _ => []
        };
        await Assert.That(references.SequenceEqual(expected, StringComparer.Ordinal)).IsTrue();
        string[] packages = items.GetProperty("PackageReference").EnumerateArray()
            .Select(item => item.GetProperty("Identity").GetString()!).Order(StringComparer.Ordinal).ToArray();
        string[] expectedPackages = fixture switch
        {
            "SecretKit.PackageConsumer" => [.. PackageCandidate.PackageIds, "Microsoft.IdentityModel.JsonWebTokens"],
            "SecretKit.InfisicalConsumer" => ["SecretKit.Core", "SecretKit.Infisical"],
            _ => []
        };
        await Assert.That(packages.SequenceEqual(expectedPackages.Order(StringComparer.Ordinal), StringComparer.Ordinal)).IsTrue();
    }

    [Test]
    [Arguments("SecretKit.Core")]
    [Arguments("SecretKit.Infisical")]
    [Arguments("SecretKit.AzureKeyVault")]
    [Arguments("SecretKit.Extensions.Configuration")]
    [Arguments("SecretKit.Extensions.Hosting")]
    [Arguments("SecretKit.Infisical.Management")]
    [Arguments("SecretKit.AzureKeyVault.Management")]
    public async Task ShippedAssemblyDependenciesAndFriendshipsRespectReviewedBoundaries(string package)
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        PackageCandidate candidate = PackageCandidate.FromEnvironment(root);
        ArchiveContent archive = PackageArchive.Read(File.ReadAllBytes(candidate.ArchivePath(package)));
        using var assembly = new MemoryStream(archive.Files[$"lib/net10.0/{package}.dll"], writable: false);
        using var image = new PEReader(assembly, PEStreamOptions.PrefetchMetadata);
        MetadataReader metadata = image.GetMetadataReader();
        string[] dependencies = metadata.AssemblyReferences
            .Select(handle => metadata.GetString(metadata.GetAssemblyReference(handle).Name)).ToArray();
        string[] allowed = package switch
        {
            "SecretKit.Core" => [],
            "SecretKit.Infisical" or "SecretKit.AzureKeyVault" or
                "SecretKit.Extensions.Configuration" or "SecretKit.AzureKeyVault.Management" => ["SecretKit.Core"],
            "SecretKit.Extensions.Hosting" or "SecretKit.Infisical.Management" => ["SecretKit.Core", "SecretKit.Infisical"],
            _ => throw new InvalidOperationException("Unknown shipped package.")
        };
        await Assert.That(dependencies.Where(name => name.StartsWith("SecretKit.", StringComparison.Ordinal))
            .All(name => allowed.Contains(name, StringComparer.Ordinal))).IsTrue();
        if (package == "SecretKit.Core")
            await Assert.That(dependencies.All(name => name.StartsWith("System.", StringComparison.Ordinal))).IsTrue();

        string[] friends = metadata.GetAssemblyDefinition().GetCustomAttributes()
            .Select(handle => metadata.GetCustomAttribute(handle))
            .Where(attribute => IsFriendAttribute(metadata, attribute))
            .Select(attribute => FriendName(metadata, attribute)).Order(StringComparer.Ordinal).ToArray();
        string[] expected = package switch
        {
            "SecretKit.Infisical" => ["SecretKit.Hosting.Tests", "SecretKit.Infisical.Management", "SecretKit.Infisical.Tests", "SecretKit.ProviderContract.Tests"],
            "SecretKit.Infisical.Management" => ["SecretKit.Infisical.Management.Tests"],
            _ => []
        };
        await Assert.That(friends.SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal)).IsTrue();
    }

    private static bool IsFriendAttribute(MetadataReader metadata, CustomAttribute attribute)
    {
        if (attribute.Constructor.Kind != HandleKind.MemberReference) return false;
        MemberReference constructor = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
        if (constructor.Parent.Kind != HandleKind.TypeReference) return false;
        TypeReference type = metadata.GetTypeReference((TypeReferenceHandle)constructor.Parent);
        return metadata.GetString(type.Namespace) == "System.Runtime.CompilerServices" &&
            metadata.GetString(type.Name) == "InternalsVisibleToAttribute";
    }

    private static string FriendName(MetadataReader metadata, CustomAttribute attribute)
    {
        BlobReader value = metadata.GetBlobReader(attribute.Value);
        if (value.ReadUInt16() != 1) throw new InvalidDataException("Invalid assembly friendship.");
        return value.ReadSerializedString() ?? throw new InvalidDataException("Missing assembly friendship.");
    }
}
