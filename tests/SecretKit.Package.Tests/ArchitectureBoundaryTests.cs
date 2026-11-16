using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
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
        if (package == "SecretKit.Infisical.Management")
        {
            await Assert.That(RuntimeManagementDependencyTests.UnapprovedRuntimeReferences(metadata)).IsEmpty();
            string[] publicTypes = metadata.TypeDefinitions
                .Select(metadata.GetTypeDefinition)
                .Where(type => (type.Attributes & TypeAttributes.VisibilityMask) is TypeAttributes.Public or TypeAttributes.NestedPublic)
                .Select(type => metadata.GetString(type.Name))
                .ToArray();
            string[] expectedSqlTypes =
            [
                "SqlRotationNullableText",
                "SqlRotationPasswordRequirements",
                "SqlRotationTime",
                "SqlRotationSecretsMapping"
            ];
            foreach (string sqlType in expectedSqlTypes)
                await Assert.That(publicTypes.Contains(sqlType, StringComparer.Ordinal)).IsTrue();
            string[] duplicateSuffixes =
            [
                "RotationNullableText",
                "RotationPasswordRequirements",
                "RotationTime",
                "RotationSecretsMapping"
            ];
            await Assert.That(publicTypes.Any(name => duplicateSuffixes.Any(suffix =>
                name.EndsWith(suffix, StringComparison.Ordinal) && !name.StartsWith("Sql", StringComparison.Ordinal)))).IsFalse();
            bool hasUnestablishedFlags = metadata.PropertyDefinitions
                .Select(metadata.GetPropertyDefinition)
                .Any(property =>
                {
                    string name = metadata.GetString(property.Name);
                    return name.StartsWith("HasUnestablished", StringComparison.Ordinal) &&
                        name.EndsWith("Projection", StringComparison.Ordinal);
                });
            await Assert.That(hasUnestablishedFlags).IsFalse();
        }
        await Assert.That(HasPublicSecretMaterialPropertyWithoutJsonIgnore(metadata)).IsFalse();
        if (package is "SecretKit.Core" or "SecretKit.Extensions.Configuration" or "SecretKit.Extensions.Hosting" or
            "SecretKit.Infisical" or "SecretKit.Infisical.Management")
        {
            bool trimmable = metadata.GetAssemblyDefinition().GetCustomAttributes()
                .Select(handle => metadata.GetCustomAttribute(handle))
                .Any(attribute => IsAssemblyMetadata(metadata, attribute, "IsTrimmable", "True"));
            bool aotCompatible = metadata.GetAssemblyDefinition().GetCustomAttributes()
                .Select(handle => metadata.GetCustomAttribute(handle))
                .Any(attribute => IsAssemblyMetadata(metadata, attribute, "IsAotCompatible", "True"));
            await Assert.That(trimmable).IsTrue();
            await Assert.That(aotCompatible).IsTrue();
            await Assert.That(HasTrimmingIncompatibleAttribute(metadata)).IsFalse();
            await Assert.That(HasRefitContentSerializerReference(metadata)).IsFalse();
        }
        bool hasLegacyObjectLock = metadata.FieldDefinitions
            .Select(handle => metadata.GetFieldDefinition(handle))
            .Any(field =>
            {
                string name = metadata.GetString(field.Name);
                if (name is not ("_gate" or "<Gate>k__BackingField" or "UsedReceiptsGate")) return false;
                BlobReader signature = metadata.GetBlobReader(field.Signature);
                return signature.ReadSignatureHeader().Kind == SignatureKind.Field &&
                    signature.ReadByte() == (byte)SignatureTypeCode.Object;
            });
        await Assert.That(hasLegacyObjectLock).IsFalse();
    }

    private static bool HasPublicSecretMaterialPropertyWithoutJsonIgnore(MetadataReader metadata)
    {
        foreach (TypeDefinitionHandle typeHandle in metadata.TypeDefinitions)
        {
            TypeDefinition type = metadata.GetTypeDefinition(typeHandle);
            if ((type.Attributes & TypeAttributes.VisibilityMask) is not (TypeAttributes.Public or TypeAttributes.NestedPublic))
                continue;
            foreach (PropertyDefinitionHandle propertyHandle in type.GetProperties())
            {
                PropertyDefinition property = metadata.GetPropertyDefinition(propertyHandle);
                PropertyAccessors accessors = property.GetAccessors();
                if (accessors.Getter.IsNil) continue;
                MethodDefinition getter = metadata.GetMethodDefinition(accessors.Getter);
                if ((getter.Attributes & MethodAttributes.MemberAccessMask) != MethodAttributes.Public) continue;
                BlobReader blob = metadata.GetBlobReader(property.Signature);
                blob.ReadSignatureHeader();
                _ = blob.ReadCompressedInteger();
                if (!TypeSignatureReferencesSecretMaterial(metadata, ref blob)) continue;
                bool hasJsonIgnore = property.GetCustomAttributes()
                    .Select(metadata.GetCustomAttribute)
                    .Any(attribute => HasAttributeName(metadata, attribute,
                        "System.Text.Json.Serialization", "JsonIgnoreAttribute"));
                if (!hasJsonIgnore) return true;
            }
        }
        return false;
    }

    private static bool TypeSignatureReferencesSecretMaterial(MetadataReader metadata, ref BlobReader blob)
    {
        SignatureTypeCode code = blob.ReadSignatureTypeCode();
        switch (code)
        {
            case SignatureTypeCode.TypeHandle:
                {
                    EntityHandle handle = blob.ReadTypeHandle();
                    if (handle.Kind == HandleKind.TypeDefinition)
                    {
                        TypeDefinition type = metadata.GetTypeDefinition((TypeDefinitionHandle)handle);
                        return metadata.GetString(type.Namespace) == "SecretKit.Core" &&
                            metadata.GetString(type.Name) == "SecretMaterial";
                    }
                    if (handle.Kind == HandleKind.TypeReference)
                    {
                        TypeReference type = metadata.GetTypeReference((TypeReferenceHandle)handle);
                        return metadata.GetString(type.Namespace) == "SecretKit.Core" &&
                            metadata.GetString(type.Name) == "SecretMaterial";
                    }
                    return false;
                }
            case SignatureTypeCode.GenericTypeInstance:
                {
                    _ = blob.ReadByte();
                    _ = blob.ReadTypeHandle();
                    int count = blob.ReadCompressedInteger();
                    bool match = false;
                    for (int i = 0; i < count; i++)
                    {
                        if (TypeSignatureReferencesSecretMaterial(metadata, ref blob)) match = true;
                    }
                    return match;
                }
            case SignatureTypeCode.SZArray:
                return TypeSignatureReferencesSecretMaterial(metadata, ref blob);
            case SignatureTypeCode.OptionalModifier:
            case SignatureTypeCode.RequiredModifier:
                _ = blob.ReadTypeHandle();
                return TypeSignatureReferencesSecretMaterial(metadata, ref blob);
            default:
                return false;
        }
    }

    private static bool HasAttributeName(MetadataReader metadata, CustomAttribute attribute, string expectedNamespace, string expectedName)
    {
        if (attribute.Constructor.Kind != HandleKind.MemberReference) return false;
        MemberReference constructor = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
        if (constructor.Parent.Kind != HandleKind.TypeReference) return false;
        TypeReference type = metadata.GetTypeReference((TypeReferenceHandle)constructor.Parent);
        return metadata.GetString(type.Namespace) == expectedNamespace &&
            metadata.GetString(type.Name) == expectedName;
    }

    private static bool HasTrimmingIncompatibleAttribute(MetadataReader metadata)
    {
        foreach (CustomAttributeHandle handle in metadata.CustomAttributes)
        {
            CustomAttribute attribute = metadata.GetCustomAttribute(handle);
            if (attribute.Constructor.Kind != HandleKind.MemberReference) continue;
            MemberReference constructor = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
            if (constructor.Parent.Kind != HandleKind.TypeReference) continue;
            TypeReference type = metadata.GetTypeReference((TypeReferenceHandle)constructor.Parent);
            if (metadata.GetString(type.Namespace) == "System.Diagnostics.CodeAnalysis" &&
                metadata.GetString(type.Name) is "RequiresUnreferencedCodeAttribute" or "RequiresDynamicCodeAttribute")
            {
                return true;
            }
        }
        return false;
    }

    private static bool HasRefitContentSerializerReference(MetadataReader metadata)
    {
        foreach (MemberReferenceHandle handle in metadata.MemberReferences)
        {
            MemberReference member = metadata.GetMemberReference(handle);
            if (member.Parent.Kind != HandleKind.TypeReference) continue;
            TypeReference type = metadata.GetTypeReference((TypeReferenceHandle)member.Parent);
            string typeNs = metadata.GetString(type.Namespace);
            string typeName = metadata.GetString(type.Name);
            string methodName = metadata.GetString(member.Name);
            if (typeNs == "Refit" && typeName == "SystemTextJsonContentSerializer")
            {
                return true;
            }
            if (typeNs == "System.Text.Json" && typeName == "JsonSerializer" &&
                methodName is "Serialize" or "SerializeToUtf8Bytes" or "Deserialize")
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsAssemblyMetadata(MetadataReader metadata, CustomAttribute attribute, string expectedKey, string expectedValue)
    {
        if (attribute.Constructor.Kind != HandleKind.MemberReference) return false;
        MemberReference constructor = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
        if (constructor.Parent.Kind != HandleKind.TypeReference) return false;
        TypeReference type = metadata.GetTypeReference((TypeReferenceHandle)constructor.Parent);
        if (metadata.GetString(type.Namespace) != "System.Reflection" ||
            metadata.GetString(type.Name) != "AssemblyMetadataAttribute")
        {
            return false;
        }
        BlobReader value = metadata.GetBlobReader(attribute.Value);
        if (value.ReadUInt16() != 1) return false;
        string? key = value.ReadSerializedString();
        string? actual = value.ReadSerializedString();
        return string.Equals(key, expectedKey, StringComparison.Ordinal) &&
            string.Equals(actual, expectedValue, StringComparison.OrdinalIgnoreCase);
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
