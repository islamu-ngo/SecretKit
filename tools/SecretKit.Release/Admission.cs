using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace SecretKit.Release;

public sealed record AdmissionOperation(string Id, string Member, string[] Variants,
    string Contract, string Effect, string[] RequiredCases, string[] Prerequisites);
public sealed record AdmissionInventory(int SchemaVersion, string Kind, string Provider,
    string Policy, FileDigest[] Sources, AdmissionOperation[] Operations, string[] Exclusions);

public static class Admission
{
    public static void Validate(AdmissionInventory inventory, IReadOnlyCollection<string> currentMembers)
    {
        Guard.Require(inventory.SchemaVersion == 1 && inventory.Kind == "current-admission" &&
            inventory.Provider is "Infisical" or "AzureKeyVault" &&
            inventory.Policy == "complete-live", "admission-policy");
        Guard.Require(inventory.Sources.Length > 0 &&
            inventory.Sources.All(s => s.File.StartsWith("src/", StringComparison.Ordinal) &&
                !s.File.Contains("..", StringComparison.Ordinal) && s.File.EndsWith(".cs", StringComparison.Ordinal) &&
                Manifest.IsHash(s.Sha256)) &&
            inventory.Sources.Select(s => s.File).Distinct(StringComparer.Ordinal).Count() == inventory.Sources.Length,
            "admission-sources");
        Guard.Require(inventory.Operations.Length is > 0 and <= 4096 &&
            inventory.Operations.All(o => Label(o.Id) && Bounded(o.Member) &&
                o.Contract is "implemented-subset" or "contract-gap" && Bounded(o.Effect) &&
                o.Variants.Length > 0 && o.Variants.All(Bounded) &&
                o.Variants.Distinct(StringComparer.Ordinal).Count() == o.Variants.Length &&
                o.RequiredCases.Length > 0 && o.RequiredCases.All(Label) &&
                o.RequiredCases.Distinct(StringComparer.Ordinal).Count() == o.RequiredCases.Length &&
                o.Prerequisites.Length > 0 && o.Prerequisites.All(Label) &&
                o.Prerequisites.Distinct(StringComparer.Ordinal).Count() == o.Prerequisites.Length) &&
            inventory.Operations.Select(o => o.Id).Distinct(StringComparer.Ordinal).Count() == inventory.Operations.Length,
            "admission-operations");
        Manifest.ExactSet(inventory.Operations.Select(o => o.Member), currentMembers, "admission-member-coverage");
        Guard.Require(inventory.Exclusions.Length > 0 && inventory.Exclusions.All(Bounded) &&
            inventory.Exclusions.Distinct(StringComparer.Ordinal).Count() == inventory.Exclusions.Length,
            "admission-exclusions");
    }

    // Reads compiler metadata only; it neither loads providers nor executes their code.
    public static string[] PublicRemoteMembers(string assemblyPath)
    {
        using FileStream stream = File.OpenRead(assemblyPath);
        using var image = new PEReader(stream);
        MetadataReader metadata = image.GetMetadataReader();
        var types = new SignatureNames();
        var members = new List<string>();
        foreach (TypeDefinitionHandle handle in metadata.TypeDefinitions)
        {
            TypeDefinition type = metadata.GetTypeDefinition(handle);
            if ((type.Attributes & TypeAttributes.Interface) != 0 || !PublicType(metadata, handle))
                continue;
            string owner = types.GetTypeFromDefinition(metadata, handle, 0);
            foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
            {
                MethodDefinition method = metadata.GetMethodDefinition(methodHandle);
                if ((method.Attributes & MethodAttributes.MemberAccessMask) != MethodAttributes.Public ||
                    (method.Attributes & MethodAttributes.SpecialName) != 0)
                    continue;
                string name = metadata.GetString(method.Name);
                MethodSignature<string> signature = method.DecodeSignature(types, genericContext: null);
                bool factory = signature.ReturnType.StartsWith(
                    "SecretKit.Infisical.Management.ManagementRequest<", StringComparison.Ordinal);
                bool asynchronous = name is not ("DisposeAsync" or "StopAsync") &&
                    (signature.ReturnType.StartsWith("System.Threading.Tasks.ValueTask", StringComparison.Ordinal) ||
                        signature.ReturnType.StartsWith("System.Threading.Tasks.Task", StringComparison.Ordinal));
                if (factory || asynchronous)
                    members.Add($"{owner}.{name}({string.Join(",", signature.ParameterTypes)})");
            }
        }
        return members.Order(StringComparer.Ordinal).ToArray();
    }

    private static bool PublicType(MetadataReader metadata, TypeDefinitionHandle handle)
    {
        TypeDefinition type = metadata.GetTypeDefinition(handle);
        TypeAttributes visibility = type.Attributes & TypeAttributes.VisibilityMask;
        return visibility == TypeAttributes.Public ||
            visibility == TypeAttributes.NestedPublic && PublicType(metadata, type.GetDeclaringType());
    }

    private static bool Bounded(string value) => value.Length is > 0 and <= 4096 &&
        value.All(c => c is >= ' ' and <= '~');

    private static bool Label(string value) => value.Length is > 0 and <= 128 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_');

    private sealed class SignatureNames : ISignatureTypeProvider<string, object?>
    {
        public string GetArrayType(string elementType, ArrayShape shape) => elementType + "[" + new string(',', shape.Rank - 1) + "]";
        public string GetByReferenceType(string elementType) => elementType + "&";
        public string GetFunctionPointerType(MethodSignature<string> signature) => "function-pointer";
        public string GetGenericInstantiation(string genericType, System.Collections.Immutable.ImmutableArray<string> typeArguments) =>
            genericType.Split('`')[0] + "<" + string.Join(",", typeArguments) + ">";
        public string GetGenericMethodParameter(object? genericContext, int index) => "!!" + index;
        public string GetGenericTypeParameter(object? genericContext, int index) => "!" + index;
        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
        public string GetPinnedType(string elementType) => elementType;
        public string GetPointerType(string elementType) => elementType + "*";
        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => "System." + typeCode;
        public string GetSZArrayType(string elementType) => elementType + "[]";
        public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind)
        {
            TypeDefinition type = reader.GetTypeDefinition(handle);
            string name = reader.GetString(type.Name);
            return type.GetDeclaringType().IsNil
                ? reader.GetString(type.Namespace) + "." + name
                : GetTypeFromDefinition(reader, type.GetDeclaringType(), rawTypeKind) + "+" + name;
        }
        public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
        {
            TypeReference type = reader.GetTypeReference(handle);
            return type.ResolutionScope.Kind == HandleKind.TypeReference
                ? GetTypeFromReference(reader, (TypeReferenceHandle)type.ResolutionScope, rawTypeKind) + "+" + reader.GetString(type.Name)
                : reader.GetString(type.Namespace) + "." + reader.GetString(type.Name);
        }
        public string GetTypeFromSpecification(MetadataReader reader, object? genericContext,
            TypeSpecificationHandle handle, byte rawTypeKind) => reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
    }
}
