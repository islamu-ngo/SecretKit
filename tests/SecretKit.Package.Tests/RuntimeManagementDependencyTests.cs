using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace SecretKit.Package.Tests;

public sealed class RuntimeManagementDependencyTests
{
    private const string Runtime = "SecretKit.Infisical";
    private const string I = "[SecretKit.Infisical]SecretKit.Infisical.";
    private const string S = "[System.Runtime]System.";
    private const string C = "[SecretKit.Core]SecretKit.Core.";
    private const string H = "[System.Net.Http]System.Net.Http.";
    private static readonly HashSet<string> Approved = new(StringComparer.Ordinal)
    {
        // Public identity/network selection and read-only native rotation selectors.
        $"type {I}IInfisicalTokenSource",
        $"type {I}InfisicalAccessToken",
        $"type {I}InfisicalNativeAddress",
        $"type {I}InfisicalNetworkOptions",
        $"type {I}InfisicalRotationAddress",
        $"type {I}InfisicalRotationProfile",
        $"method {I}IInfisicalTokenSource::GetTokenAsync [32;0;1]({S}Threading.CancellationToken)->{S}Threading.Tasks.ValueTask`1<{C}SecretOutcome`1<{I}InfisicalAccessToken>>",
        $"method {I}InfisicalAccessToken::get_ExpiresAt [32;0;0]()->{S}Nullable`1<{S}DateTimeOffset>",
        $"method {I}InfisicalAccessToken::get_Material [32;0;0]()->{C}SecretMaterial",
        $"method {I}InfisicalNativeAddress::get_Environment [32;0;0]()->String",
        $"method {I}InfisicalNativeAddress::get_Folder [32;0;0]()->String",
        $"method {I}InfisicalNativeAddress::get_ProjectId [32;0;0]()->String",
        $"method {I}InfisicalRotationAddress::get_Profile [32;0;0]()->{I}InfisicalRotationProfile",
        $"method {I}InfisicalRotationAddress::get_RotationId [32;0;0]()->String",
        $"method {I}InfisicalNetworkOptions::.ctor [32;0;0]()->Void",
        $"method {I}InfisicalNetworkOptions::get_MaximumRequestBytes [32;0;0]()->Int32",
        $"method {I}InfisicalNetworkOptions::get_MaximumResponseBytes [32;0;0]()->Int32",
        $"method {I}InfisicalNetworkOptions::get_OperationTimeout [32;0;0]()->{S}TimeSpan",
        $"method {I}InfisicalNetworkOptions::set_AllowLoopbackDevelopmentHttp [32;0;1](Boolean)->Void modreq({S}Runtime.CompilerServices.IsExternalInit)",
        $"method {I}InfisicalNetworkOptions::set_MaximumResponseBytes [32;0;1](Int32)->Void modreq({S}Runtime.CompilerServices.IsExternalInit)",
        $"method {I}InfisicalNetworkOptions::set_Proxy [32;0;1]([System.Net.Primitives]System.Net.IWebProxy)->Void modreq({S}Runtime.CompilerServices.IsExternalInit)",

        // Internal fixed-origin transport ownership; no arbitrary runtime operation.
        $"type {I}InfisicalTransportBinding",
        $"method {I}InfisicalTransportBinding::.ctor [32;0;4]({S}Uri,{I}InfisicalNetworkOptions,{H}HttpMessageHandler,Boolean)->Void",
        $"method {I}InfisicalTransportBinding::ValidateOrigin [0;0;2]({S}Uri,{I}InfisicalNetworkOptions)->Void",
        $"method {I}InfisicalTransportBinding::get_Client [32;0;0]()->{H}HttpClient",
        $"method {I}InfisicalTransportBinding::get_Requests [32;0;0]()->{H}HttpClient",
        $"method {I}InfisicalTransportBinding::Dispose [32;0;0]()->Void",

        // One credential-to-publication budget and finite Retry-After parsing.
        $"type {I}InfisicalOperation",
        $"type {I}InfisicalOperationBudget",
        $"method {I}InfisicalOperationBudget::RetryAfter [0;0;2]({H}HttpResponseMessage,{S}TimeProvider)->{S}Nullable`1<{S}TimeSpan>",
        $"method {I}InfisicalOperationBudget::RunAsync [16;1;8]({S}TimeSpan,{S}TimeProvider,{S}Threading.CancellationToken,{S}Nullable`1<{I}InfisicalOperation>,{S}Func`2<{S}Threading.CancellationToken,{S}Threading.Tasks.ValueTask`1<{C}SecretOutcome`1<!!0>>>,{S}Func`1<{C}DispatchEvidence>,{S}Threading.CancellationToken,{I}InfisicalOperationObservation)->{S}Threading.Tasks.ValueTask`1<{C}SecretOutcome`1<!!0>>",

        // C14 reuses capture/deferral/observation, not the runtime diagnostic emitter.
        $"type {I}InfisicalDiagnosticStart",
        $"type {I}InfisicalDiagnosticInterval",
        $"type {I}InfisicalDiagnostics",
        $"type {I}InfisicalOperationCompletion",
        $"type {I}InfisicalOperationObservation",
        $"type {I}InfisicalTermination",
        $"method {I}InfisicalDiagnostics::Capture [0;0;1]({S}TimeProvider)->{S}Nullable`1<{I}InfisicalDiagnosticStart>",
        $"method {I}InfisicalDiagnostics::Complete [0;0;2]({S}Nullable`1<{I}InfisicalDiagnosticStart>,{S}TimeProvider)->{S}Nullable`1<{I}InfisicalDiagnosticInterval>",
        $"method {I}InfisicalDiagnostics::Defer [0;0;0]()->{S}IDisposable",
        $"method {I}InfisicalDiagnosticInterval::get_StartUtc [32;0;0]()->{S}DateTime",
        $"method {I}InfisicalDiagnosticInterval::get_Duration [32;0;0]()->{S}TimeSpan",
        $"method {I}InfisicalDiagnosticInterval::get_Parent [32;0;0]()->[System.Diagnostics.DiagnosticSource]System.Diagnostics.ActivityContext",
        $"method {I}InfisicalOperationCompletion::get_Status [32;0;0]()->{C}SecretStatus",
        $"method {I}InfisicalOperationCompletion::get_Reason [32;0;0]()->{C}SecretFailureReason",
        $"method {I}InfisicalOperationCompletion::get_Dispatch [32;0;0]()->{C}DispatchEvidence",
        $"method {I}InfisicalOperationCompletion::get_Termination [32;0;0]()->{I}InfisicalTermination",
        $"method {I}InfisicalOperationObservation::.ctor [32;0;0]()->Void",
        $"method {I}InfisicalOperationObservation::get_Completion [32;0;0]()->{S}Nullable`1<{I}InfisicalOperationCompletion>",
    };

    [Test]
    public async Task CurrentCompiledManagementUsesOnlyReviewedRuntimeMembers()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string path = Path.Combine(root, "src", "SecretKit.Infisical.Management", "bin", "Release",
            "net10.0", "SecretKit.Infisical.Management.dll");
        using var stream = File.OpenRead(path);
        using var image = new PEReader(stream, PEStreamOptions.PrefetchMetadata);
        MetadataReader metadata = image.GetMetadataReader();
        string[] references = RuntimeReferences(metadata);
        Console.WriteLine(string.Join(Environment.NewLine, references));
        await Assert.That(references.Length > 0).IsTrue();
        await Assert.That(UnapprovedRuntimeReferences(metadata)).IsEmpty();
    }

    internal static string[] UnapprovedRuntimeReferences(MetadataReader metadata) =>
        RuntimeReferences(metadata).Where(reference => !Approved.Contains(reference)).ToArray();

    private static string[] RuntimeReferences(MetadataReader metadata)
    {
        var provider = new Names();
        var references = new HashSet<string>(StringComparer.Ordinal);
        foreach (TypeReferenceHandle handle in metadata.TypeReferences)
        {
            Named type = provider.GetTypeFromReference(metadata, handle, 0);
            if (type.Runtime) references.Add("type " + type.Name);
        }
        foreach (MemberReferenceHandle handle in metadata.MemberReferences)
        {
            MemberReference member = metadata.GetMemberReference(handle);
            Named owner = member.Parent.Kind switch
            {
                HandleKind.TypeReference => provider.GetTypeFromReference(metadata, (TypeReferenceHandle)member.Parent, 0),
                HandleKind.TypeSpecification => provider.GetTypeFromSpecification(metadata, null,
                    (TypeSpecificationHandle)member.Parent, 0),
                _ => new("", false)
            };
            if (!owner.Runtime) continue;
            string name = owner.Name + "::" + metadata.GetString(member.Name);
            references.Add(member.GetKind() == MemberReferenceKind.Field
                ? "field " + name + ":" + member.DecodeFieldSignature(provider, null).Name
                : "method " + name + Signature(member.DecodeMethodSignature(provider, null)));
        }
        return references.Order(StringComparer.Ordinal).ToArray();
    }

    private static string Signature(MethodSignature<Named> signature) =>
        $" [{signature.Header.RawValue};{signature.GenericParameterCount};{signature.RequiredParameterCount}]" +
        $"({string.Join(",", signature.ParameterTypes.Select(type => type.Name))})->{signature.ReturnType.Name}";

    private readonly record struct Named(string Name, bool Runtime);

    // Assembly scopes, nested owners and constructed generic owners are resolved
    // from metadata. Signatures distinguish overloads, fields, generic arity and
    // static/instance/calling-convention changes; token row numbers are not policy.
    private sealed class Names : ISignatureTypeProvider<Named, object?>
    {
        public Named GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
        {
            TypeReference type = reader.GetTypeReference(handle);
            string name = reader.GetString(type.Name);
            if (type.ResolutionScope.Kind == HandleKind.TypeReference)
            {
                Named parent = GetTypeFromReference(reader, (TypeReferenceHandle)type.ResolutionScope, rawTypeKind);
                return new(parent.Name + "+" + name, parent.Runtime);
            }
            string assembly = type.ResolutionScope.Kind == HandleKind.AssemblyReference
                ? reader.GetString(reader.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope).Name)
                : reader.GetString(reader.GetAssemblyDefinition().Name);
            string ns = reader.GetString(type.Namespace);
            return new($"[{assembly}]{(ns.Length == 0 ? "" : ns + ".")}{name}", assembly == Runtime);
        }

        public Named GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind)
        {
            TypeDefinition type = reader.GetTypeDefinition(handle);
            string name = reader.GetString(type.Name);
            if (!type.GetDeclaringType().IsNil)
            {
                Named parent = GetTypeFromDefinition(reader, type.GetDeclaringType(), rawTypeKind);
                return new(parent.Name + "+" + name, parent.Runtime);
            }
            string assembly = reader.GetString(reader.GetAssemblyDefinition().Name);
            string ns = reader.GetString(type.Namespace);
            return new($"[{assembly}]{(ns.Length == 0 ? "" : ns + ".")}{name}", assembly == Runtime);
        }

        public Named GetTypeFromSpecification(MetadataReader reader, object? genericContext,
            TypeSpecificationHandle handle, byte rawTypeKind) =>
            reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
        public Named GetGenericInstantiation(Named genericType, ImmutableArray<Named> typeArguments) =>
            new(genericType.Name + "<" + string.Join(",", typeArguments.Select(type => type.Name)) + ">", genericType.Runtime);
        public Named GetArrayType(Named elementType, ArrayShape shape) =>
            new($"{elementType.Name}[{shape.Rank};{string.Join(",", shape.Sizes)};{string.Join(",", shape.LowerBounds)}]", elementType.Runtime);
        public Named GetByReferenceType(Named elementType) => new(elementType.Name + "&", elementType.Runtime);
        public Named GetPointerType(Named elementType) => new(elementType.Name + "*", elementType.Runtime);
        public Named GetSZArrayType(Named elementType) => new(elementType.Name + "[]", elementType.Runtime);
        public Named GetPinnedType(Named elementType) => new(elementType.Name + " pinned", elementType.Runtime);
        public Named GetModifiedType(Named modifier, Named unmodifiedType, bool isRequired) =>
            new($"{unmodifiedType.Name} mod{(isRequired ? "req" : "opt")}({modifier.Name})", unmodifiedType.Runtime);
        public Named GetFunctionPointerType(MethodSignature<Named> signature) => new("fn" + Signature(signature), false);
        public Named GetGenericMethodParameter(object? genericContext, int index) => new("!!" + index, false);
        public Named GetGenericTypeParameter(object? genericContext, int index) => new("!" + index, false);
        public Named GetPrimitiveType(PrimitiveTypeCode typeCode) => new(typeCode.ToString(), false);
    }

    [Test]
    [Arguments("method")]
    [Arguments("overload")]
    [Arguments("field")]
    [Arguments("type")]
    [Arguments("nested")]
    [Arguments("generic")]
    public async Task IndependentlyEncodedDisallowedReferenceIsRejected(string variant)
    {
        using var stream = new MemoryStream(Synthetic(variant));
        using var image = new PEReader(stream);
        string[] violations = UnapprovedRuntimeReferences(image.GetMetadataReader());
        await Assert.That(violations.Length > 0).IsTrue();
        await Assert.That(violations.Any(reference => reference.Contains(variant switch
        {
            "field" => "::UnapprovedField:",
            "overload" => "::Defer [0;0;1](Int32)",
            "type" => "UnapprovedRuntimeType",
            "nested" => "+UnapprovedNested",
            "generic" => "<Int32>::UnapprovedMember",
            _ => "::UnapprovedMember"
        }, StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    [Arguments("approved")]
    [Arguments("foreign")]
    public async Task IndependentlyEncodedReviewedOrForeignReferenceIsAccepted(string variant)
    {
        using var stream = new MemoryStream(Synthetic(variant));
        using var image = new PEReader(stream);
        await Assert.That(UnapprovedRuntimeReferences(image.GetMetadataReader())).IsEmpty();
    }

    // A separate in-memory ECMA-335 producer supplies test images. It does not
    // call the scanner or derive expected policy/signatures from scanner output.
    private static byte[] Synthetic(string variant)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(0, metadata.GetOrAddString("DependencyFixture.dll"),
            metadata.GetOrAddGuid(Guid.Empty), default, default);
        metadata.AddAssembly(metadata.GetOrAddString("DependencyFixture"), new Version(1, 0),
            default, default, (AssemblyFlags)0, AssemblyHashAlgorithm.None);
        AssemblyReferenceHandle runtime = metadata.AddAssemblyReference(
            metadata.GetOrAddString(variant == "foreign" ? "Other.Assembly" : Runtime),
            new Version(1, 0), default, default, (AssemblyFlags)0, default);
        TypeReferenceHandle owner = metadata.AddTypeReference(runtime, metadata.GetOrAddString("SecretKit.Infisical"),
            metadata.GetOrAddString(variant == "type" ? "UnapprovedRuntimeType" : "InfisicalDiagnostics"));
        EntityHandle target = owner;
        if (variant == "nested")
            target = metadata.AddTypeReference(owner, default, metadata.GetOrAddString("UnapprovedNested"));
        if (variant == "generic")
        {
            var type = new BlobBuilder();
            new BlobEncoder(type).TypeSpecificationSignature().GenericInstantiation(owner, 1, false).AddArgument().Int32();
            target = metadata.AddTypeSpecification(metadata.GetOrAddBlob(type));
        }
        if (variant == "field")
        {
            var field = new BlobBuilder();
            new BlobEncoder(field).FieldSignature().Int32();
            metadata.AddMemberReference(target, metadata.GetOrAddString("UnapprovedField"), metadata.GetOrAddBlob(field));
        }
        else if (variant != "type")
        {
            AssemblyReferenceHandle system = metadata.AddAssemblyReference(metadata.GetOrAddString("System.Runtime"),
                new Version(10, 0), default, default, (AssemblyFlags)0, default);
            TypeReferenceHandle disposable = metadata.AddTypeReference(system, metadata.GetOrAddString("System"),
                metadata.GetOrAddString("IDisposable"));
            var method = new BlobBuilder();
            new BlobEncoder(method).MethodSignature().Parameters(variant == "overload" ? 1 : 0,
                result => result.Type().Type(disposable, false),
                parameters => { if (variant == "overload") parameters.AddParameter().Type().Int32(); });
            metadata.AddMemberReference(target, metadata.GetOrAddString(
                variant is "approved" or "overload" ? "Defer" : "UnapprovedMember"), metadata.GetOrAddBlob(method));
        }
        metadata.AddTypeDefinition(TypeAttributes.NotPublic, default, metadata.GetOrAddString("<Module>"), default,
            MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
        var pe = new ManagedPEBuilder(new PEHeaderBuilder(imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(metadata), new BlobBuilder(), flags: CorFlags.ILOnly);
        var output = new BlobBuilder();
        pe.Serialize(output);
        return output.ToArray();
    }
}
