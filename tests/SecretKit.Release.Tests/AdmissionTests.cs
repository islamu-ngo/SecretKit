using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class AdmissionTests
{
    private static Assembly[] NativeAssemblies() =>
    [
        typeof(SecretKit.Infisical.InfisicalClient).Assembly,
        typeof(SecretKit.Infisical.Management.ManagementClient).Assembly,
        typeof(SecretKit.AzureKeyVault.AzureKeyVaultClient).Assembly,
        typeof(SecretKit.AzureKeyVault.Management.VaultAdministration).Assembly
    ];

    private static string RepositoryRoot()
    {
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "SecretKit.slnx")))
            root = root.Parent;
        return root?.FullName ?? throw new InvalidOperationException("Repository root unavailable.");
    }

    private static string InventoryPath(string provider) => Path.Combine(RepositoryRoot(),
        "docs", "internal", "releases", "admission",
        provider == "Infisical" ? "infisical.json" : "azure-key-vault.json");

    private static AdmissionInventory Inventory(string provider) =>
        Manifest.Parse<AdmissionInventory>(File.ReadAllBytes(InventoryPath(provider)));

    private static string[] Members(string provider) => NativeAssemblies()
        .Where(a => a.GetName().Name!.StartsWith("SecretKit." + provider, StringComparison.Ordinal))
        .SelectMany(a => Admission.PublicRemoteMembers(a.Location)).ToArray();

    [Test]
    [Arguments("Infisical")]
    [Arguments("AzureKeyVault")]
    public async Task ActualInventoriesCoverCompiledMembersAndOwningSourceBytes(string provider)
    {
        AdmissionInventory inventory = Inventory(provider);
        string[] members = Members(provider);
        Admission.Validate(inventory, members);
        await Assert.That(inventory.Provider).IsEqualTo(provider);
        await Assert.That(inventory.Operations.Length).IsEqualTo(members.Length);

        // The native assembly references, not cases or inventory contents, select
        // both the member denominator and the complete handwritten source roots.
        string root = RepositoryRoot();
        string[] sourceFiles = NativeAssemblies()
            .Where(a => a.GetName().Name!.StartsWith("SecretKit." + provider, StringComparison.Ordinal))
            .SelectMany(a => Directory.GetFiles(Path.Combine(root, "src", a.GetName().Name!), "*.cs"))
            .Select(file => Path.GetRelativePath(root, file).Replace('\\', '/')).ToArray();
        Manifest.ExactSet(inventory.Sources.Select(s => s.File), sourceFiles, "admission-source-coverage");
        foreach (FileDigest source in inventory.Sources)
        {
            string actual = Manifest.Hash(await File.ReadAllBytesAsync(Path.Combine(root, source.File)));
            await Assert.That(source.Sha256).IsEqualTo(actual);
        }

        using JsonDocument schema = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root,
            "docs", "internal", "releases", "admission", "admission.schema.json")));
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(InventoryPath(provider)));
        ValidateSchema(document.RootElement, schema.RootElement, schema.RootElement);
    }

    [Test]
    [Arguments("Infisical", "omit")]
    [Arguments("AzureKeyVault", "omit")]
    [Arguments("Infisical", "duplicate")]
    [Arguments("AzureKeyVault", "duplicate")]
    [Arguments("Infisical", "foreign")]
    [Arguments("AzureKeyVault", "foreign")]
    public async Task ActualInventoryCannotChangeItsCompiledDenominator(string provider, string fault)
    {
        AdmissionInventory inventory = Inventory(provider);
        AdmissionOperation first = inventory.Operations[0];
        inventory = fault switch
        {
            "omit" => inventory with { Operations = inventory.Operations.Skip(1).ToArray() },
            "duplicate" => inventory with
            {
                Operations = [.. inventory.Operations, first with { Id = first.Id + ".duplicate" }]
            },
            "foreign" => inventory with
            {
                Operations = [first with { Member = "Unexposed.Vendor.Endpoint()" }, .. inventory.Operations.Skip(1)]
            },
            _ => throw new InvalidOperationException()
        };
        await Assert.That(() => Admission.Validate(inventory, Members(provider))).Throws<ReleaseException>();
    }

    [Test]
    [Arguments("unknown-field")]
    [Arguments("placeholder-variant")]
    [Arguments("duplicate-variant")]
    [Arguments("unsafe-source")]
    [Arguments("invalid-hash")]
    [Arguments("empty-cases")]
    [Arguments("long-id")]
    [Arguments("wrong-policy")]
    public async Task ActualSchemaRejectsMalformedInventoryContracts(string fault)
    {
        JsonNode document = JsonNode.Parse(File.ReadAllBytes(InventoryPath("Infisical")))!;
        JsonNode operation = document["operations"]![0]!;
        switch (fault)
        {
            case "unknown-field": operation["passed"] = true; break;
            case "placeholder-variant": operation["variants"] = new JsonArray("native"); break;
            case "duplicate-variant": operation["variants"] = new JsonArray("same", "same"); break;
            case "unsafe-source": document["sources"]![0]!["file"] = "src/../historical.cs"; break;
            case "invalid-hash": document["sources"]![0]!["sha256"] = "not-a-hash"; break;
            case "empty-cases": operation["requiredCases"] = new JsonArray(); break;
            case "long-id": operation["id"] = new string('a', 129); break;
            case "wrong-policy": document["policy"] = "offline-only"; break;
            default: throw new InvalidOperationException();
        }
        using JsonDocument schema = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(RepositoryRoot(),
            "docs", "internal", "releases", "admission", "admission.schema.json")));
        using JsonDocument changed = JsonDocument.Parse(document.ToJsonString());
        await Assert.That(() => ValidateSchema(changed.RootElement, schema.RootElement, schema.RootElement))
            .Throws<InvalidDataException>();
    }

    [Test]
    public void DeclaredDiscriminatorsRemainIndependentOfPassingCases()
    {
        AdmissionInventory infisical = Inventory("Infisical");
        AdmissionInventory azure = Inventory("AzureKeyVault");
        foreach (string method in new[] { "CreateDefinitionAsync", "UpdateDefinitionAsync",
            "ListDefinitionsAsync", "InspectDefinitionAsync", "DeleteDefinitionAsync",
            "ListLeasesAsync", "InspectLeaseAsync", "RenewLeaseAsync", "RevokeLeaseAsync" })
            RequireVariants(infisical, "InfisicalDynamicClient." + method,
                Enum.GetNames<SecretKit.Infisical.InfisicalDynamicProvider>().Select(v => "profile." + v));
        foreach (string method in new[] { "CreateDefinitionAsync", "UpdateDefinitionAsync",
            "AcquireDatabaseAsync", "RenewAsync", "RevokeAsync" })
            RequireVariants(infisical, "InfisicalDynamicClient." + method,
                Enum.GetNames<SecretKit.Infisical.NativeSqlEngine>().Select(v => "SqlDatabase.engine." + v));
        foreach (string method in new[] { "ListAsync", "GetAsync", "RotateSecretsAsync", "SetAutomaticRotationAsync" })
            RequireVariants(infisical, "InfisicalRotationClient." + method,
                Enum.GetNames<SecretKit.Infisical.InfisicalRotationProfile>().Select(v => "profile." + v));
        foreach (string method in new[] { "CreateOrUpdateNotificationAsync", "UpdateNotificationAsync" })
            RequireVariants(azure, "VaultAdministration." + method,
                Enum.GetNames<SecretKit.AzureKeyVault.Management.VaultNotificationEvent>().Select(v => "event." + v));
        RequireVariants(azure, "VaultAdministration.ChangeAccessPoliciesAsync",
            Enum.GetNames<SecretKit.AzureKeyVault.Management.SecretPermission>().Select(v => "permission." + v));
        RequireVariants(infisical, "ManagementClient.ExecuteAsync", infisical.Operations
            .Where(o => o.Member.StartsWith("SecretKit.Infisical.Management.", StringComparison.Ordinal) &&
                !o.Member.Contains(".ManagementClient.", StringComparison.Ordinal)).Select(o => "factory." + o.Id));
    }

    private static void RequireVariants(AdmissionInventory inventory, string member, IEnumerable<string> variants)
    {
        AdmissionOperation operation = inventory.Operations.Single(o =>
            o.Member.Contains("." + member + "(", StringComparison.Ordinal));
        if (variants.Except(operation.Variants, StringComparer.Ordinal).Any())
            throw new InvalidDataException("Missing declared discriminator: " + operation.Id);
    }

    // Evaluate the deliberately small schema vocabulary used by the admission
    // file. Unsupported validation keywords fail the test rather than silently
    // treating a future schema extension as checked. No schema package needed.
    private static void ValidateSchema(JsonElement value, JsonElement schema, JsonElement root)
    {
        string[] keywords = ["$schema", "title", "$defs", "$ref", "type", "const", "enum", "properties",
            "required", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems",
            "minLength", "maxLength", "pattern"];
        if (schema.EnumerateObject().Any(p => !keywords.Contains(p.Name, StringComparer.Ordinal)))
            throw new InvalidDataException("Unsupported admission schema keyword.");
        if (schema.TryGetProperty("$ref", out JsonElement reference))
        {
            string[] path = reference.GetString()!.Split('/');
            if (path.Length != 3 || path[0] != "#" || path[1] != "$defs")
                throw new InvalidDataException("Unsupported admission schema reference.");
            ValidateSchema(value, root.GetProperty("$defs").GetProperty(path[2]), root);
            return;
        }
        void Require(bool condition)
        {
            if (!condition) throw new InvalidDataException("Admission schema mismatch.");
        }
        if (schema.TryGetProperty("const", out JsonElement constant))
            Require(JsonElement.DeepEquals(value, constant));
        if (schema.TryGetProperty("enum", out JsonElement choices))
            Require(choices.EnumerateArray().Any(choice => JsonElement.DeepEquals(value, choice)));
        if (schema.TryGetProperty("type", out JsonElement type))
            Require(type.GetString() switch
            {
                "object" => value.ValueKind == JsonValueKind.Object,
                "array" => value.ValueKind == JsonValueKind.Array,
                "string" => value.ValueKind == JsonValueKind.String,
                _ => throw new InvalidDataException("Unsupported admission schema type.")
            });
        if (value.ValueKind == JsonValueKind.Object)
        {
            JsonProperty[] properties = value.EnumerateObject().ToArray();
            Require(properties.Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() == properties.Length);
            if (schema.TryGetProperty("required", out JsonElement required))
                foreach (JsonElement name in required.EnumerateArray())
                    Require(value.TryGetProperty(name.GetString()!, out _));
            if (schema.TryGetProperty("properties", out JsonElement expected))
                foreach (JsonProperty property in properties)
                {
                    if (expected.TryGetProperty(property.Name, out JsonElement child))
                        ValidateSchema(property.Value, child, root);
                    else Require(!schema.TryGetProperty("additionalProperties", out JsonElement additional) ||
                        additional.ValueKind != JsonValueKind.False);
                }
        }
        if (value.ValueKind == JsonValueKind.Array)
        {
            JsonElement[] items = value.EnumerateArray().ToArray();
            if (schema.TryGetProperty("minItems", out JsonElement minimum)) Require(items.Length >= minimum.GetInt32());
            if (schema.TryGetProperty("maxItems", out JsonElement maximum)) Require(items.Length <= maximum.GetInt32());
            if (schema.TryGetProperty("uniqueItems", out JsonElement unique) && unique.GetBoolean())
                for (int index = 0; index < items.Length; index++)
                    Require(!items.Take(index).Any(previous => JsonElement.DeepEquals(previous, items[index])));
            if (schema.TryGetProperty("items", out JsonElement itemSchema))
                foreach (JsonElement item in items) ValidateSchema(item, itemSchema, root);
        }
        if (value.ValueKind == JsonValueKind.String)
        {
            string text = value.GetString()!;
            if (schema.TryGetProperty("minLength", out JsonElement minimum)) Require(text.Length >= minimum.GetInt32());
            if (schema.TryGetProperty("maxLength", out JsonElement maximum)) Require(text.Length <= maximum.GetInt32());
            if (schema.TryGetProperty("pattern", out JsonElement pattern))
                Require(Regex.IsMatch(text, pattern.GetString()!, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)));
        }
    }

    private static AdmissionInventory Example() => new(1, "current-admission", "Infisical",
        "complete-live", [new("src/SecretKit.Infisical/InfisicalClient.cs", new string('a', 64))],
        [new("read", "SecretKit.Infisical.InfisicalClient.ReadAsync", ["selected-version"],
            "implemented-subset", "Selected-authority owned material, not metadata-only visibility.",
            ["read-effect", "denied-read"], ["owned-environment", "runtime-identity", "observer-identity"])],
        ["Removed third-party connection/sync catalog; no callable compatibility aliases."]);

    [Test]
    public void CurrentAdmissionIsIndependentOfHistoricalResearchOrPassingCases()
    {
        AdmissionInventory inventory = Example();
        Admission.Validate(inventory, ["SecretKit.Infisical.InfisicalClient.ReadAsync"]);
    }

    [Test]
    [Arguments("historical")]
    [Arguments("omitted")]
    [Arguments("duplicate")]
    [Arguments("variant")]
    [Arguments("depth")]
    [Arguments("source")]
    [Arguments("missing-effect")]
    public async Task CurrentAdmissionRejectsOmissionsAndMisrepresentedContracts(string fault)
    {
        AdmissionInventory inventory = Example();
        string[] members = ["SecretKit.Infisical.InfisicalClient.ReadAsync"];
        inventory = fault switch
        {
            "historical" => inventory with { Kind = "ContractResearchOnly" },
            "omitted" => inventory with { Operations = [] },
            "duplicate" => inventory with { Operations = [inventory.Operations[0], inventory.Operations[0]] },
            "variant" => inventory with { Operations = [inventory.Operations[0] with { Variants = ["same", "same"] }] },
            "depth" => inventory with { Policy = "offline-only" },
            "source" => inventory with { Sources = [new("../historical.json", new string('a', 64))] },
            "missing-effect" => inventory with { Operations = [inventory.Operations[0] with { Effect = "" }] },
            _ => throw new InvalidOperationException()
        };
        await Assert.That(() => Admission.Validate(inventory, members)).Throws<ReleaseException>();
        if (fault == "omitted")
        {
            await Assert.That(() => Admission.Validate(Example(), [.. members, "Retained.UncoveredOperation"]))
                .Throws<ReleaseException>();
        }
    }

    [Test]
    public async Task CompiledRemoteMemberDenominatorIsRecordedBeforeEvidence()
    {
        var assemblies = new[]
        {
            typeof(SecretKit.Infisical.InfisicalClient).Assembly,
            typeof(SecretKit.Infisical.Management.ManagementClient).Assembly,
            typeof(SecretKit.AzureKeyVault.AzureKeyVaultClient).Assembly,
            typeof(SecretKit.AzureKeyVault.Management.VaultAdministration).Assembly
        };
        var inventory = assemblies.ToDictionary(a => a.GetName().Name!,
            a => Admission.PublicRemoteMembers(a.Location), StringComparer.Ordinal);
        foreach (var family in inventory)
        {
            await Assert.That(family.Value.Length > 0).IsTrue();
            await Assert.That(family.Value.Distinct(StringComparer.Ordinal).Count()).IsEqualTo(family.Value.Length);
            await Assert.That(family.Value.SequenceEqual(Admission.PublicRemoteMembers(
                assemblies.Single(a => a.GetName().Name == family.Key).Location))).IsTrue();
        }
        await Assert.That(inventory["SecretKit.Infisical"].Any(m => m.Contains(".AcquireDatabaseAsync(", StringComparison.Ordinal))).IsTrue();
        await Assert.That(inventory["SecretKit.Infisical.Management"].Any(m => m.Contains("Gateway", StringComparison.Ordinal))).IsTrue();
        await Assert.That(inventory["SecretKit.Infisical.Management"].Any(m => m.Contains("SecretRotation", StringComparison.Ordinal))).IsTrue();
        await Assert.That(inventory["SecretKit.AzureKeyVault.Management"].Any(m => m.Contains(".QueryBatchAsync(", StringComparison.Ordinal))).IsTrue();
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "SecretKit.slnx")))
            root = root.Parent;
        if (root is null)
            throw new InvalidOperationException("Repository root unavailable.");
        string evidence = Path.Combine(root.FullName, "dev", "active", "provider-engineering", "evidence");
        Directory.CreateDirectory(evidence);
        await File.WriteAllBytesAsync(Path.Combine(evidence, "compiled-remote-members.json"),
            JsonSerializer.SerializeToUtf8Bytes(inventory, Manifest.JsonOptions));
    }
}
