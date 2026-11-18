using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class OperatorContractUnionTests
{
    private const string Contract = """
        {"schemaVersion":1,"provenance":["Synthetic consumer"],"exclusions":["Other operations"],
         "shapes":{},"operations":[{
           "id":"widget","method":"post","path":"/widgets","parameters":[],
           "request":{"type":"object","properties":{"value":{"type":"string"}}},
           "status":"200","response":{"type":"object","properties":{"value":{"type":"string"}}}
         }]}
        """;

    private const string Specification = """
        {"openapi":"3.0.3","paths":{"/widgets":{"post":{
          "requestBody":{"content":{"application/json":{"schema":{
            "type":"object","properties":{"value":{"type":"string"}}
          }}}},
          "responses":{"200":{"content":{"application/json":{"schema":{
            "type":"object","properties":{"value":{"type":"string"}}
          }}}}}
        }}}}
        """;

    [Test]
    [Arguments("anyOf", true, """[{"type":"string"},{"type":"number"}]""", 0)]
    [Arguments("oneOf", true, """[{"type":"string"},{"type":"number"}]""", 0)]
    [Arguments("anyOf", true, """[{"type":"boolean"},{"type":"number"}]""", 1)]
    [Arguments("oneOf", true, """[{"type":"boolean"},{"type":"number"}]""", 1)]
    [Arguments("anyOf", false, """[{"type":"string"},{"type":"number"}]""", 1)]
    [Arguments("oneOf", false, """[{"type":"string"},{"type":"number"}]""", 1)]
    public async Task UnionCompatibilityUsesConsumerDirection(string keyword, bool request, string branches, int failures)
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        Shape(spec, request)["properties"]!["value"] = new JsonObject { [keyword] = JsonNode.Parse(branches) };

        var result = Compare(spec, JsonNode.Parse(Contract)!);

        await Assert.That(result.Findings.Count).IsEqualTo(failures);
        if (failures != 0) await Assert.That(result.Findings.Single().Code).IsEqualTo("union");
    }

    [Test]
    [Arguments("anyOf", """[{"type":"string"},{}]""")]
    [Arguments("oneOf", """[{"type":"string"},{}]""")]
    [Arguments("anyOf", """[{"type":"string"},{"type":"string","pattern":"x"}]""")]
    [Arguments("anyOf", """[{"type":"string"},{"$ref":"#/missing"}]""")]
    [Arguments("oneOf", """[{"type":"string"},{"type":"string"}]""")]
    [Arguments("oneOf", """[{"type":"integer"},{"type":"number"}]""")]
    [Arguments("anyOf", "[]")]
    public async Task EveryUnionBranchMustBeEstablishedBeforeSelectingAMatch(string keyword, string branches)
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        Shape(spec, true)["properties"]!["value"] = new JsonObject { [keyword] = JsonNode.Parse(branches) };

        var result = Compare(spec, JsonNode.Parse(Contract)!);

        await Assert.That(result.Findings.Count).IsEqualTo(1);
        await Assert.That(result.Findings[0].Code.StartsWith("unestablished-", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    [Arguments("anyOf")]
    [Arguments("oneOf")]
    public async Task ScalarQueryUnionAcceptsTheDeclaredWireType(string keyword)
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonNode parameter = JsonNode.Parse(
            """{"name":"recursive","in":"query","schema":{"type":"string","enum":["false"]}}""")!;
        contract["operations"]![0]!["parameters"]!.AsArray().Add(parameter.DeepClone());
        parameter["schema"] = new JsonObject
        {
            [keyword] = JsonNode.Parse("""[{"type":"string"},{"type":"boolean"}]""")
        };
        spec["paths"]!["/widgets"]!["post"]!["parameters"] = new JsonArray(parameter);

        await Assert.That(Compare(spec, contract).Findings.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("none", "")]
    [Arguments("removed", "narrowing-unmatched,response-member-removed")]
    [Arguments("base-type", "narrowing-unmatched,type")]
    [Arguments("undeclared", "enum")]
    [Arguments("stale", "narrowing-unmatched")]
    [Arguments("rule-changed", "enum,narrowing-unmatched")]
    public async Task AuditedNarrowingRemainsBoundToAnExistingStrictlyWiderProperty(string change, string codes)
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonNode sdk = contract["operations"]![0]!["response"]!["properties"]!["value"]!;
        sdk["enum"] = new JsonArray("shared");
        contract["operations"]![0]!["narrowings"] = JsonNode.Parse("""
            [{"path":"response.value","sdkRule":{"type":"string","enum":["shared"]},
              "openApiRule":{"type":"string"},"rationale":"Only shared values are selected."}]
            """);
        switch (change)
        {
            case "removed": Shape(spec, false)["properties"]!.AsObject().Remove("value"); break;
            case "base-type": Shape(spec, false)["properties"]!["value"]!["type"] = "boolean"; break;
            case "undeclared": contract["operations"]![0]!.AsObject().Remove("narrowings"); break;
            case "stale": Shape(spec, false)["properties"]!["value"]!["enum"] = new JsonArray("shared"); break;
            case "rule-changed":
                contract["operations"]![0]!["narrowings"]![0]!["sdkRule"]!["enum"] = new JsonArray("personal"); break;
        }

        var result = Compare(spec, contract);

        await Assert.That(string.Join(',', result.Findings.Select(finding => finding.Code).Order(StringComparer.Ordinal)))
            .IsEqualTo(codes);
    }

    [Test]
    public async Task ResponseUnionRequiresCoverageOrAnAuditedSubset()
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        Shape(spec, false)["properties"]!["value"] = JsonNode.Parse(
            """{"anyOf":[{"type":"string"},{"type":"number"}]}""");
        contract["operations"]![0]!["narrowings"] = JsonNode.Parse("""
            [{"path":"response.value","sdkRule":{"type":"string"},
              "openApiRule":{"anyOf":[{"type":"string"},{"type":"number"}]},
              "rationale":"This consumer accepts textual results only."}]
            """);

        await Assert.That(Compare(spec, contract).Findings.Count).IsEqualTo(0);
    }

    [Test]
    public async Task PresenceNarrowingCannotAdmitARemovedRequiredProperty()
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        contract["operations"]![0]!["response"]!["required"] = new JsonArray("value");
        contract["operations"]![0]!["narrowings"] = JsonNode.Parse("""
            [{"path":"response","sdkRule":{"type":"object","required":["value"]},
              "openApiRule":{"type":"object"},"rationale":"The reader requires a value."}]
            """);
        Shape(spec, false)["properties"]!.AsObject().Remove("value");

        var result = Compare(spec, contract);

        await Assert.That(result.Findings.Any(finding => finding.Code == "response-member-removed")).IsTrue();
    }

    [Test]
    public async Task PositiveIntegerRevisionNarrowingChecksEveryBound()
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        Shape(spec, false)["properties"]!["value"] = JsonNode.Parse("""{"type":"number"}""");
        contract["operations"]![0]!["response"]!["properties"]!["value"] = JsonNode.Parse(
            """{"type":"integer","minimum":1,"maximum":2147483647}""");
        contract["operations"]![0]!["narrowings"] = JsonNode.Parse("""
            [{"path":"response.value","sdkRule":{"type":"integer","minimum":1,"maximum":2147483647},
              "openApiRule":{"type":"number"},"rationale":"Only positive Int32 revisions can be represented."}]
            """);

        await Assert.That(Compare(spec, contract).Findings.Count).IsEqualTo(0);
    }

    [Test]
    public async Task PresenceNarrowingAdmitsAnExistingOptionalProperty()
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        contract["operations"]![0]!["response"]!["required"] = new JsonArray("value");
        contract["operations"]![0]!["narrowings"] = JsonNode.Parse("""
            [{"path":"response","sdkRule":{"type":"object","required":["value"]},
              "openApiRule":{"type":"object"},"rationale":"The reader requires the documented value."}]
            """);

        await Assert.That(Compare(spec, contract).Findings.Count).IsEqualTo(0);
    }

    [Test]
    public async Task ReferencedAlternativesAreResolvedBeforeResponseCoverage()
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        spec["components"] = JsonNode.Parse("""{"text":{"type":"string"},"numeric":{"type":"number"}}""");
        Shape(spec, false)["properties"]!["value"] = JsonNode.Parse(
            """{"anyOf":[{"$ref":"#/components/text"},{"$ref":"#/components/numeric"}]}""");
        contract["operations"]![0]!["response"]!["properties"]!["value"] = JsonNode.Parse(
            """{"anyOf":[{"type":"string"},{"type":"number"}]}""");

        await Assert.That(Compare(spec, contract).Findings.Count).IsEqualTo(0);
    }

    [Test]
    public async Task NarrowingCannotLeakIntoAnotherResponseAlternative()
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonNode response = Shape(spec, false);
        response.AsObject().Clear();
        response["anyOf"] = JsonNode.Parse("""
            [{"type":"object","properties":{"value":{"type":"number"}}},
             {"type":"object","properties":{"value":{"type":"boolean"}}}]
            """);
        contract["operations"]![0]!["response"]!["properties"]!["value"] = JsonNode.Parse("""{"type":"integer"}""");
        contract["operations"]![0]!["narrowings"] = JsonNode.Parse("""
            [{"path":"response.value","sdkRule":{"type":"integer"},"openApiRule":{"type":"number"},
              "rationale":"Only integer revisions are accepted."}]
            """);

        var result = Compare(spec, contract);

        await Assert.That(result.Findings.Single().Code).IsEqualTo("union");
    }

    [Test]
    [Arguments(false, 1)]
    [Arguments(true, 0)]
    public async Task NullableNestedAlternativeRequiresAnEstablishedType(bool typed, int findings)
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        Shape(spec, true)["properties"]!["value"] = JsonNode.Parse("""
            {"anyOf":[{"type":"string"},
              {"type":"object","properties":{"hint":{"nullable":true}}}]}
            """);
        if (typed)
            Shape(spec, true)["properties"]!["value"]!["anyOf"]![1]!["properties"]!["hint"]!["type"] = "integer";

        var result = Compare(spec, JsonNode.Parse(Contract)!);

        await Assert.That(result.Findings.Count).IsEqualTo(findings);
        if (findings != 0)
            await Assert.That(result.Findings.Single().Code).IsEqualTo("unestablished-schema");
    }

    private static JsonNode Shape(JsonNode spec, bool request)
    {
        JsonNode operation = spec["paths"]!["/widgets"]!["post"]!;
        return (request ? operation["requestBody"]! : operation["responses"]!["200"]!)["content"]!["application/json"]!["schema"]!;
    }

    private static OperatorContractReport Compare(JsonNode spec, JsonNode contract) =>
        OperatorContractCheck.Compare(JsonSerializer.SerializeToUtf8Bytes(spec), JsonSerializer.SerializeToUtf8Bytes(contract));
}
