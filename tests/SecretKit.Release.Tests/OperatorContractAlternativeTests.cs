using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class OperatorContractAlternativeTests
{
    private const string Contract = """
        {"schemaVersion":1,"provenance":["Synthetic consumer"],"exclusions":["Queued responses"],
         "shapes":{},"operations":[{
           "id":"widget","method":"get","path":"/widgets","parameters":[],
           "excludedAlternatives":[{"location":"response","discriminator":"queued",
             "rationale":"The synthetic reader requires value, not a queued envelope."}],
           "status":"200","response":{"type":"object","required":["value"],
             "properties":{"value":{"type":"string"}}}
         }]}
        """;

    private const string Specification = """
        {"openapi":"3.0.3","paths":{"/widgets":{"get":{
          "responses":{"200":{"content":{"application/json":{"schema":{
            "anyOf":[
              {"type":"object","required":["value"],"properties":{"value":{"type":"string"}}},
              {"type":"object","required":["queued"],"properties":{
                "queued":{"type":"object","properties":{"hint":{"nullable":true}}}}}
            ]
          }}}}}
        }}}}
        """;

    [Test]
    [Arguments("none", false)]
    [Arguments("missing-discriminator", true)]
    [Arguments("consumer-discriminator", true)]
    [Arguments("stale", true)]
    [Arguments("consumed-unestablished", true)]
    [Arguments("ambiguous", true)]
    [Arguments("all-excluded", true)]
    [Arguments("malformed-branch", true)]
    [Arguments("missing-property", true)]
    public async Task AuditedExclusionCannotHideAConsumedOrUnmatchedAlternative(string change, bool fails)
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonArray branches = Response(spec)["anyOf"]!.AsArray();
        switch (change)
        {
            case "missing-discriminator": branches[1]!["required"] = new JsonArray(); break;
            case "consumer-discriminator":
                contract["operations"]![0]!["response"]!["properties"]!["queued"] =
                    JsonNode.Parse("""{"type":"object","properties":{}}""");
                branches[0]!["properties"]!["queued"] = JsonNode.Parse("""{"type":"object","properties":{}}"""); break;
            case "stale": branches.RemoveAt(1); break;
            case "consumed-unestablished":
                branches[0]!["properties"]!["value"] = JsonNode.Parse("""{"nullable":true}"""); break;
            case "ambiguous": branches.Add(branches[1]!.DeepClone()); break;
            case "all-excluded": branches.RemoveAt(0); break;
            case "malformed-branch": branches[1] = "invalid"; break;
            case "missing-property": branches[1]!["properties"]!.AsObject().Clear(); break;
        }

        var result = Compare(spec, contract);

        await Assert.That(result.Findings.Count != 0).IsEqualTo(fails);
        if (change == "consumed-unestablished")
            await Assert.That(result.Findings.Any(finding => finding.Code == "unestablished-schema")).IsTrue();
        if (change == "stale")
            await Assert.That(result.Findings.Any(finding => finding.Code == "excluded-alternative-unmatched")).IsTrue();
        if (change is "consumer-discriminator" or "ambiguous" or "missing-property")
            await Assert.That(result.Findings.Any(finding => finding.Code == "excluded-alternative")).IsTrue();
    }

    [Test]
    public async Task NestedExclusionsStayBoundToTheirExactConsumerLocation()
    {
        JsonNode spec = JsonNode.Parse(Specification)!;
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonNode actual = Response(spec).DeepClone();
        JsonNode expected = contract["operations"]![0]!["response"]!.DeepClone();
        JsonNode wrapper = JsonNode.Parse("""
            {"type":"object","required":["payload"],"properties":{}}
            """)!;
        wrapper["properties"]!["payload"] = actual;
        Response(spec).AsObject().Clear();
        Response(spec)["anyOf"] = new JsonArray(wrapper);
        contract["operations"]![0]!["response"] = JsonNode.Parse("""
            {"type":"object","required":["payload"],"properties":{}}
            """);
        contract["operations"]![0]!["response"]!["properties"]!["payload"] = expected;
        contract["operations"]![0]!["excludedAlternatives"]![0]!["location"] = "response.payload";

        await Assert.That(Compare(spec, contract).Findings.Count).IsEqualTo(0);
    }

    private static JsonNode Response(JsonNode spec) =>
        spec["paths"]!["/widgets"]!["get"]!["responses"]!["200"]!["content"]!["application/json"]!["schema"]!;

    private static OperatorContractReport Compare(JsonNode spec, JsonNode contract) =>
        OperatorContractCheck.Compare(JsonSerializer.SerializeToUtf8Bytes(spec), JsonSerializer.SerializeToUtf8Bytes(contract));
}
