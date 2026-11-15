using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class OperatorContractCheckTests
{
    // Independent, synthetic interface: no provider schema or implementation is used.
    private const string Contract = """
        {
          "schemaVersion": 1,
          "provenance": ["Synthetic consumer contract"],
          "exclusions": ["All other operations"],
          "shapes": {},
          "operations": [{
            "id": "widget-update", "method": "patch", "path": "/widgets/{id}",
            "parameters": [
              {"name":"id","in":"path","required":true,"schema":{"type":"string"}},
              {"name":"scope","in":"query","required":true,"schema":{"type":"string"}},
              {"name":"revision","in":"query","required":false,"schema":{"type":"integer"}}
            ],
            "request": {
              "type":"object","required":["name"],
              "properties":{"name":{"type":"string"},"note":{"type":"string","nullable":true}}
            },
            "status":"200",
            "response": {
              "type":"object","required":["widget"],
              "properties":{"widget":{"type":"object","required":["id","version"],
                "properties":{"id":{"type":"string"},"version":{"type":"integer"},
                  "label":{"type":"string","nullable":true}}}}
            }
          }]
        }
        """;

    private const string Specification = """
        {
          "openapi":"3.0.3",
          "paths":{"/widgets/{id}":{
            "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
            "patch":{
              "parameters":[
                {"name":"scope","in":"query","required":true,"schema":{"type":"string"}},
                {"name":"revision","in":"query","required":false,"schema":{"type":"integer"}}
              ],
              "requestBody":{"required":true,"content":{"application/json":{"schema":{
                "type":"object","required":["name"],
                "properties":{"name":{"type":"string"},"note":{"type":"string","nullable":true}}
              }}}},
              "responses":{"200":{"description":"Synthetic result","content":{"application/json":{"schema":{
                "type":"object","required":["widget"],
                "properties":{"widget":{"type":"object","required":["id","version"],
                  "properties":{"id":{"type":"string"},"version":{"type":"integer"},
                    "label":{"type":"string","nullable":true}}}}
              }}}}}
            }
          }}
        }
        """;

    [Test]
    public async Task MatchingContractChecksInheritedParametersAndResponseEnvelope()
    {
        var result = Compare(Spec());

        await Assert.That(result.Findings.Count).IsEqualTo(0);
        await Assert.That(result.CheckedOperations).IsEqualTo(1);
        await Assert.That(result.SpecSha256).IsEqualTo(Manifest.Hash(Bytes(Spec())));
    }

    [Test]
    [Arguments("path", "path-removed")]
    [Arguments("method", "method-removed")]
    [Arguments("parameter-removed", "parameter-removed")]
    [Arguments("parameter-type", "type")]
    [Arguments("parameter-required", "request-required")]
    [Arguments("new-parameter", "request-required")]
    [Arguments("body-member", "request-required")]
    [Arguments("optional-member-required", "request-required")]
    [Arguments("response-type", "type")]
    [Arguments("response-removed", "response-member-removed")]
    [Arguments("response-optional", "response-required")]
    [Arguments("response-nullable", "nullable")]
    [Arguments("request-nullability", "nullable")]
    [Arguments("response-envelope", "type")]
    [Arguments("response-status", "response-removed")]
    [Arguments("request-media", "json-media")]
    public async Task IncompatibleChangesProduceClosedDrift(string change, string expectedCode)
    {
        JsonNode spec = Spec();
        JsonNode operation = Operation(spec);
        JsonNode request = Request(spec);
        JsonNode widget = Response(spec)["properties"]!["widget"]!;
        switch (change)
        {
            case "path": spec["paths"]!.AsObject().Clear(); break;
            case "method": spec["paths"]!["/widgets/{id}"]!.AsObject().Remove("patch"); break;
            case "parameter-removed": operation["parameters"]!.AsArray().RemoveAt(0); break;
            case "parameter-type": operation["parameters"]![0]!["schema"]!["type"] = "number"; break;
            case "parameter-required": operation["parameters"]![1]!["required"] = true; break;
            case "new-parameter":
                operation["parameters"]!.AsArray().Add(JsonNode.Parse(
                    """{"name":"new","in":"header","required":true,"schema":{"type":"string"}}""")); break;
            case "body-member":
                request["properties"]!["new"] = JsonNode.Parse("""{"type":"string"}""");
                request["required"]!.AsArray().Add("new"); break;
            case "optional-member-required": request["required"]!.AsArray().Add("note"); break;
            case "response-type": widget["properties"]!["version"]!["type"] = "string"; break;
            case "response-removed": widget["properties"]!.AsObject().Remove("label"); break;
            case "response-optional": widget["required"]!.AsArray().RemoveAt(1); break;
            case "response-nullable": widget["properties"]!["id"]!["nullable"] = true; break;
            case "request-nullability": request["properties"]!["note"]!["nullable"] = false; break;
            case "response-envelope":
                Response(spec).AsObject().Clear();
                Response(spec)["type"] = "string"; break;
            case "response-status": operation["responses"]!.AsObject().Clear(); break;
            case "request-media": operation["requestBody"]!["content"]!.AsObject().Clear(); break;
        }

        var result = Compare(spec);

        await Assert.That(result.Findings.Any(finding => finding.Code == expectedCode &&
            finding.Operation == "widget-update")).IsTrue();
    }

    [Test]
    [Arguments("unrelated-operation")]
    [Arguments("optional-request")]
    [Arguments("optional-response")]
    [Arguments("required-response")]
    [Arguments("request-relaxed")]
    [Arguments("response-nonnullable")]
    [Arguments("path-label")]
    [Arguments("operation-override")]
    public async Task CompatibleChangesDoNotReportDrift(string change)
    {
        JsonNode spec = Spec();
        switch (change)
        {
            case "unrelated-operation":
                spec["paths"]!["/unrelated"] = JsonNode.Parse(
                    """{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"oneOf":[]}}}}}}}""");
                break;
            case "optional-request": Request(spec)["properties"]!["extra"] = JsonNode.Parse("""{"type":"string"}"""); break;
            case "optional-response": Response(spec)["properties"]!["extra"] = JsonNode.Parse("""{"oneOf":[]}"""); break;
            case "required-response":
                Response(spec)["properties"]!["extra"] = JsonNode.Parse("""{"type":"string"}""");
                Response(spec)["required"]!.AsArray().Add("extra"); break;
            case "request-relaxed": Request(spec)["required"] = new JsonArray(); break;
            case "response-nonnullable":
                Response(spec)["properties"]!["widget"]!["properties"]!["label"]!["nullable"] = false; break;
            case "path-label":
                JsonNode path = spec["paths"]!["/widgets/{id}"]!.DeepClone();
                path["parameters"]![0]!["name"] = "widgetId";
                spec["paths"]!.AsObject().Clear();
                spec["paths"]!["/widgets/{widgetId}"] = path; break;
            case "operation-override":
                spec["paths"]!["/widgets/{id}"]!["parameters"]!.AsArray().Add(
                    JsonNode.Parse("""{"name":"scope","in":"query","required":true,"schema":{"type":"number"}}"""));
                break;
        }

        await Assert.That(Compare(spec).Findings.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("oneOf")]
    [Arguments("allOf")]
    [Arguments("anyOf")]
    [Arguments("not")]
    [Arguments("unknownKeyword")]
    public async Task UnknownRelevantSchemaConstructNeverCountsAsMatch(string keyword)
    {
        JsonNode spec = Spec();
        Response(spec)["properties"]!["widget"]![keyword] = new JsonArray();

        var result = Compare(spec);

        await Assert.That(result.Findings.Single().Code).IsEqualTo("unestablished-schema");
    }

    [Test]
    [Arguments("duplicate-parameter", "unestablished-parameter")]
    [Arguments("ambiguous-path", "unestablished-path")]
    [Arguments("parameter-content", "unestablished-parameter")]
    [Arguments("parameter-object", "unestablished-parameter")]
    [Arguments("schema-less", "unestablished-schema")]
    [Arguments("ref-sibling", "unestablished-reference")]
    [Arguments("external", "unestablished-reference")]
    [Arguments("local-file", "unestablished-reference")]
    [Arguments("dangling", "unestablished-reference")]
    [Arguments("cycle", "unestablished-reference-cycle")]
    [Arguments("recursive-shape", "unestablished-reference-cycle")]
    public async Task AmbiguousOrUnsafeDefinitionsFailClosed(string change, string code)
    {
        JsonNode spec = Spec();
        switch (change)
        {
            case "duplicate-parameter":
                Operation(spec)["parameters"]!.AsArray().Add(Operation(spec)["parameters"]![0]!.DeepClone()); break;
            case "ambiguous-path":
                spec["paths"]!["/widgets/{other}"] = spec["paths"]!["/widgets/{id}"]!.DeepClone(); break;
            case "parameter-content": Operation(spec)["parameters"]![0]!["content"] = new JsonObject(); break;
            case "parameter-object":
                Operation(spec)["parameters"]![0]!["schema"] = JsonNode.Parse("""{"type":"object","properties":{}}"""); break;
            case "schema-less": Request(spec)["properties"]!["name"] = new JsonObject(); break;
            case "ref-sibling":
                Request(spec)["$ref"] = "#/components/schemas/body"; break;
            case "external":
                RequestContainer(spec)["schema"] = JsonNode.Parse("""{"$ref":"https://invalid.example/spec.json#/body"}"""); break;
            case "local-file":
                RequestContainer(spec)["schema"] = JsonNode.Parse("""{"$ref":"other.json#/body"}"""); break;
            case "dangling":
                RequestContainer(spec)["schema"] = JsonNode.Parse("""{"$ref":"#/missing"}"""); break;
            case "cycle":
                spec["components"] = JsonNode.Parse("""{"schemas":{"body":{"$ref":"#/components/schemas/body"}}}""");
                RequestContainer(spec)["schema"] = JsonNode.Parse("""{"$ref":"#/components/schemas/body"}"""); break;
            case "recursive-shape":
                spec["components"] = new JsonObject { ["schemas"] = new JsonObject { ["body"] = Request(spec).DeepClone() } };
                spec["components"]!["schemas"]!["body"]!["properties"]!["name"] =
                    JsonNode.Parse("""{"$ref":"#/components/schemas/body"}""");
                RequestContainer(spec)["schema"] = JsonNode.Parse("""{"$ref":"#/components/schemas/body"}"""); break;
        }

        await Assert.That(Compare(spec).Findings.Single().Code).IsEqualTo(code);
    }

    [Test]
    public async Task LocalPointersResolveEscapedNamesAndReferencedWrappers()
    {
        JsonNode spec = Spec();
        JsonNode operation = Operation(spec);
        spec["components"] = new JsonObject
        {
            ["a/b~c"] = Request(spec).DeepClone(),
            ["response"] = operation["responses"]!["200"]!.DeepClone(),
            ["parameter"] = operation["parameters"]![0]!.DeepClone()
        };
        RequestContainer(spec)["schema"] = JsonNode.Parse("""{"$ref":"#/components/a~1b~0c"}""");
        operation["responses"]!["200"] = JsonNode.Parse("""{"$ref":"#/components/response"}""");
        operation["parameters"]![0] = JsonNode.Parse("""{"$ref":"#/components/parameter"}""");

        await Assert.That(Compare(spec).Findings.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(32, 0)]
    [Arguments(33, 1)]
    public async Task ReferenceDepthHasAnExactBoundary(int depth, int failures)
    {
        JsonNode spec = Spec();
        var definitions = new JsonObject();
        spec["components"] = definitions;
        for (int index = 0; index < depth; index++)
            definitions["r" + index] = index == depth - 1 ? Request(spec).DeepClone() :
                new JsonObject { ["$ref"] = "#/components/r" + (index + 1) };
        RequestContainer(spec)["schema"] = new JsonObject { ["$ref"] = "#/components/r0" };

        var result = Compare(spec);

        await Assert.That(result.Findings.Count).IsEqualTo(failures);
        if (failures != 0)
            await Assert.That(result.Findings.Single().Code).IsEqualTo("unestablished-reference-depth");
    }

    [Test]
    [Arguments(4096, 0)]
    [Arguments(4097, 1)]
    public async Task ReferenceCountIncludesRepeatedResolution(int count, int failures)
    {
        JsonNode spec = Spec();
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonNode body = Request(spec);
        body["required"] = new JsonArray();
        body["properties"] = new JsonObject();
        JsonNode expected = contract["operations"]![0]!["request"]!;
        expected["required"] = new JsonArray();
        expected["properties"] = new JsonObject();
        spec["components"] = JsonNode.Parse("""{"scalar":{"type":"string"}}""");
        for (int index = 0; index < count; index++)
        {
            body["properties"]!["p" + index] = new JsonObject { ["$ref"] = "#/components/scalar" };
            expected["properties"]!["p" + index] = new JsonObject { ["type"] = "string" };
        }

        var result = OperatorContractCheck.Compare(Bytes(spec), Bytes(contract));

        await Assert.That(result.Findings.Count).IsEqualTo(failures);
        if (failures != 0)
            await Assert.That(result.Findings.Single().Code).IsEqualTo("unestablished-reference-limit");
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task InputByteLimitAllowsExactlyThirtyTwoMiB(int excess)
    {
        byte[] spec = Encoding.UTF8.GetBytes(Specification);
        byte[] padded = new byte[32 * 1024 * 1024 + excess];
        padded.AsSpan().Fill((byte)' ');
        spec.CopyTo(padded, 0);

        if (excess == 0)
            await Assert.That(OperatorContractCheck.Compare(padded, Encoding.UTF8.GetBytes(Contract)).Findings.Count).IsEqualTo(0);
        else
            await Assert.That(() => OperatorContractCheck.Compare(padded, Encoding.UTF8.GetBytes(Contract)))
                .Throws<ReleaseException>().WithMessage("operator-input-size");
    }

    [Test]
    [Arguments(64, false)]
    [Arguments(65, true)]
    public async Task JsonNestingHasAnExactBoundary(int depth, bool rejected)
    {
        string nested = new('[', depth - 1);
        string suffix = new(']', depth - 1);
        byte[] spec = Encoding.UTF8.GetBytes(Specification.TrimEnd()[..^1] + ",\"unused\":" + nested + "0" + suffix + "}");

        if (rejected)
            await Assert.That(() => OperatorContractCheck.Compare(spec, Encoding.UTF8.GetBytes(Contract)))
                .Throws<ReleaseException>().WithMessage("operator-json");
        else
            await Assert.That(OperatorContractCheck.Compare(spec, Encoding.UTF8.GetBytes(Contract)).Findings.Count).IsEqualTo(0);
    }

    [Test]
    public async Task DuplicateJsonPropertiesCannotSilentlyReplaceAContract()
    {
        byte[] spec = Encoding.UTF8.GetBytes(Specification.Replace("\"openapi\":\"3.0.3\"",
            "\"openapi\":\"3.0.3\",\"openapi\":\"3.0.3\"", StringComparison.Ordinal));

        await Assert.That(() => OperatorContractCheck.Compare(spec, Encoding.UTF8.GetBytes(Contract)))
            .Throws<ReleaseException>().WithMessage("operator-json-duplicate");
    }

    [Test]
    [Arguments(true, true, 1)]
    [Arguments(true, false, 0)]
    [Arguments(false, true, 0)]
    [Arguments(false, false, 1)]
    public async Task EnumCompatibilityUsesConsumerDirection(bool request, bool narrowActual, int failures)
    {
        JsonNode spec = Spec();
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonNode actual = request ? Request(spec)["properties"]!["name"]! :
            Response(spec)["properties"]!["widget"]!["properties"]!["id"]!;
        JsonNode expected = request ? contract["operations"]![0]!["request"]!["properties"]!["name"]! :
            contract["operations"]![0]!["response"]!["properties"]!["widget"]!["properties"]!["id"]!;
        actual["enum"] = narrowActual ? new JsonArray("a") : new JsonArray("a", "b");
        expected["enum"] = narrowActual ? new JsonArray("a", "b") : new JsonArray("a");

        var result = OperatorContractCheck.Compare(Bytes(spec), Bytes(contract));

        await Assert.That(result.Findings.Count).IsEqualTo(failures);
        if (failures != 0) await Assert.That(result.Findings.Single().Code).IsEqualTo("enum");
    }

    [Test]
    [Arguments(true, 1, 0)]
    [Arguments(true, 3, 1)]
    [Arguments(false, 1, 1)]
    [Arguments(false, 3, 0)]
    public async Task PrimitiveBoundsUseConsumerDirection(bool request, int actualMinimum, int failures)
    {
        JsonNode spec = Spec();
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonNode actual = request ? Request(spec)["properties"]!["name"]! :
            Response(spec)["properties"]!["widget"]!["properties"]!["id"]!;
        JsonNode expected = request ? contract["operations"]![0]!["request"]!["properties"]!["name"]! :
            contract["operations"]![0]!["response"]!["properties"]!["widget"]!["properties"]!["id"]!;
        actual["minLength"] = actualMinimum;
        expected["minLength"] = 2;

        var result = OperatorContractCheck.Compare(Bytes(spec), Bytes(contract));

        await Assert.That(result.Findings.Count).IsEqualTo(failures);
        if (failures != 0) await Assert.That(result.Findings.Single().Code).IsEqualTo("constraint");
    }

    [Test]
    [Arguments(true, "integer", "number", 0)]
    [Arguments(true, "number", "integer", 1)]
    [Arguments(false, "integer", "number", 1)]
    [Arguments(false, "number", "integer", 0)]
    public async Task IntegerAndNumberCompatibilityUsesConsumerDirection(bool request, string expectedType,
        string actualType, int failures)
    {
        JsonNode spec = Spec();
        JsonNode contract = JsonNode.Parse(Contract)!;
        JsonNode actual = request ? Request(spec)["properties"]!["name"]! :
            Response(spec)["properties"]!["widget"]!["properties"]!["id"]!;
        JsonNode expected = request ? contract["operations"]![0]!["request"]!["properties"]!["name"]! :
            contract["operations"]![0]!["response"]!["properties"]!["widget"]!["properties"]!["id"]!;
        actual["type"] = actualType;
        expected["type"] = expectedType;

        var result = OperatorContractCheck.Compare(Bytes(spec), Bytes(contract));

        await Assert.That(result.Findings.Count).IsEqualTo(failures);
        if (failures != 0) await Assert.That(result.Findings.Single().Code).IsEqualTo("type");
    }

    [Test]
    [Arguments("""{"type":"string","enum":[1]}""")]
    [Arguments("""{"type":"string","minLength":4,"maxLength":2}""")]
    [Arguments("""{"type":"string","nullable":"true"}""")]
    [Arguments("""{"type":"string","format":"float"}""")]
    [Arguments("""{"type":"object","properties":{},"additionalProperties":{"type":"string"}}""")]
    public async Task MalformedRelevantConstraintsNeverCountAsMatches(string shape)
    {
        JsonNode spec = Spec();
        Request(spec)["properties"]!["name"] = JsonNode.Parse(shape);

        await Assert.That(Compare(spec).Findings.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(false, 0)]
    [Arguments(true, 1)]
    public async Task RealCommandWorksWithoutReleaseAuthorityAndNeverWritesArtifacts(bool drift, int expectedExit)
    {
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-operator-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(directory, "docs", "internal"));
        string contractPath = Path.Combine(directory, OperatorContractCheck.ManifestPath);
        string specPath = Path.Combine(directory, "spec.json");
        try
        {
            await File.WriteAllTextAsync(contractPath, Contract);
            JsonNode spec = Spec();
            if (drift) spec["paths"]!.AsObject().Clear();
            await File.WriteAllBytesAsync(specPath, Bytes(spec));
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = directory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            start.ArgumentList.Add(typeof(Program).Assembly.Location);
            start.ArgumentList.Add("operator-contract-check");
            start.ArgumentList.Add(specPath);
            foreach (string key in start.Environment.Keys.Where(key =>
                key.StartsWith("SECRETKIT_", StringComparison.Ordinal) || key == "NUGET_API_KEY").ToArray())
                start.Environment.Remove(key);
            using Process process = Process.Start(start)!;
            Task<string> output = process.StandardOutput.ReadToEndAsync();
            Task<string> error = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try { await process.WaitForExitAsync(timeout.Token); }
            finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }

            await Assert.That(process.ExitCode).IsEqualTo(expectedExit);
            await Assert.That(await error).IsEqualTo("");
            await Assert.That((await output).Contains("operator-contract-checked:1:findings:" +
                (drift ? "1" : "0"), StringComparison.Ordinal)).IsTrue();
            await Assert.That(Directory.GetFiles(directory, "*", SearchOption.AllDirectories).Length).IsEqualTo(2);
            await Assert.That(await File.ReadAllTextAsync(contractPath)).IsEqualTo(Contract);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Test]
    [Arguments(false, 0)]
    [Arguments(true, 1)]
    public async Task ActualRevocationManifestRejectsAnAdditionalResponseMember(bool extra, int findings)
    {
        DirectoryInfo? root = new(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "SecretKit.slnx"))) root = root.Parent;
        JsonNode manifest = JsonNode.Parse(await File.ReadAllBytesAsync(Path.Combine(
            root?.FullName ?? throw new InvalidOperationException("Repository root unavailable."), OperatorContractCheck.ManifestPath)))!;
        JsonNode operation = manifest["operations"]!.AsArray().Single(row => row!["id"]!.GetValue<string>() == "token-revoke")!;
        manifest["operations"] = new JsonArray(operation.DeepClone());
        JsonNode spec = JsonNode.Parse("""
            {"openapi":"3.0.3","paths":{"/api/v1/auth/token/revoke":{"post":{
              "requestBody":{"required":true,"content":{"application/json":{"schema":{
                "type":"object","required":["accessToken"],"properties":{"accessToken":{"type":"string"}}}}}},
              "responses":{"200":{"content":{"application/json":{"schema":{
                "type":"object","required":["message"],"additionalProperties":false,
                "properties":{"message":{"type":"string"}}}}}}}
            }}}}
            """)!;
        if (extra)
            spec["paths"]!["/api/v1/auth/token/revoke"]!["post"]!["responses"]!["200"]!["content"]!["application/json"]!["schema"]!["properties"]!["extra"] =
                JsonNode.Parse("""{"type":"boolean"}""");

        var result = OperatorContractCheck.Compare(Bytes(spec), Bytes(manifest));

        await Assert.That(result.Findings.Count).IsEqualTo(findings);
        if (extra) await Assert.That(result.Findings.Single().Code).IsEqualTo("response-additional-properties");
    }

    private static JsonNode Spec() => JsonNode.Parse(Specification)!;
    private static JsonNode Operation(JsonNode spec) => spec["paths"]!["/widgets/{id}"]!["patch"]!;
    private static JsonNode RequestContainer(JsonNode spec) => Operation(spec)["requestBody"]!["content"]!["application/json"]!;
    private static JsonNode Request(JsonNode spec) => RequestContainer(spec)["schema"]!;
    private static JsonNode Response(JsonNode spec) => Operation(spec)["responses"]!["200"]!["content"]!["application/json"]!["schema"]!;
    private static byte[] Bytes(JsonNode node) => JsonSerializer.SerializeToUtf8Bytes(node);
    private static OperatorContractReport Compare(JsonNode spec) =>
        OperatorContractCheck.Compare(Bytes(spec), Encoding.UTF8.GetBytes(Contract));
}
