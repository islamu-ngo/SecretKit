using System.Globalization;
using System.Text.Json;

namespace SecretKit.Release;

public sealed record OperatorContractFinding(string Operation, string Code, string Location);
public sealed record OperatorContractReport(string SpecSha256, int CheckedOperations,
    IReadOnlyList<OperatorContractFinding> Findings);

// allow: SIZE_OK - The bounded recursive traversal shares diagnostic and reference-cycle state.
// This compares selected consumer facts, not complete OpenAPI documents or provider behavior.
// It has no transport, publisher, generator or manifest-writing dependency.
public static partial class OperatorContractCheck
{
    public const string ManifestPath = "docs/internal/infisical-operator-contracts.json";
    private const int MaximumBytes = 32 * 1024 * 1024;

    public static OperatorContractReport Check(string source, string specification) =>
        Compare(Manifest.ReadLocalFile(specification, MaximumBytes),
            Manifest.ReadLocalFile(Path.Combine(source, ManifestPath), MaximumBytes));

    public static OperatorContractReport Compare(byte[] specification, byte[] contract)
    {
        using JsonDocument spec = Parse(specification);
        using JsonDocument expected = Parse(contract);
        JsonElement root = spec.RootElement;
        Guard.Require(Text(root, "openapi") is "3.0.0" or "3.0.1" or "3.0.2" or "3.0.3",
            "operator-unestablished-openapi");
        JsonElement paths = Object(root, "paths", "operator-paths");
        JsonElement manifest = expected.RootElement;
        Keys(manifest, "operator-manifest", "schemaVersion", "provenance", "exclusions", "shapes", "operations");
        Guard.Require(manifest.TryGetProperty("schemaVersion", out JsonElement version) &&
            version.ValueKind == JsonValueKind.Number && version.TryGetInt32(out int number) && number == 1,
            "operator-manifest");
        Guard.Require(Strings(manifest, "provenance").Count > 0 &&
            Strings(manifest, "exclusions").Count > 0, "operator-manifest");
        _ = Object(manifest, "shapes", "operator-manifest");
        JsonElement operations = Array(manifest, "operations", "operator-manifest");
        Guard.Require(operations.GetArrayLength() is > 0 and <= 128, "operator-manifest");
        var actualResolver = new LocalReferences(root);
        var expectedResolver = new LocalReferences(manifest);
        var findings = new List<OperatorContractFinding>();
        var identities = new HashSet<string>(StringComparer.Ordinal);
        var routes = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement operation in operations.EnumerateArray())
        {
            Keys(operation, "operator-manifest", "id", "method", "path", "parameters", "request", "status", "response",
                "narrowings", "excludedAlternatives");
            string id = Text(operation, "id");
            string method = Text(operation, "method");
            string path = Text(operation, "path");
            Guard.Require(Manifest.SafeIdentity(id) && identities.Add(id) &&
                method is "get" or "post" or "patch" or "delete" or "put" &&
                path.StartsWith('/') && !path.Any(char.IsControl) &&
                routes.Add(method + ":" + PathShape(path)), "operator-manifest");
            string location = "operation";
            Dictionary<string, JsonElement> narrowings = ReadNarrowings(operation);
            var visitedNarrowings = new HashSet<string>(StringComparer.Ordinal);
            var admittedNarrowings = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            var exclusions = ReadExcludedAlternatives(operation);
            var appliedExclusions = new HashSet<(string Location, string Discriminator)>();
            var invalidExclusions = new HashSet<(string Location, string Discriminator)>();
            var selectedAlternatives = new Dictionary<(JsonElement Schema, string Location), JsonElement[]>();
            var exclusionConsumers = new Dictionary<(string Location, string Discriminator), (bool Found, bool Declares)>();
            try
            {
                foreach (var key in exclusions)
                    exclusionConsumers.Add(key, ConsumerDiscriminator(
                        Object(operation, "response", "operator-manifest"), expectedResolver, key));
                JsonProperty[] matchingPaths = paths.EnumerateObject()
                    .Where(candidate => PathShape(candidate.Name) == PathShape(path)).ToArray();
                if (matchingPaths.Length == 0) { Add("path-removed"); continue; }
                // Template labels are not wire data. Match by position, but never pick
                // between two definitions of the same templated method.
                var candidates = new List<(string Path, JsonElement Item)>();
                foreach (JsonProperty candidate in matchingPaths)
                    actualResolver.Visit(candidate.Value, item =>
                    {
                        if (item.TryGetProperty(method, out _)) candidates.Add((candidate.Name, item));
                    });
                if (candidates.Count == 0) { Add("method-removed"); continue; }
                Guard.Require(candidates.Count == 1, "unestablished-path");
                var selected = candidates[0];
                JsonElement actual = Object(selected.Item, method, "unestablished-operation");
                Keys(actual, "unestablished-operation", "tags", "summary", "description", "externalDocs",
                    "operationId", "parameters", "requestBody", "responses", "callbacks", "deprecated",
                    "security", "servers");
                Guard.Require(!actual.TryGetProperty("callbacks", out _), "unestablished-operation");
                var inherited = Parameters(selected.Item, actualResolver);
                foreach (var parameter in Parameters(actual, actualResolver))
                    inherited[parameter.Key] = parameter.Value;
                var wanted = Parameters(operation, expectedResolver);
                string[] expectedLabels = PathLabels(path);
                string[] actualLabels = PathLabels(selected.Path);
                var parameterNames = new HashSet<(string In, string Name)>();
                foreach (var (key, parameter) in wanted)
                {
                    string name = key.Name;
                    if (key.In == "path")
                    {
                        int index = System.Array.IndexOf(expectedLabels, name);
                        Guard.Require(index >= 0 && index < actualLabels.Length, "operator-manifest");
                        name = actualLabels[index];
                    }
                    var mapped = (key.In, name);
                    parameterNames.Add(mapped);
                    location = "parameter." + key.In + "." + SafeField(key.Name);
                    if (!inherited.TryGetValue(mapped, out JsonElement found)) { Add("parameter-removed"); continue; }
                    if (Flag(found, "required") && !Flag(parameter, "required")) Add("request-required");
                    CompareShape(Object(found, "schema", "unestablished-parameter"),
                        Object(parameter, "schema", "operator-manifest"), request: true, 0, scalarParameter: true);
                }
                location = "parameters";
                foreach (var (key, parameter) in inherited)
                    if (!parameterNames.Contains(key) && Flag(parameter, "required")) Add("request-required");
                Guard.Require(actualLabels.All(label => inherited.TryGetValue(("path", label), out var parameter) &&
                    Flag(parameter, "required")), "unestablished-parameter");

                location = "request";
                if (operation.TryGetProperty("request", out JsonElement request))
                {
                    if (!actual.TryGetProperty("requestBody", out JsonElement body)) Add("request-body-removed");
                    else actualResolver.Visit(body, resolved =>
                    {
                        Keys(resolved, "unestablished-request", "description", "required", "content");
                        CompareShape(JsonSchema(resolved), request, request: true, 0);
                    });
                }
                else if (actual.TryGetProperty("requestBody", out JsonElement body))
                    actualResolver.Visit(body, resolved =>
                    {
                        if (Flag(resolved, "required")) Add("request-required");
                    });

                location = "response";
                string status = Text(operation, "status");
                Guard.Require(status.Length == 3 && status[0] == '2' && status.All(char.IsAsciiDigit), "operator-manifest");
                JsonElement responses = Object(actual, "responses", "unestablished-response");
                if (!responses.TryGetProperty(status, out JsonElement response)) Add("response-removed");
                else actualResolver.Visit(response, resolved =>
                {
                    Keys(resolved, "unestablished-response", "description", "headers", "content", "links");
                    CompareShape(JsonSchema(resolved), Object(operation, "response", "operator-manifest"),
                        request: false, 0);
                });
            }
            catch (ReleaseException error)
            {
                // Only closed codes and consumer-owned labels escape. Never echo spec text.
                Add(error.Message);
            }
            foreach (string unused in narrowings.Keys.Except(visitedNarrowings))
                findings.Add(new(id, "narrowing-unmatched", unused));
            foreach (var key in exclusions.Except(appliedExclusions))
                findings.Add(new(id, "excluded-alternative-unmatched", key.Location));
            foreach (var key in invalidExclusions)
                findings.Add(new(id, "excluded-alternative", key.Location));

            void Add(string code)
            {
                if (!admittedNarrowings.TryGetValue(location, out HashSet<string>? allowed) || !allowed.Contains(code))
                    findings.Add(new(id, code, location));
            }

            JsonElement[] SelectAlternatives(JsonElement schema, string at)
            {
                if (selectedAlternatives.TryGetValue((schema, at), out JsonElement[]? cached)) return cached;
                JsonElement[] branches = Alternatives(schema);
                var removed = new HashSet<int>();
                foreach (var key in exclusions.Where(key => key.Location == at))
                {
                    var matching = new List<int>();
                    for (int index = 0; index < branches.Length; index++)
                    {
                        int candidate = index;
                        actualResolver.Visit(branches[index], branch =>
                        {
                            if (Strings(branch, "required").Contains(key.Discriminator)) matching.Add(candidate);
                        });
                    }
                    var consumer = exclusionConsumers[key];
                    if (matching.Count != 1 || !consumer.Found || consumer.Declares ||
                        removed.Contains(matching[0]))
                    {
                        invalidExclusions.Add(key);
                        continue;
                    }
                    bool valid = false;
                    actualResolver.Visit(branches[matching[0]], branch =>
                    {
                        valid = (!branch.TryGetProperty("type", out _) || Text(branch, "type") == "object") &&
                            branch.TryGetProperty("properties", out JsonElement fields) &&
                            fields.ValueKind == JsonValueKind.Object && fields.TryGetProperty(key.Discriminator, out _);
                    });
                    if (!valid) { invalidExclusions.Add(key); continue; }
                    removed.Add(matching[0]);
                    appliedExclusions.Add(key);
                }
                JsonElement[] selected = branches.Where((_, index) => !removed.Contains(index)).ToArray();
                selectedAlternatives.Add((schema, at), selected);
                return selected;
            }

            void CompareShape(JsonElement actual, JsonElement wanted, bool request, int depth, bool scalarParameter = false)
            {
                Guard.Require(depth <= 64, "unestablished-schema-depth");
                actualResolver.Visit(actual, a => expectedResolver.Visit(wanted, e =>
                {
                    bool actualUnion = HasUnion(a);
                    bool expectedUnion = HasUnion(e);
                    // Establish every alternative before a request can select any one of them.
                    if (actualUnion) EstablishUnion(a, actualResolver, (depth, location, request ? null : SelectAlternatives));
                    if (expectedUnion) EstablishUnion(e, expectedResolver, (depth, location, null));
                    string narrowingLocation = location;
                    bool ownsNarrowing = false;
                    if (!request && !admittedNarrowings.ContainsKey(location) &&
                        narrowings.TryGetValue(location, out JsonElement narrowing))
                    {
                        JsonElement sdkRule = Object(narrowing, "sdkRule", "operator-narrowing");
                        JsonElement apiRule = Object(narrowing, "openApiRule", "operator-narrowing");
                        if (MatchesRule(a, apiRule, actualResolver) && MatchesRule(e, sdkRule, expectedResolver) &&
                            RuleSubset(sdkRule, apiRule) && !RuleSubset(apiRule, sdkRule))
                        {
                            visitedNarrowings.Add(location);
                            admittedNarrowings.Add(location, NarrowingCodes(sdkRule));
                            ownsNarrowing = true;
                        }
                    }
                    try
                    {
                        if (actualUnion || expectedUnion)
                        {
                            JsonElement[] actualBranches = actualUnion && !request ? SelectAlternatives(a, location) : Alternatives(a);
                            JsonElement[] expectedBranches = Alternatives(e);
                            foreach (JsonElement suppliedBranch in request ? expectedBranches : actualBranches)
                            {
                                bool matched = false;
                                foreach (JsonElement acceptedBranch in request ? actualBranches : expectedBranches)
                                {
                                    int start = findings.Count;
                                    CompareShape(request ? acceptedBranch : suppliedBranch, request ? suppliedBranch : acceptedBranch,
                                        request, depth + 1, scalarParameter);
                                    matched = findings.Count == start;
                                    findings.RemoveRange(start, findings.Count - start);
                                    if (matched) break;
                                }
                                if (!matched) Add("union");
                            }
                            return;
                        }
                        ValidateShape(a);
                        ValidateShape(e);
                        string actualType = Text(a, "type");
                        string expectedType = Text(e, "type");
                        Guard.Require(!scalarParameter || actualType is not ("array" or "object") &&
                            expectedType is not ("array" or "object"), "unestablished-parameter");
                        string supplied = request ? expectedType : actualType;
                        string accepted = request ? actualType : expectedType;
                        if (supplied != accepted && !(supplied == "integer" && accepted == "number"))
                        {
                            Add("type");
                            return;
                        }
                        JsonElement narrower = request ? e : a;
                        JsonElement wider = request ? a : e;
                        if (Flag(narrower, "nullable") && !Flag(wider, "nullable")) Add("nullable");
                        if (wider.TryGetProperty("enum", out JsonElement acceptedValues) &&
                            (!narrower.TryGetProperty("enum", out JsonElement suppliedValues) ||
                                suppliedValues.EnumerateArray().Any(value =>
                                    !acceptedValues.EnumerateArray().Any(other => JsonElement.DeepEquals(value, other)))))
                            Add("enum");
                        if (wider.TryGetProperty("format", out JsonElement format) &&
                            (!narrower.TryGetProperty("format", out JsonElement sourceFormat) ||
                                sourceFormat.GetString() != format.GetString())) Add("format");
                        foreach (string bound in new[] { "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems" })
                        {
                            if (!wider.TryGetProperty(bound, out JsonElement limit)) continue;
                            if (!narrower.TryGetProperty(bound, out JsonElement sourceLimit) ||
                                (bound.StartsWith("min", StringComparison.Ordinal)
                                    ? sourceLimit.GetDouble() < limit.GetDouble()
                                    : sourceLimit.GetDouble() > limit.GetDouble())) Add("constraint");
                        }
                        if (expectedType == "array")
                        {
                            string previous = location;
                            location += "[]";
                            CompareShape(Object(a, "items", "unestablished-schema"),
                                Object(e, "items", "operator-manifest"), request, depth + 1);
                            location = previous;
                        }
                        if (expectedType != "object") return;
                        JsonElement actualFields = Object(a, "properties", "unestablished-schema");
                        JsonElement expectedFields = Object(e, "properties", "operator-manifest");
                        HashSet<string> actualRequired = Strings(a, "required");
                        HashSet<string> expectedRequired = Strings(e, "required");
                        if (request && actualRequired.Except(expectedRequired).Any()) Add("request-required");
                        if (!request && expectedRequired.Except(actualRequired).Any()) Add("response-required");
                        if (!request && e.TryGetProperty("additionalProperties", out JsonElement extra) &&
                            extra.ValueKind == JsonValueKind.False &&
                            (!a.TryGetProperty("additionalProperties", out JsonElement actualExtra) ||
                                actualExtra.ValueKind != JsonValueKind.False ||
                                actualFields.EnumerateObject().Any(field => !expectedFields.TryGetProperty(field.Name, out _))))
                            Add("response-additional-properties");
                        foreach (JsonProperty field in expectedFields.EnumerateObject())
                        {
                            string previous = location;
                            location += "." + SafeField(field.Name);
                            if (!actualFields.TryGetProperty(field.Name, out JsonElement actualField))
                                Add(request ? "request-member-removed" : "response-member-removed");
                            else CompareShape(actualField, field.Value, request, depth + 1);
                            location = previous;
                        }
                    }
                    finally
                    {
                        if (ownsNarrowing) admittedNarrowings.Remove(narrowingLocation);
                    }
                }));
            }
        }
        return new(Manifest.Hash(specification), operations.GetArrayLength(), findings.AsReadOnly());
    }

    private static JsonDocument Parse(byte[] bytes)
    {
        Guard.Require(bytes.Length is > 0 and <= MaximumBytes, "operator-input-size");
        JsonDocument document;
        try { document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 }); }
        catch (JsonException) { throw new ReleaseException("operator-json"); }
        try { Unique(document.RootElement); return document; }
        catch { document.Dispose(); throw; }

        static void Unique(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    Guard.Require(names.Add(property.Name), "operator-json-duplicate");
                    Unique(property.Value);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
                foreach (JsonElement child in element.EnumerateArray()) Unique(child);
        }
    }

    private static Dictionary<(string In, string Name), JsonElement> Parameters(JsonElement owner, LocalReferences resolver)
    {
        var result = new Dictionary<(string In, string Name), JsonElement>();
        if (!owner.TryGetProperty("parameters", out JsonElement parameters)) return result;
        Guard.Require(parameters.ValueKind == JsonValueKind.Array, "unestablished-parameter");
        foreach (JsonElement parameter in parameters.EnumerateArray())
            resolver.Visit(parameter, value =>
            {
                Keys(value, "unestablished-parameter", "name", "in", "required", "schema", "description",
                    "deprecated", "style", "explode", "allowReserved", "example", "examples");
                string name = Text(value, "name");
                string kind = Text(value, "in");
                Guard.Require(name.Length > 0 && kind is "query" or "path" or "header" or "cookie" &&
                    result.TryAdd((kind, name), value), "unestablished-parameter");
                _ = Flag(value, "required");
                if (value.TryGetProperty("style", out JsonElement style))
                    Guard.Require(style.ValueKind == JsonValueKind.String &&
                        style.GetString() == (kind is "query" or "cookie" ? "form" : "simple"), "unestablished-parameter");
                Guard.Require(!Flag(value, "allowReserved"), "unestablished-parameter");
                _ = Flag(value, "explode");
                _ = Object(value, "schema", "unestablished-parameter");
            });
        return result;
    }

    private static JsonElement JsonSchema(JsonElement owner)
    {
        JsonElement content = Object(owner, "content", "json-media");
        JsonElement media = Object(content, "application/json", "json-media");
        Keys(media, "unestablished-media", "schema", "example", "examples");
        return Object(media, "schema", "unestablished-schema");
    }

    private static void ValidateShape(JsonElement schema)
    {
        Keys(schema, "unestablished-schema", "type", "nullable", "enum", "format", "properties", "required",
            "items", "additionalProperties", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems",
            "title", "description", "default", "example", "examples", "deprecated");
        string type = Text(schema, "type", "unestablished-schema");
        Guard.Require(type is "string" or "boolean" or "integer" or "number" or "object" or "array",
            "unestablished-schema");
        _ = Flag(schema, "nullable");
        if (schema.TryGetProperty("format", out JsonElement format))
            Guard.Require(format.ValueKind == JsonValueKind.String && (type switch
            {
                "string" => format.GetString() is "uuid" or "date-time" or "date" or "password",
                "integer" or "number" => format.GetString() is "int32" or "int64" or "float" or "double",
                _ => false
            }),
                "unestablished-format");
        if (schema.TryGetProperty("enum", out JsonElement values))
        {
            Guard.Require(values.ValueKind == JsonValueKind.Array && values.GetArrayLength() > 0, "unestablished-schema");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement value in values.EnumerateArray())
            {
                bool valid = value.ValueKind == JsonValueKind.Null ? Flag(schema, "nullable") : type switch
                {
                    "string" => value.ValueKind == JsonValueKind.String,
                    "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
                    "number" or "integer" => value.ValueKind == JsonValueKind.Number &&
                        value.TryGetDouble(out double number) && double.IsFinite(number) &&
                        (type == "number" || Math.Truncate(number) == number),
                    _ => false
                };
                Guard.Require(valid && seen.Add(value.GetRawText()), "unestablished-schema");
            }
        }
        foreach (string bound in new[] { "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems" })
            if (schema.TryGetProperty(bound, out JsonElement value))
                Guard.Require(value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out double number) &&
                    double.IsFinite(number) &&
                    (bound is "minimum" or "maximum" ? type is "integer" or "number" :
                        number >= 0 && Math.Truncate(number) == number &&
                        (bound.EndsWith("Length", StringComparison.Ordinal) ? type == "string" : type == "array")),
                    "unestablished-schema");
        foreach (var (minimum, maximum) in new[] { ("minimum", "maximum"), ("minLength", "maxLength"), ("minItems", "maxItems") })
            if (schema.TryGetProperty(minimum, out JsonElement lower) && schema.TryGetProperty(maximum, out JsonElement upper))
                Guard.Require(lower.GetDouble() <= upper.GetDouble(), "unestablished-schema");
        if (schema.TryGetProperty("additionalProperties", out JsonElement additional))
            Guard.Require(type == "object" && additional.ValueKind is JsonValueKind.True or JsonValueKind.False,
                "unestablished-schema");
        if (type == "object")
        {
            JsonElement fields = Object(schema, "properties", "unestablished-schema");
            Guard.Require(Strings(schema, "required").All(name => fields.TryGetProperty(name, out _)),
                "unestablished-schema");
        }
        else Guard.Require(!schema.TryGetProperty("properties", out _) && !schema.TryGetProperty("required", out _),
            "unestablished-schema");
        if (type == "array") _ = Object(schema, "items", "unestablished-schema");
        else Guard.Require(!schema.TryGetProperty("items", out _), "unestablished-schema");
    }

    private static string PathShape(string path) => string.Join('/', path.Split('/').Select(segment =>
        segment.StartsWith('{') && segment.EndsWith('}') ? "{}" : segment));

    private static string[] PathLabels(string path) => path.Split('/')
        .Where(segment => segment.StartsWith('{') && segment.EndsWith('}')).Select(segment => segment[1..^1]).ToArray();

    private static string SafeField(string name)
    {
        Guard.Require(name.Length is > 0 and <= 128 &&
            name.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-'),
            "operator-manifest-field");
        return name;
    }

    private static void Keys(JsonElement value, string code, params string[] allowed)
    {
        Guard.Require(value.ValueKind == JsonValueKind.Object, code);
        Guard.Require(value.EnumerateObject().All(property => allowed.Contains(property.Name, StringComparer.Ordinal)), code);
    }

    private static JsonElement Object(JsonElement owner, string name, string code)
    {
        Guard.Require(owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out _), code);
        JsonElement value = owner.GetProperty(name);
        Guard.Require(value.ValueKind == JsonValueKind.Object, code);
        return value;
    }

    private static JsonElement Array(JsonElement owner, string name, string code)
    {
        Guard.Require(owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out _), code);
        JsonElement value = owner.GetProperty(name);
        Guard.Require(value.ValueKind == JsonValueKind.Array, code);
        return value;
    }

    private static string Text(JsonElement owner, string name, string code = "unestablished-definition")
    {
        Guard.Require(owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out _), code);
        JsonElement value = owner.GetProperty(name);
        Guard.Require(value.ValueKind == JsonValueKind.String, code);
        return value.GetString()!;
    }

    private static bool Flag(JsonElement owner, string name)
    {
        if (!owner.TryGetProperty(name, out JsonElement value)) return false;
        Guard.Require(value.ValueKind is JsonValueKind.True or JsonValueKind.False, "unestablished-definition");
        return value.GetBoolean();
    }

    private static HashSet<string> Strings(JsonElement owner, string name)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (!owner.TryGetProperty(name, out JsonElement value)) return result;
        Guard.Require(value.ValueKind == JsonValueKind.Array, "unestablished-definition");
        foreach (JsonElement item in value.EnumerateArray())
            Guard.Require(item.ValueKind == JsonValueKind.String && result.Add(item.GetString()!),
                "unestablished-definition");
        return result;
    }

    private sealed class LocalReferences(JsonElement document)
    {
        private readonly HashSet<string> _active = new(StringComparer.Ordinal);
        private int _count;

        public void Visit(JsonElement value, Action<JsonElement> read)
        {
            Guard.Require(value.ValueKind == JsonValueKind.Object, "unestablished-definition");
            if (!value.TryGetProperty("$ref", out JsonElement reference)) { read(value); return; }
            Guard.Require(value.EnumerateObject().Count() == 1 && reference.ValueKind == JsonValueKind.String,
                "unestablished-reference");
            string pointer = reference.GetString()!;
            Guard.Require(pointer.StartsWith("#/", StringComparison.Ordinal) && !pointer.Contains('%'),
                "unestablished-reference");
            Guard.Require(++_count <= 4096, "unestablished-reference-limit");
            Guard.Require(_active.Add(pointer), "unestablished-reference-cycle");
            try
            {
                Guard.Require(_active.Count <= 32, "unestablished-reference-depth");
                JsonElement selected = document;
                foreach (string encoded in pointer[2..].Split('/'))
                {
                    for (int index = 0; index < encoded.Length; index++)
                        if (encoded[index] == '~')
                        {
                            Guard.Require(++index < encoded.Length && encoded[index] is '0' or '1',
                                "unestablished-reference");
                        }
                    string token = encoded.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal);
                    if (selected.ValueKind == JsonValueKind.Array)
                    {
                        Guard.Require(int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out int index) &&
                            index >= 0 && index < selected.GetArrayLength() &&
                            index.ToString(CultureInfo.InvariantCulture) == token, "unestablished-reference");
                        selected = selected[index];
                    }
                    else
                    {
                        Guard.Require(selected.ValueKind == JsonValueKind.Object &&
                            selected.TryGetProperty(token, out _), "unestablished-reference");
                        selected = selected.GetProperty(token);
                    }
                }
                Visit(selected, read);
            }
            finally { _active.Remove(pointer); }
        }
    }
}
