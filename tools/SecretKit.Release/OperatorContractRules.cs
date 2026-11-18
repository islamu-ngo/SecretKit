using System.Text.Json;

namespace SecretKit.Release;

public static partial class OperatorContractCheck
{
    private static readonly string[] RuleFacts =
    [
        "type", "nullable", "enum", "format", "required", "minimum", "maximum",
        "minLength", "maxLength", "minItems", "maxItems", "anyOf", "oneOf"
    ];

    private static bool HasUnion(JsonElement schema) =>
        schema.TryGetProperty("anyOf", out _) || schema.TryGetProperty("oneOf", out _);

    private static JsonElement[] Alternatives(JsonElement schema) =>
        schema.TryGetProperty("anyOf", out JsonElement any) ? any.EnumerateArray().ToArray() :
        schema.TryGetProperty("oneOf", out JsonElement one) ? one.EnumerateArray().ToArray() : [schema];

    private static void EstablishUnion(JsonElement schema, LocalReferences resolver,
        (int Depth, string Location, Func<JsonElement, string, JsonElement[]>? Select) context)
    {
        Guard.Require(context.Depth <= 64, "unestablished-schema-depth");
        resolver.Visit(schema, value =>
        {
            if (HasUnion(value))
            {
                Keys(value, "unestablished-schema", "anyOf", "oneOf", "title", "description", "default", "example", "deprecated");
                Guard.Require(value.TryGetProperty("anyOf", out _) != value.TryGetProperty("oneOf", out _),
                    "unestablished-schema");
                JsonElement branches = value.GetProperty(value.TryGetProperty("anyOf", out _) ? "anyOf" : "oneOf");
                Guard.Require(branches.ValueKind == JsonValueKind.Array && branches.GetArrayLength() > 0,
                    "unestablished-schema");
                foreach (JsonElement branch in branches.EnumerateArray())
                    resolver.Visit(branch, _ => { });
                JsonElement[] selected = context.Select?.Invoke(value, context.Location) ?? branches.EnumerateArray().ToArray();
                Guard.Require(selected.Length > 0, "unestablished-union-empty");
                foreach (JsonElement branch in selected)
                    EstablishUnion(branch, resolver, (context.Depth + 1, context.Location, context.Select));
                if (value.TryGetProperty("oneOf", out _))
                    for (int first = 0; first < selected.Length; first++)
                        for (int second = first + 1; second < selected.Length; second++)
                            resolver.Visit(selected[first], left => resolver.Visit(selected[second], right =>
                                Guard.Require(Disjoint(left, right), "unestablished-oneof-overlap")));
                return;
            }
            ValidateShape(value);
            if (value.TryGetProperty("properties", out JsonElement fields))
                foreach (JsonProperty field in fields.EnumerateObject())
                    EstablishUnion(field.Value, resolver,
                        (context.Depth + 1, context.Location + "." + field.Name, context.Select));
            if (value.TryGetProperty("items", out JsonElement items))
                EstablishUnion(items, resolver, (context.Depth + 1, context.Location + "[]", context.Select));
        });
    }

    private static HashSet<(string Location, string Discriminator)> ReadExcludedAlternatives(JsonElement operation)
    {
        var result = new HashSet<(string Location, string Discriminator)>();
        if (!operation.TryGetProperty("excludedAlternatives", out _)) return result;
        foreach (JsonElement item in Array(operation, "excludedAlternatives", "operator-exclusion").EnumerateArray())
        {
            Keys(item, "operator-exclusion", "location", "discriminator", "rationale");
            string location = Text(item, "location", "operator-exclusion");
            Guard.Require(location == "response" || location.StartsWith("response.", StringComparison.Ordinal),
                "operator-exclusion");
            foreach (string part in location.Split('.')) _ = SafeField(part.Replace("[]", "", StringComparison.Ordinal));
            string discriminator = SafeField(Text(item, "discriminator", "operator-exclusion"));
            Guard.Require(!string.IsNullOrWhiteSpace(Text(item, "rationale", "operator-exclusion")) &&
                result.Add((location, discriminator)), "operator-exclusion");
        }
        return result;
    }

    private static (bool Found, bool Declares) ConsumerDiscriminator(JsonElement response, LocalReferences resolver,
        (string Location, string Discriminator) target)
    {
        string[] path = target.Location.Split('.');
        bool found = false;
        bool declares = false;
        Visit(response, 1);
        return (found, declares);

        void Visit(JsonElement schema, int position) => resolver.Visit(schema, resolved =>
        {
            if (HasUnion(resolved))
            {
                foreach (JsonElement branch in Alternatives(resolved)) Visit(branch, position);
                return;
            }
            if (position == path.Length)
            {
                found = true;
                declares |= resolved.TryGetProperty("properties", out JsonElement fields) &&
                    fields.ValueKind == JsonValueKind.Object && fields.TryGetProperty(target.Discriminator, out _);
                return;
            }
            string name = path[position].Replace("[]", "", StringComparison.Ordinal);
            if (!resolved.TryGetProperty("properties", out JsonElement properties) ||
                properties.ValueKind != JsonValueKind.Object || !properties.TryGetProperty(name, out JsonElement child)) return;
            for (int index = name.Length; index < path[position].Length; index += 2)
                resolver.Visit(child, array => child = Object(array, "items", "operator-exclusion"));
            Visit(child, position + 1);
        });
    }

    private static bool Disjoint(JsonElement left, JsonElement right)
    {
        if (HasUnion(left) || HasUnion(right)) return false;
        if (Flag(left, "nullable") && Flag(right, "nullable")) return false;
        string first = Text(left, "type");
        string second = Text(right, "type");
        if (first != second && !(first is "number" or "integer" && second is "number" or "integer"))
            return true;
        return left.TryGetProperty("enum", out JsonElement leftValues) &&
            right.TryGetProperty("enum", out JsonElement rightValues) &&
            !leftValues.EnumerateArray().Any(value => rightValues.EnumerateArray().Any(other => JsonElement.DeepEquals(value, other)));
    }

    private static Dictionary<string, JsonElement> ReadNarrowings(JsonElement operation)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        if (!operation.TryGetProperty("narrowings", out _)) return result;
        foreach (JsonElement item in Array(operation, "narrowings", "operator-narrowing").EnumerateArray())
        {
            Keys(item, "operator-narrowing", "path", "sdkRule", "openApiRule", "rationale");
            string path = Text(item, "path", "operator-narrowing");
            Guard.Require(path == "response" || path.StartsWith("response.", StringComparison.Ordinal),
                "operator-narrowing");
            foreach (string part in path.Split('.'))
                _ = SafeField(part.Replace("[]", "", StringComparison.Ordinal));
            Guard.Require(!string.IsNullOrWhiteSpace(Text(item, "rationale", "operator-narrowing")) &&
                result.TryAdd(path, item), "operator-narrowing");
            ValidateRule(Object(item, "sdkRule", "operator-narrowing"));
            ValidateRule(Object(item, "openApiRule", "operator-narrowing"));
        }
        return result;
    }

    private static void ValidateRule(JsonElement rule)
    {
        Keys(rule, "operator-narrowing", RuleFacts);
        if (HasUnion(rule))
        {
            Guard.Require(rule.EnumerateObject().Count() == 1, "operator-narrowing");
            JsonElement union = rule.GetProperty(rule.TryGetProperty("anyOf", out _) ? "anyOf" : "oneOf");
            Guard.Require(union.ValueKind == JsonValueKind.Array && union.GetArrayLength() > 0, "operator-narrowing");
            foreach (JsonElement branch in union.EnumerateArray()) ValidateRule(branch);
            Guard.Require(PrimitiveRule(rule), "operator-narrowing");
            return;
        }
        string type = Text(rule, "type", "operator-narrowing");
        // Object rules project presence only; primitive rules project all compared facts.
        if (type == "object")
        {
            Keys(rule, "operator-narrowing", "type", "required");
            _ = Strings(rule, "required");
        }
        else ValidateShape(rule);
    }

    private static bool PrimitiveRule(JsonElement rule) => HasUnion(rule)
        ? Alternatives(rule).All(PrimitiveRule)
        : Text(rule, "type") is "string" or "boolean" or "integer" or "number";

    private static bool MatchesRule(JsonElement schema, JsonElement rule, LocalReferences resolver)
    {
        bool matches = false;
        resolver.Visit(schema, resolved => matches = MatchesResolvedRule(resolved, rule, resolver));
        return matches;
    }

    private static bool MatchesResolvedRule(JsonElement schema, JsonElement rule, LocalReferences resolver)
    {
        foreach (string fact in RuleFacts)
        {
            bool actualHas = schema.TryGetProperty(fact, out JsonElement actual);
            bool expectedHas = rule.TryGetProperty(fact, out JsonElement expected);
            if (fact == "required")
            {
                if (!Strings(schema, fact).SetEquals(Strings(rule, fact))) return false;
            }
            else if (fact == "nullable")
            {
                if (Flag(schema, fact) != Flag(rule, fact)) return false;
            }
            else if (fact is "anyOf" or "oneOf")
            {
                if (actualHas != expectedHas) return false;
                if (actualHas && (actual.GetArrayLength() != expected.GetArrayLength() ||
                    actual.EnumerateArray().Where((branch, index) => !MatchesRule(branch, expected[index], resolver)).Any()))
                    return false;
            }
            else if (actualHas != expectedHas || actualHas && !JsonElement.DeepEquals(actual, expected))
                return false;
        }
        return true;
    }

    private static bool RuleSubset(JsonElement subset, JsonElement superset) =>
        Alternatives(subset).All(narrow => Alternatives(superset).Any(wide => PrimitiveSubset(narrow, wide)));

    private static bool PrimitiveSubset(JsonElement narrow, JsonElement wide)
    {
        if (HasUnion(narrow) || HasUnion(wide)) return RuleSubset(narrow, wide);
        string supplied = Text(narrow, "type");
        string accepted = Text(wide, "type");
        if (supplied != accepted && !(supplied == "integer" && accepted == "number")) return false;
        if (Flag(narrow, "nullable") && !Flag(wide, "nullable")) return false;
        if (wide.TryGetProperty("enum", out JsonElement values) &&
            (!narrow.TryGetProperty("enum", out JsonElement selected) ||
                selected.EnumerateArray().Any(value => !values.EnumerateArray().Any(other => JsonElement.DeepEquals(value, other)))))
            return false;
        if (wide.TryGetProperty("format", out JsonElement format) &&
            (!narrow.TryGetProperty("format", out JsonElement selectedFormat) || !JsonElement.DeepEquals(format, selectedFormat)))
            return false;
        foreach (string fact in RuleFacts.Where(fact => fact.StartsWith("min", StringComparison.Ordinal) ||
            fact.StartsWith("max", StringComparison.Ordinal)))
            if (wide.TryGetProperty(fact, out JsonElement limit) &&
                (!narrow.TryGetProperty(fact, out JsonElement selectedLimit) ||
                    (fact.StartsWith("min", StringComparison.Ordinal) ?
                        selectedLimit.GetDouble() < limit.GetDouble() : selectedLimit.GetDouble() > limit.GetDouble())))
                return false;
        return Strings(wide, "required").IsSubsetOf(Strings(narrow, "required"));
    }

    private static HashSet<string> NarrowingCodes(JsonElement rule) =>
        !HasUnion(rule) && Text(rule, "type") == "object"
            ? new(StringComparer.Ordinal) { "response-required" }
            : new(StringComparer.Ordinal) { "type", "nullable", "enum", "format", "constraint", "union" };
}
