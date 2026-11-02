using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecretKit.Infisical.Conformance.Tests;

// The fixture's constraint engine and secret store own their evidence and keys.
// The source coordinator cannot manufacture either history by signing its packet.
// A native deployment must replace these with separately operated provider taps.
internal sealed class InfisicalValidationPermissionEnforcer(Func<ValidationPermissionState[]> readRules, string fault) : IDisposable
{
    private readonly InfisicalValidationPermissionWriter writer = new(ValidationPermissionJournal.Enforcement);
    private readonly List<ValidationPermissionEnforcement> decisions = [];
    private bool fenced;
    internal ValidationPermissionPin Pin => writer.Pin;
    internal ValidationPermissionEnforcement Decide(ValidationPermissionAuthorization auth, byte[] bytes)
    {
        ValidationPermissionContract.Require(!fenced && auth.InputHash == ValidationPermissionContract.RawHash(bytes));
        using var body = JsonDocument.Parse(bytes); var input = body.RootElement;
        ValidationPermissionContract.Require(input.GetProperty("projectId").GetString() == auth.Project && input.GetProperty("environment").GetString() == auth.Environment &&
            input.GetProperty("secretPath").GetString() == auth.Path && input.GetProperty("type").GetString() == "shared" && input.GetProperty("skipMultilineEncoding").GetBoolean());
        var inventory = readRules().OrderBy(r => r.Row).ToArray();
        var rules = inventory.Where(r => r.Project == auth.Project && r.Environment == auth.Environment && r.Path == auth.Path).ToArray();
        bool allowed = rules.Where(r => r.Active).All(r => Matches(auth.Name, r.Key) && Matches(input.GetProperty("secretValue").GetString()!, r.Value));
        var decision = !auth.Allowed ? ValidationPermissionConstraintDecision.NotEvaluated : allowed ? ValidationPermissionConstraintDecision.Allowed : ValidationPermissionConstraintDecision.Violated;
        if (fault == "violating-accepted" && decision == ValidationPermissionConstraintDecision.Violated) decision = ValidationPermissionConstraintDecision.Allowed;
        if (fault == "allowed-rejected" && decision == ValidationPermissionConstraintDecision.Allowed) decision = ValidationPermissionConstraintDecision.Violated;
        if (fault == "fake-enforcement-success") decision = ValidationPermissionConstraintDecision.Allowed;
        if (fault == "rule-revision" && rules.Length > 0) rules[0] = rules[0] with { Version = 99 };
        if (fault == "rule-configuration" && rules.Length > 0) rules[0] = rules[0] with { Value = rules[0].Value! with { RequiredPrefix = "OTHER_" } };
        var entry = new ValidationPermissionEnforcement(auth.Request, ValidationPermissionContract.Hash(auth),
            fault == "protected-input" ? "foreign-input" : auth.InputHash, ValidationPermissionContract.Hash(inventory), rules, decision);
        decisions.Add(entry); return entry;
    }
    private static bool Matches(string value, ValidationPermissionConstraints? c) => c is null ||
        (c.MinimumLength is null || value.Length >= c.MinimumLength) && (c.MaximumLength is null || value.Length <= c.MaximumLength) &&
        (c.RequiredPrefix is null || value.StartsWith(c.RequiredPrefix, StringComparison.Ordinal)) &&
        (c.RequiredSuffix is null || value.EndsWith(c.RequiredSuffix, StringComparison.Ordinal)) &&
        (c.RegexPattern is null || Regex.IsMatch(value, c.RegexPattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)));
    internal void Fence() => fenced = true;
    internal ValidationPermissionSigned<ValidationPermissionEnforcementHistory> Publish(ValidationPermissionRoot root, ValidationPermissionStep step)
    {
        var entries = decisions.ToArray();
        if (step is ValidationPermissionStep.ObserveBefore or ValidationPermissionStep.ObserveAfter)
        {
            if (fault == "omitted-enforcement" && entries.Length > 0) entries = entries.Skip(1).ToArray();
            if (fault == "duplicate-enforcement" && entries.Length > 0) entries = [.. entries, entries[0]];
        }
        return writer.Sign(root, step, new ValidationPermissionEnforcementHistory(entries, fenced, 0));
    }
    internal ValidationPermissionSigned<MemberPermissionSeal> Seal(ValidationPermissionRoot root, ValidationPermissionStep step, ValidationPermissionPayload<ValidationPermissionEnforcementHistory> payload) =>
        writer.Sign(root, step, new MemberPermissionSeal(ValidationPermissionContract.Hash(payload), true, 0, 1));
    public void Dispose() { decisions.Clear(); writer.Dispose(); }
}
internal sealed class InfisicalValidationPermissionBackend(string fault, byte[] borrowedMaterial) : IDisposable
{
    private readonly InfisicalValidationPermissionWriter writer = new(ValidationPermissionJournal.Backend);
    private readonly Dictionary<string, (ValidationPermissionSecret State, byte[] Value)> values = [];
    private readonly List<ValidationPermissionSecret> seeds = [];
    private readonly List<ValidationPermissionBackendChange> changes = [];
    private readonly List<byte[]> owned = [];
    private bool fenced;
    internal ValidationPermissionPin Pin => writer.Pin;
    internal int Remaining => values.Count;
    internal IEnumerable<byte[]> Buffers => owned;
    internal MemberPermissionBorrowed[] Borrowed => [new("borrowed-secret", "30000000-0000-0000-0000-000000000010", ValidationPermissionContract.RawHash(borrowedMaterial))];
    internal ValidationPermissionSecret Seed(ValidationPermissionProbe probe, string project)
    {
        ValidationPermissionContract.Require(!fenced && !values.ContainsKey(probe.Key));
        var state = new ValidationPermissionSecret(probe.Key, Guid.NewGuid().ToString(), project, probe.Environment, probe.Path, probe.Name, ValidationPermissionContract.Hash("PASS_BASE_OK"), 1);
        Store(state, "PASS_BASE_OK"); seeds.Add(state); return state;
    }
    internal ValidationPermissionBackendChange Apply(ValidationPermissionAuthorization auth, ValidationPermissionEnforcement decision, ValidationPermissionProbe probe, byte[] bytes)
    {
        ValidationPermissionContract.Require(!fenced && !changes.Any(c => c.Request == auth.Request));
        using var body = JsonDocument.Parse(bytes); string value = body.RootElement.GetProperty("secretValue").GetString()!;
        var before = values.TryGetValue(probe.Key, out var stored) ? stored.State : null;
        bool apply = auth.Allowed && decision.Decision == ValidationPermissionConstraintDecision.Allowed;
        if (fault == "authorized-uncommitted" && apply) apply = false;
        if (fault == "unauthorized-commit" && !auth.Allowed) apply = true;
        var after = !apply ? before : new ValidationPermissionSecret(probe.Key, before?.Id ?? Guid.NewGuid().ToString(), auth.Project, auth.Environment, auth.Path,
            auth.Name, ValidationPermissionContract.Hash(value), (before?.Version ?? 0) + 1);
        if (apply) Store(after!, value);
        var change = new ValidationPermissionBackendChange(auth.Request, ValidationPermissionContract.Hash(decision), ValidationPermissionContract.RawHash(bytes),
            apply ? Guid.NewGuid().ToString() : "", before, after);
        changes.Add(change); return change;
    }
    private void Store(ValidationPermissionSecret state, string value)
    {
        if (values.TryGetValue(state.Key, out var prior)) CryptographicOperations.ZeroMemory(prior.Value);
        byte[] bytes = Encoding.UTF8.GetBytes(value); owned.Add(bytes); values[state.Key] = (state, bytes);
    }
    internal object? Read(string project, string environment, string path, string name)
    {
        var item = values.Values.SingleOrDefault(v => v.State.Project == project && v.State.Environment == environment && v.State.Path == path && v.State.Name == name);
        return item.State is null ? null : new
        {
            secretKey = item.State.Name,
            secretValue = Encoding.UTF8.GetString(item.Value),
            secretValueHidden = false,
            workspace = item.State.Project,
            environment = item.State.Environment,
            version = item.State.Version
        };
    }
    internal void Fence() => fenced = true;
    internal void Clear()
    {
        ValidationPermissionContract.Require(fenced); foreach (var bytes in owned) CryptographicOperations.ZeroMemory(bytes); values.Clear();
        if (fault == "borrowed-backend-change") borrowedMaterial[0] ^= 1;
    }
    internal ValidationPermissionSigned<ValidationPermissionBackendHistory> Publish(ValidationPermissionRoot root, ValidationPermissionStep step)
    {
        var entries = changes.ToArray(); var inventory = values.Values.Select(v => v.State).OrderBy(s => s.Key).ToArray();
        if (step is ValidationPermissionStep.ObserveBefore or ValidationPermissionStep.ObserveAfter)
        {
            if (fault == "omitted-backend" && entries.Length > 0) entries = entries.Skip(1).ToArray();
            if (fault == "duplicate-backend" && entries.Length > 0) entries = [.. entries, entries[0]];
            if (fault == "missing-secret-inventory" && inventory.Length > 0) inventory = inventory.Skip(1).ToArray();
        }
        return writer.Sign(root, step, new ValidationPermissionBackendHistory(seeds.ToArray(), entries, inventory, Borrowed, fenced, 0));
    }
    internal ValidationPermissionSigned<MemberPermissionSeal> Seal(ValidationPermissionRoot root, ValidationPermissionStep step, ValidationPermissionPayload<ValidationPermissionBackendHistory> payload) =>
        writer.Sign(root, step, new MemberPermissionSeal(ValidationPermissionContract.Hash(payload), true, 0, 1));
    public void Dispose()
    {
        foreach (var bytes in owned) CryptographicOperations.ZeroMemory(bytes);
        owned.Clear(); values.Clear(); seeds.Clear(); changes.Clear(); writer.Dispose();
    }
}
