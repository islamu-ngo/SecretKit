using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// These packets have valid signatures from newly enrolled test authorities.
// Rejection must come from semantic joins, not a broken signature or head.
public sealed class InfisicalSettingsPermissionSemanticTests
{
    public static IEnumerable<string> Faults() =>
        ["binding-kind", "binding-scope", "binding-input", "binding-intent", "binding-parent", "binding-id",
         "binding-request", "binding-request-input", "credential-principal", "credential-kind", "credential-hash",
         "state-name", "state-workflow", "state-revision", "commit-input", "commit-decision", "commit-missing",
         "policy-request", "membership-position", "request-input", "request-credential", "decision-policy",
         "decision-membership", "decision-subject", "decision-request", "duplicate-request", "missing-decision",
         "reordered-commits", "intermediate-policy", "unfenced-storage", "pending-storage"];

    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task CorrectlySignedButUncausalHistoriesCannotCertifySettings(string fault)
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        string operation = SettingsPermissionContract.SupportedOperations.First(o => o.EndsWith(".CreateProjectPrivilege", StringComparison.Ordinal));
        using var env = provider.Environment(operation, SettingsPermissionAction.Edit);
        var root = provider.Root(operation, SettingsPermissionAction.Edit, "independent-effect");
        using var capability = SecretMaterial.FromText("settings-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        SettingsPermissionTrial? retained = null;
        try
        {
            var trial = await SettingsPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
            await SettingsPermissionEffects.WitnessAsync(env, trial, false, deadline.Token);
            await trial.ArmAsync(deadline.Token);
            await trial.SettleAsync(await SettingsPermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token), deadline.Token);
            await SettingsPermissionEffects.WitnessAsync(env, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        var packet = provider.ClosedPacket!;
        using var signer = new Signer(root);
        using (var baseline = new SettingsPermissionVerifier(signer.Root))
            baseline.Check(signer.Sign(packet), SettingsPermissionStep.Close);
        using var verifier = new SettingsPermissionVerifier(signer.Root);
        await InfisicalSettingsPermissionSourceTests.Rejected(() =>
        {
            verifier.Check(signer.Sign(Tamper(packet, fault)), SettingsPermissionStep.Close);
            return Task.CompletedTask;
        });
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }

    private static SettingsPermissionPacket Tamper(SettingsPermissionPacket packet, string fault)
    {
        string original = packet.Values<SettingsPermissionRequest>(SettingsPermissionJournal.Ingress, "request").Single(r => r.Phase == "original").Id;
        string later = packet.Values<SettingsPermissionRequest>(SettingsPermissionJournal.Ingress, "request").Last(r => r.Phase == "observer").Id;
        var journals = packet.Journals.Select(s =>
        {
            var p = s.Content;
            var entries = p.Events.ToList();
            bool changed = false;
            for (int i = 0; i < entries.Count; i++)
            {
                var e = entries[i];
                if (fault.StartsWith("binding-", StringComparison.Ordinal) && e.Kind == "bind" && !changed)
                {
                    var b = e.Value.Deserialize<SettingsPermissionBinding>(SettingsPermissionContract.Options)!;
                    b = fault switch
                    {
                        "binding-kind" => b with { Kind = "credential" },
                        "binding-scope" => b with { Scope = "foreign" },
                        "binding-input" => b with { InputHash = "foreign" },
                        "binding-intent" => b with { IntentHash = "foreign" },
                        "binding-parent" => b with { ParentCommit = "foreign" },
                        "binding-id" => b with { CanonicalId = "invented-id" },
                        "binding-request" => b with { Request = "unobserved-request" },
                        _ => b with { RequestInputHash = "foreign" }
                    };
                    entries[i] = Value(e, b); changed = true;
                }
                if (fault.StartsWith("credential-", StringComparison.Ordinal) && e.Kind == "credential" && !changed)
                {
                    var c = e.Value.Deserialize<SettingsPermissionCredential>(SettingsPermissionContract.Options)!;
                    if (!c.Owned) continue;
                    c = fault switch
                    {
                        "credential-principal" => c with { Principal = "foreign" },
                        "credential-kind" => c with { Kind = MemberPermissionActorKind.User },
                        _ => c with { Hash = "substituted" }
                    };
                    entries[i] = Value(e, c); changed = true;
                }
                if (p.Journal == SettingsPermissionJournal.Storage && e.Kind == "change" && !changed &&
                    (fault.StartsWith("state-", StringComparison.Ordinal) || fault.StartsWith("commit-", StringComparison.Ordinal)))
                {
                    var c = e.Value.Deserialize<SettingsPermissionChange>(SettingsPermissionContract.Options)!;
                    if (c.DecisionHash.Length == 0 || c.Commit.Length == 0) continue;
                    c = fault switch
                    {
                        "state-name" => c with { After = c.After! with { Name = "unpersisted" } },
                        "state-workflow" => c with { After = c.After! with { Fixed = c.After.Fixed with { WorkflowHash = "unselected-change" } } },
                        "state-revision" => c with { After = c.After! with { Revision = 17 } },
                        "commit-input" => c with { InputHash = "foreign" },
                        "commit-decision" => c with { DecisionHash = "foreign" },
                        _ => c with { Commit = "" }
                    };
                    entries[i] = Value(e, c); changed = true;
                }
                if (p.Journal == SettingsPermissionJournal.Policy && e.Kind == "change" && fault == "policy-request")
                {
                    var c = e.Value.Deserialize<SettingsPermissionPolicyChange>(SettingsPermissionContract.Options)!;
                    if (c.Request == original) entries[i] = Value(e, c with { Request = later });
                }
                if (p.Journal == SettingsPermissionJournal.Membership && e.Kind == "change" && fault == "membership-position")
                {
                    var c = e.Value.Deserialize<SettingsPermissionMemberChange>(SettingsPermissionContract.Options)!;
                    // Final membership is identical, but its grant now claims a
                    // request AFTER the successful PATCH. A final snapshot passes.
                    if (c.Request == original) entries[i] = Value(e, c with { Request = later });
                }
                if (p.Journal == SettingsPermissionJournal.Ingress && e.Kind == "request" && !changed &&
                    fault.StartsWith("request-", StringComparison.Ordinal))
                {
                    var r = e.Value.Deserialize<SettingsPermissionRequest>(SettingsPermissionContract.Options)!;
                    if (r.Phase != "patch") continue;
                    entries[i] = Value(e, fault == "request-input" ? r with { BodyHash = "foreign" } : r with { CredentialId = "foreign" }); changed = true;
                }
                if (p.Journal == SettingsPermissionJournal.Access && e.Kind == "decision" && !changed &&
                    fault.StartsWith("decision-", StringComparison.Ordinal))
                {
                    var d = e.Value.Deserialize<SettingsPermissionDecision>(SettingsPermissionContract.Options)!;
                    if (d.Action != "edit" || !d.Allowed) continue;
                    d = fault switch
                    {
                        "decision-policy" => d with { PolicyHash = "foreign" },
                        "decision-membership" => d with { MembershipHash = "foreign" },
                        "decision-subject" => d with { Subject = "workspace" },
                        _ => d with { RequestHash = "foreign" }
                    };
                    entries[i] = Value(e, d); changed = true;
                }
            }
            if (fault == "duplicate-request" && p.Journal == SettingsPermissionJournal.Ingress) entries.Add(entries.First(e => e.Kind == "request"));
            if (fault == "missing-decision" && p.Journal == SettingsPermissionJournal.Access) entries.RemoveAt(1);
            if (fault == "reordered-commits" && p.Journal == SettingsPermissionJournal.Storage)
            {
                var indices = entries.Select((e, i) => (e, i)).Where(x => x.e.Kind == "change" &&
                    x.e.Value.Deserialize<SettingsPermissionChange>(SettingsPermissionContract.Options)!.DecisionHash.Length > 0).Select(x => x.i).ToArray();
                (entries[indices[0]], entries[indices[1]]) = (entries[indices[1]], entries[indices[0]]);
            }
            if (fault == "intermediate-policy" && p.Journal == SettingsPermissionJournal.Policy)
            {
                var e = entries.First(e => e.Kind == "change");
                var c = e.Value.Deserialize<SettingsPermissionPolicyChange>(SettingsPermissionContract.Options)!;
                entries.Insert(1, Value(e, c with { Request = "unobserved-intermediate" }));
            }
            return s with
            {
                Content = p with
                {
                    Events = entries.ToArray(),
                    Fenced = fault != "unfenced-storage" || p.Journal != SettingsPermissionJournal.Storage,
                    Pending = fault == "pending-storage" && p.Journal == SettingsPermissionJournal.Storage ? 1 : p.Pending
                }
            };
        }).ToArray();
        return packet with { Journals = journals };
    }

    private static SettingsPermissionEvent Value<T>(SettingsPermissionEvent e, T value) =>
        e with { Value = JsonSerializer.SerializeToElement(value, SettingsPermissionContract.Options) };

    private sealed class Signer : IDisposable
    {
        private readonly Dictionary<SettingsPermissionJournal, ECDsa> keys = [];
        internal SettingsPermissionRoot Root { get; }
        internal Signer(SettingsPermissionRoot root)
        {
            foreach (var pin in root.Profile.Pins) keys.Add(pin.Journal, ECDsa.Create(ECCurve.NamedCurves.nistP256));
            Root = root with { Profile = root.Profile with { Pins = root.Profile.Pins.Select(p => p with { Spki = Convert.ToBase64String(keys[p.Journal].ExportSubjectPublicKeyInfo()) }).ToArray() } };
        }
        internal SettingsPermissionPacket Sign(SettingsPermissionPacket packet) => packet with
        {
            Journals = packet.Journals.Select(s =>
            {
                string head = ""; var history = new List<SettingsPermissionEvent>(); var key = keys[s.Content.Journal];
                foreach (var e in s.Content.Events)
                {
                    var next = e with { Sequence = history.Count + 1, Previous = head };
                    if (next.Kind == "enroll") next = Value(next, SettingsPermissionContract.Hash(Root));
                    history.Add(next); head = SettingsPermissionContract.Hash(next);
                }
                var p = s.Content with
                {
                    RootHash = SettingsPermissionContract.Hash(Root),
                    KeyHash = SettingsPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()),
                    Events = history.ToArray(),
                    Count = history.Count,
                    Head = head
                };
                byte[] bytes = SettingsPermissionContract.Bytes(p);
                try { return new SettingsPermissionSigned(p, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }).ToArray()
        };
        public void Dispose() { foreach (var key in keys.Values) key.Dispose(); }
    }
}
