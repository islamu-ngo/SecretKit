using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// These packets have valid signatures from newly enrolled test authorities.
// Rejection must come from semantic joins, not a broken signature or head.
public sealed class InfisicalAuthTemplatePermissionSemanticTests
{
    public static IEnumerable<string> Faults() =>
        ["binding-kind", "binding-scope", "binding-input", "binding-intent", "binding-parent", "binding-id",
         "binding-request", "binding-request-input", "credential-principal", "credential-kind", "credential-hash",
         "state-name", "state-audience", "state-revision", "commit-input", "commit-decision", "commit-missing",
         "policy-request", "membership-position", "request-input", "request-credential", "decision-policy",
         "decision-membership", "decision-subject", "decision-request", "duplicate-request", "missing-decision",
         "reordered-commits", "intermediate-policy", "unfenced-storage", "pending-storage"];

    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task CorrectlySignedButUncausalHistoriesCannotCertifySettings(string fault)
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture();
        string operation = AuthTemplatePermissionContract.Operations[0];
        using var env = provider.Environment(operation, AuthTemplatePermissionAction.Edit);
        var root = provider.Root(operation, AuthTemplatePermissionAction.Edit, "independent-effect");
        using var capability = SecretMaterial.FromText("auth-template-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        AuthTemplatePermissionTrial? retained = null;
        try
        {
            var trial = await AuthTemplatePermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
            await AuthTemplatePermissionEffects.WitnessAsync(env, trial, false, deadline.Token);
            await trial.ArmAsync(deadline.Token);
            await trial.SettleAsync(await AuthTemplatePermissionEffects.DispatchAsync(env, root, trial.Plan, trial.Issued, deadline.Token), deadline.Token);
            await AuthTemplatePermissionEffects.ActivateAsync(env, trial, deadline.Token);
            await AuthTemplatePermissionEffects.WitnessAsync(env, trial, true, deadline.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        var packet = provider.ClosedPacket!;
        using var signer = new Signer(root);
        using (var baseline = new AuthTemplatePermissionVerifier(signer.Root))
            baseline.Check(signer.Sign(packet), AuthTemplatePermissionStep.Close);
        using var verifier = new AuthTemplatePermissionVerifier(signer.Root);
        await InfisicalAuthTemplatePermissionSourceTests.Rejected(() =>
        {
            verifier.Check(signer.Sign(Tamper(packet, fault)), AuthTemplatePermissionStep.Close);
            return Task.CompletedTask;
        });
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }

    private static AuthTemplatePermissionPacket Tamper(AuthTemplatePermissionPacket packet, string fault)
    {
        string original = packet.Values<AuthTemplatePermissionRequest>(AuthTemplatePermissionJournal.Ingress, "request").Single(r => r.Phase == "original").Id;
        string later = packet.Values<AuthTemplatePermissionRequest>(AuthTemplatePermissionJournal.Ingress, "request").Last(r => r.Phase == "observer").Id;
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
                    var b = e.Value.Deserialize<AuthTemplatePermissionBinding>(AuthTemplatePermissionContract.Options)!;
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
                    var c = e.Value.Deserialize<AuthTemplatePermissionCredential>(AuthTemplatePermissionContract.Options)!;
                    if (!c.Owned) continue;
                    c = fault switch
                    {
                        "credential-principal" => c with { Principal = "foreign" },
                        "credential-kind" => c with { Kind = MemberPermissionActorKind.Machine },
                        _ => c with { Hash = "substituted" }
                    };
                    entries[i] = Value(e, c); changed = true;
                }
                if (p.Journal == AuthTemplatePermissionJournal.Storage && e.Kind == "change" && !changed &&
                    (fault.StartsWith("state-", StringComparison.Ordinal) || fault.StartsWith("commit-", StringComparison.Ordinal)))
                {
                    var c = e.Value.Deserialize<AuthTemplatePermissionChange>(AuthTemplatePermissionContract.Options)!;
                    if (c.DecisionHash.Length == 0 || c.Commit.Length == 0) continue;
                    c = fault switch
                    {
                        "state-name" => c with { After = c.After! with { Name = "unpersisted" } },
                        "state-audience" => c with { After = c.After! with { Configuration = c.After.Configuration with { Audience = "unselected-change" } } },
                        "state-revision" => c with { After = c.After! with { Revision = 17 } },
                        "commit-input" => c with { InputHash = "foreign" },
                        "commit-decision" => c with { DecisionHash = "foreign" },
                        _ => c with { Commit = "" }
                    };
                    entries[i] = Value(e, c); changed = true;
                }
                if (p.Journal == AuthTemplatePermissionJournal.Policy && e.Kind == "change" && fault == "policy-request")
                {
                    var c = e.Value.Deserialize<AuthTemplatePermissionPolicyChange>(AuthTemplatePermissionContract.Options)!;
                    if (c.Request == original) entries[i] = Value(e, c with { Request = later });
                }
                if (p.Journal == AuthTemplatePermissionJournal.Membership && e.Kind == "change" && fault == "membership-position")
                {
                    var c = e.Value.Deserialize<AuthTemplatePermissionMemberChange>(AuthTemplatePermissionContract.Options)!;
                    // Final membership is identical, but its grant now claims a
                    // request AFTER the successful PATCH. A final snapshot passes.
                    if (c.Request == packet.Values<AuthTemplatePermissionRequest>(AuthTemplatePermissionJournal.Ingress, "request").Single(r => r.Phase == "activation").Id) entries[i] = Value(e, c with { Request = later });
                }
                if (p.Journal == AuthTemplatePermissionJournal.Ingress && e.Kind == "request" && !changed &&
                    fault.StartsWith("request-", StringComparison.Ordinal))
                {
                    var r = e.Value.Deserialize<AuthTemplatePermissionRequest>(AuthTemplatePermissionContract.Options)!;
                    if (r.Phase != "template") continue;
                    entries[i] = Value(e, fault == "request-input" ? r with { BodyHash = "foreign" } : r with { CredentialId = "foreign" }); changed = true;
                }
                if (p.Journal == AuthTemplatePermissionJournal.Access && e.Kind == "decision" && !changed &&
                    fault.StartsWith("decision-", StringComparison.Ordinal))
                {
                    var d = e.Value.Deserialize<AuthTemplatePermissionDecision>(AuthTemplatePermissionContract.Options)!;
                    if (d.Action != "edit-templates" || !d.Allowed) continue;
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
            if (fault == "duplicate-request" && p.Journal == AuthTemplatePermissionJournal.Ingress) entries.Add(entries.First(e => e.Kind == "request"));
            if (fault == "missing-decision" && p.Journal == AuthTemplatePermissionJournal.Access) entries.RemoveAt(1);
            if (fault == "reordered-commits" && p.Journal == AuthTemplatePermissionJournal.Storage)
            {
                var indices = entries.Select((e, i) => (e, i)).Where(x => x.e.Kind == "change" &&
                    x.e.Value.Deserialize<AuthTemplatePermissionChange>(AuthTemplatePermissionContract.Options)!.DecisionHash.Length > 0).Select(x => x.i).ToArray();
                (entries[indices[0]], entries[indices[1]]) = (entries[indices[1]], entries[indices[0]]);
            }
            if (fault == "intermediate-policy" && p.Journal == AuthTemplatePermissionJournal.Policy)
            {
                var e = entries.First(e => e.Kind == "change");
                var c = e.Value.Deserialize<AuthTemplatePermissionPolicyChange>(AuthTemplatePermissionContract.Options)!;
                entries.Insert(1, Value(e, c with { Request = "unobserved-intermediate" }));
            }
            return s with
            {
                Content = p with
                {
                    Events = entries.ToArray(),
                    Fenced = fault != "unfenced-storage" || p.Journal != AuthTemplatePermissionJournal.Storage,
                    Pending = fault == "pending-storage" && p.Journal == AuthTemplatePermissionJournal.Storage ? 1 : p.Pending
                }
            };
        }).ToArray();
        return packet with { Journals = journals };
    }

    private static AuthTemplatePermissionEvent Value<T>(AuthTemplatePermissionEvent e, T value) =>
        e with { Value = JsonSerializer.SerializeToElement(value, AuthTemplatePermissionContract.Options) };

    private sealed class Signer : IDisposable
    {
        private readonly Dictionary<AuthTemplatePermissionJournal, ECDsa> keys = [];
        internal AuthTemplatePermissionRoot Root { get; }
        internal Signer(AuthTemplatePermissionRoot root)
        {
            foreach (var pin in root.Profile.Pins) keys.Add(pin.Journal, ECDsa.Create(ECCurve.NamedCurves.nistP256));
            Root = root with { Profile = root.Profile with { Pins = root.Profile.Pins.Select(p => p with { Spki = Convert.ToBase64String(keys[p.Journal].ExportSubjectPublicKeyInfo()) }).ToArray() } };
        }
        internal AuthTemplatePermissionPacket Sign(AuthTemplatePermissionPacket packet) => packet with
        {
            Journals = packet.Journals.Select(s =>
            {
                string head = ""; var history = new List<AuthTemplatePermissionEvent>(); var key = keys[s.Content.Journal];
                foreach (var e in s.Content.Events)
                {
                    var next = e with { Sequence = history.Count + 1, Previous = head };
                    if (next.Kind == "enroll") next = Value(next, AuthTemplatePermissionContract.Hash(Root));
                    history.Add(next); head = AuthTemplatePermissionContract.Hash(next);
                }
                var p = s.Content with
                {
                    RootHash = AuthTemplatePermissionContract.Hash(Root),
                    KeyHash = AuthTemplatePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()),
                    Events = history.ToArray(),
                    Count = history.Count,
                    Head = head
                };
                byte[] bytes = AuthTemplatePermissionContract.Bytes(p);
                try { return new AuthTemplatePermissionSigned(p, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }).ToArray()
        };
        public void Dispose() { foreach (var key in keys.Values) key.Dispose(); }
    }
}
