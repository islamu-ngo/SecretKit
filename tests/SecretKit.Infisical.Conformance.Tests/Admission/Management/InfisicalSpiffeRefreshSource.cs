using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Interface facts retrieved separately through Tavily on 2026-10-14:
// https://infisical.com/docs/documentation/platform/identities/spiffe-auth
// https://infisical.com/docs/api-reference/endpoints/machine-identities/spiffe-auth/refresh-bundle
// HTTPS bundles are fetched on demand and cached; this endpoint forces a fetch.
// Static refresh and immediate retirement are NOT established by those contracts.
// This private service protocol is independently designed, not a vendor API.
internal enum SpiffeRefreshSourceKind { NativeProvider, ControlledFixture }
internal sealed record SpiffeRefreshRoot(string Id, string Nonce, string OrganizationId, string IdentityId,
    string Case, string Deployment, string SourceIdentity, SpiffeRefreshSourceKind Source,
    string ProviderRevision, string Operation, string Variant, string Scope)
{
    public override string ToString() => "[SpiffeRefreshRoot]";
}
internal sealed record SpiffeRefreshBinding(SpiffeRefreshRoot Root, string Registration, string BaselineKey,
    string NewKey, string WrongKey, bool IndependentIssuer, bool IndependentCache, bool BorrowedPreserved)
{
    public override string ToString() => "[SpiffeRefreshBinding]";
}
internal sealed record SpiffeRefreshArm(SpiffeRefreshBinding Binding, string Window, string BundleRevision,
    bool ExclusiveIngress, bool ClockHeld, bool BaselineCachePreserved)
{
    public override string ToString() => "[SpiffeRefreshArm]";
}
internal sealed record SpiffeRefreshReceipt(DispatchEvidence Evidence, SecretStatus Status, bool Cancelled);
internal sealed record SpiffeRefreshSettlement(SpiffeRefreshArm Arm, SpiffeRefreshReceipt Receipt,
    int Requests, int Fetches, int CacheCommits, int ForeignRequests, int PendingWork,
    bool OriginalTerminal, bool ExcludesLateWork, bool NoReplay, bool Complete,
    bool OldKeyPresent, bool NewKeyPresent, bool WrongKeyPresent, bool BorrowedPreserved)
{
    public override string ToString() => "[SpiffeRefreshSettlement]";
}
internal sealed record SpiffeRefreshProofFacts(SpiffeRefreshArm? Arm, string Registration, string Phase,
    string Proof, bool Allowed, int IssuedTokens, bool Complete)
{
    public override string ToString() => "[SpiffeRefreshProofFacts]";
}
internal sealed record SpiffeRefreshCleanup(SpiffeRefreshRoot Root, bool OriginalTerminal, bool ExcludesLateWork,
    bool OwnedAbsent, bool BorrowedPreserved, bool CopiesDestroyed, int Registrations, int PendingWork)
{
    public override string ToString() => "[SpiffeRefreshCleanup]";
}

internal interface IInfisicalSpiffeRefreshSource
{
    ValueTask<SpiffeRefreshBinding> OpenAsync(SpiffeRefreshRoot root, SecretMaterial capability, CancellationToken token);
    ValueTask<SpiffeRefreshArm> ArmAsync(SpiffeRefreshBinding binding, CancellationToken token);
    ValueTask<SpiffeRefreshSettlement> SettleAsync(SpiffeRefreshArm arm, SpiffeRefreshReceipt receipt, CancellationToken token);
    ValueTask<SpiffeRefreshProofFacts> ProofAsync(SpiffeRefreshBinding binding, SpiffeRefreshArm? arm,
        string phase, string proof, SecretMaterial jwt, CancellationToken token);
    ValueTask<SpiffeRefreshCleanup> CloseAsync(SpiffeRefreshRoot root, CancellationToken token);
}

// Concrete capability client; native all-ingress fencing and journal independence
// require separate service qualification. The transport remains host-owned.
internal sealed class InfisicalSpiffeRefreshSource(InfisicalLifecycleObservers channel,
    string identity, SpiffeRefreshSourceKind kind = SpiffeRefreshSourceKind.NativeProvider)
    : IInfisicalSpiffeRefreshSource
{
    private readonly Dictionary<string, SpiffeRefreshRoot> roots = new(StringComparer.Ordinal);
    private readonly HashSet<string> calls = new(StringComparer.Ordinal);
    private readonly HashSet<string> closed = new(StringComparer.Ordinal);

    public ValueTask<SpiffeRefreshBinding> OpenAsync(SpiffeRefreshRoot root, SecretMaterial capability, CancellationToken token)
    {
        lock (roots)
        {
            Require(root.SourceIdentity == identity && root.Source == kind &&
                root.Operation == "i.management.ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle" &&
                root.Variant == "input.organizationId-identityId" &&
                !string.IsNullOrWhiteSpace(root.ProviderRevision) && !string.IsNullOrWhiteSpace(root.Scope) &&
                root.Case is "selected-contract" or "independent-effect" or "denied-authority" or
                    "cancellation-boundary" or "lost-response-no-replay" &&
                roots.Values.All(r => r.Nonce != root.Nonce) && roots.TryAdd(root.Id, root), "missing-input");
        }
        return Post<SpiffeRefreshBinding>(root, "open", w =>
        {
            Write(w, "root", root);
            char[] copy = capability.ExportCharacters();
            try { w.WriteString("capability", copy); }
            finally { Array.Clear(copy); }
        }, token);
    }

    public ValueTask<SpiffeRefreshArm> ArmAsync(SpiffeRefreshBinding binding, CancellationToken token) =>
        Post<SpiffeRefreshArm>(binding.Root, "arm", w => Write(w, "binding", binding), token);
    public ValueTask<SpiffeRefreshSettlement> SettleAsync(SpiffeRefreshArm arm, SpiffeRefreshReceipt receipt,
        CancellationToken token) => Post<SpiffeRefreshSettlement>(arm.Binding.Root, "settle", w =>
        {
            Write(w, "arm", arm);
            Write(w, "receipt", receipt);
        }, token);
    public ValueTask<SpiffeRefreshProofFacts> ProofAsync(SpiffeRefreshBinding binding, SpiffeRefreshArm? arm,
        string phase, string proof, SecretMaterial jwt, CancellationToken token) =>
        Post<SpiffeRefreshProofFacts>(binding.Root, phase + "-" + proof, w =>
        {
            Require(phase is "before" or "after" &&
                proof is "old" or "new" or "wrong-key" or "wrong-domain" or "wrong-audience");
            Write(w, "binding", binding);
            Write(w, "arm", arm);
            w.WriteString("phase", phase);
            w.WriteString("proof", proof);
            char[] copy = jwt.ExportCharacters();
            try { w.WriteString("jwt", copy); }
            finally { Array.Clear(copy); }
        }, token, "proof");
    public ValueTask<SpiffeRefreshCleanup> CloseAsync(SpiffeRefreshRoot root, CancellationToken token) =>
        Post<SpiffeRefreshCleanup>(root, "close", w => Write(w, "root", root), token);

    private ValueTask<T> Post<T>(SpiffeRefreshRoot root, string call, Action<Utf8JsonWriter> fields,
        CancellationToken token, string? route = null) where T : notnull
    {
        lock (roots)
        {
            Require(roots.TryGetValue(root.Id, out var registered) && registered == root &&
                !closed.Contains(root.Id) && calls.Add(root.Id + "/" + call));
            if (call == "close") closed.Add(root.Id); // no retry even after a lost reply
        }
        return channel.PostAsync<T>("spiffe-refresh/" + (route ?? call), fields, token);
    }
    private static void Write<T>(Utf8JsonWriter w, string name, T value)
    {
        w.WritePropertyName(name);
        JsonSerializer.Serialize(w, value, InfisicalLifecycleFamilies.Options);
    }
    internal static void Require(bool condition, string reason = "effect-mismatch")
    {
        if (!condition) throw new NativeCaseFailureException(reason);
    }
    public override string ToString() => "[InfisicalSpiffeRefreshSource]";
}

internal sealed record SpiffeRefreshInput(InfisicalLifecycleObservers.Settings Observer, string Deployment,
    string Capability, SpiffeRefreshSourceKind Source, string ProviderRevision, string BundleEndpoint, string CaCertificate,
    string TrustDomain, string SpiffeId, string Audience, string OldJwt, string NewJwt,
    string WrongKeyJwt, string WrongDomainJwt, string WrongAudienceJwt)
{
    internal static SpiffeRefreshInput? FromInputs(NativeEnvironment environment)
    {
        JsonElement family = environment.RequireFamilyInput("ExternalIdentityAuthentication");
        if (!family.TryGetProperty("spiffeRefresh", out var selected)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(selected);
            var input = selected.Deserialize<SpiffeRefreshInput>(InfisicalLifecycleFamilies.Options);
            InfisicalSpiffeRefreshSource.Require(input is not null, "missing-input");
            input!.Validate();
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    internal void Validate()
    {
        InfisicalSpiffeRefreshSource.Require(Enum.IsDefined(Source) &&
            new[] { Deployment, Capability, ProviderRevision, CaCertificate, TrustDomain, SpiffeId, Audience, OldJwt, NewJwt,
                WrongKeyJwt, WrongDomainJwt, WrongAudienceJwt }.All(s => !string.IsNullOrWhiteSpace(s)) &&
            new[] { OldJwt, NewJwt, WrongKeyJwt, WrongDomainJwt, WrongAudienceJwt }.Distinct().Count() == 5 &&
            Uri.TryCreate(BundleEndpoint, UriKind.Absolute, out var endpoint) && endpoint.Scheme == "https" &&
            endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0 &&
            Uri.TryCreate(SpiffeId, UriKind.Absolute, out var id) && id.Scheme == "spiffe" &&
            id.Host == TrustDomain, "missing-input");
        _ = new InfisicalLifecycleObservers(Observer); // validate before ownership
    }
    internal string Jwt(string proof) => proof switch
    {
        "old" => OldJwt,
        "new" => NewJwt,
        "wrong-key" => WrongKeyJwt,
        "wrong-domain" => WrongDomainJwt,
        "wrong-audience" => WrongAudienceJwt,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    public override string ToString() => "[SpiffeRefreshInput]";
}
