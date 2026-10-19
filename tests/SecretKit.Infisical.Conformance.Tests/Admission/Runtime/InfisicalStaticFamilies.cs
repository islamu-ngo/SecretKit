using System.Diagnostics.Tracing;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalStaticFamilies
{
    public static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, IBulkAuxiliarySource? bulkAuxiliary = null)
    {
        InfisicalClientEffects.Register(registry, env, expected);
        InfisicalStaticChangesEffects.Register(registry, env, expected);
        NativeBulkEffects.Register(registry, env, expected, bulkAuxiliary);
    }

    internal static T Input<T>(NativeEnvironment env, string family, NativeCaseDefinition definition)
    {
        try
        {
            JsonElement scopes = env.RequireFamilyInput(family).GetProperty("scopes");
            return scopes.GetProperty(definition.Key.Scope)
                .GetProperty(definition.Key.Operation).GetProperty(definition.Key.Variant)
                .GetProperty(definition.Key.Case).Deserialize<T>(Options)
                ?? throw new NativeCaseFailureException("missing-input");
        }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new NativeCaseFailureException("missing-input");
        }
    }

    internal static JsonSerializerOptions Options { get; } = new(NativeRunProtocol.JsonOptions)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    internal static bool Case(string value, bool mutation) => value is
        "selected-contract" or "denied-authority" or "cancellation-boundary" or "independent-effect" ||
        mutation && value == "lost-response-no-replay";

    internal static bool Unchanged(StaticExpectedSecret[] expected, StaticSeed[] seeds) =>
        expected.All(s => seeds.SingleOrDefault(seed => seed.Key == s.Key) is { } seed ?
            s.Status == SecretStatus.Success && s.Value == seed.Value :
            s.Status == SecretStatus.Absent && s.Value is null);

    internal static async ValueTask BoundedAsync(NativeCaseProbe probe, CancellationToken token,
        Func<CancellationToken, ValueTask> execute)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(40));
        try { await execute(deadline.Token); }
        catch (NativeCaseFailureException error)
        {
            probe.Contract(false, error.Message switch
            {
                "missing-input" => NativeFailure.MissingInput,
                "contract-mismatch" => NativeFailure.ContractMismatch,
                "observer-unavailable" => NativeFailure.ObserverUnavailable,
                "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                _ => NativeFailure.UnexpectedFailure
            });
        }
        catch (OperationCanceledException)
        {
            probe.Contract(false, token.IsCancellationRequested ?
                NativeFailure.UnexpectedCancellation : NativeFailure.DeadlineExceeded);
        }
        catch (Exception error) when (error is ArgumentException or JsonException or KeyNotFoundException)
        {
            probe.Contract(false, NativeFailure.MissingInput);
        }
    }

    internal static async ValueTask<StaticDispatch<T>> DispatchAsync<T>(NativeEnvironment env,
        NativeCaseDefinition definition, NativeCaseProbe probe,
        Func<CancellationToken, ValueTask<SecretOutcome<T>>> call, CancellationToken token) where T : notnull
    {
        if (definition.Key.Case is not ("cancellation-boundary" or "lost-response-no-replay"))
            return new(await call(token), false);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var boundary = new StaticSendBoundary(env.Origin, cancellation,
            definition.Key.Case == "lost-response-no-replay");
        bool cancelled = false;
        SecretOutcome<T>? outcome = null;
        try { outcome = await call(cancellation.Token); }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested)
        {
            cancelled = true;
        }
        probe.Contract(boundary.Reached.Task.IsCompletedSuccessfully && cancelled,
            NativeFailure.ContractMismatch);
        return new(outcome, cancelled);
    }
}

internal sealed record StaticDispatch<T>(SecretOutcome<T>? Outcome, bool Cancelled) where T : notnull;

// Every field arrives through the existing protected stdin protocol, never environment variables.
internal sealed record StaticFixtureInput(string ProjectId, string Environment, string EnvironmentId,
    string OwnedNamespace, StaticSeed[] Seeds, StaticApiRevision ApiRevision)
{
    public override string ToString() => "[StaticFixtureInput]";
}

// Names the fixed native endpoint contracts, not a vendor software-version claim.
internal enum StaticApiRevision { SecretsV4FoldersV2 }

internal sealed record StaticSeed(string Key, string Value)
{
    public override string ToString() => "[StaticSeed]";
}

internal sealed record StaticExpectedSecret(string Key, SecretStatus Status, string? Value, int? Version)
{
    public override string ToString() => "[StaticExpectedSecret]";
}

internal sealed class StaticOwnedFixture : IAsyncDisposable
{
    private readonly NativeEnvironment env;
    private readonly NativeCaseProbe probe;
    private readonly string scope;
    private readonly List<(string Parent, string Name, string? Id)> folders = [];
    internal StaticFixtureInput Input { get; }
    internal InfisicalClient Setup { get; }
    internal InfisicalClient Runtime { get; }
    internal InfisicalClient Denied { get; }
    internal InfisicalClient Administrative { get; }
    internal InfisicalClient Observer { get; }
    internal string Folder { get; private set; } = "";
    internal string FolderId { get; private set; } = "";

    internal StaticOwnedFixture(NativeEnvironment env, StaticFixtureInput input,
        NativeCaseProbe probe, string scope)
    {
        if (string.IsNullOrWhiteSpace(input.OwnedNamespace) || input.OwnedNamespace == "/" ||
            !input.OwnedNamespace.StartsWith('/') ||
            input.OwnedNamespace.Split('/').Any(p => p is "." or "..") ||
            !Guid.TryParse(input.EnvironmentId, out _) || input.Seeds is null ||
            input.Seeds.Length > 128 || input.Seeds.Any(s => string.IsNullOrWhiteSpace(s.Key)) ||
            input.Seeds.Select(s => s.Key).Distinct(StringComparer.Ordinal).Count() != input.Seeds.Length ||
            input.ApiRevision != StaticApiRevision.SecretsV4FoldersV2)
            throw new NativeCaseFailureException("missing-input");
        this.env = env;
        Input = input;
        this.probe = probe;
        this.scope = scope;
        Setup = env.CreateClient(NativeIdentityRole.Setup);
        Runtime = env.CreateRuntimeClient();
        Denied = env.CreateDeniedClient();
        Administrative = env.CreateClient(NativeIdentityRole.Administrative);
        Observer = env.CreateObserverClient();
    }

    internal SecretReference Secret(InfisicalClient client, string key, string? folder = null,
        int? version = null, InfisicalResolution resolution = InfisicalResolution.Raw, bool imports = false) =>
        new(client.Authority, new InfisicalSecretAddress(Input.ProjectId, Input.Environment,
            folder ?? Folder, key, version, resolution, imports));

    internal InfisicalNativeAuthority Authority(InfisicalClient client, NativeIdentityRole role,
        string? folder = null) => new(client.Authority, env.Tokens(role), Input.ProjectId,
            Input.Environment, folder ?? Folder);

    internal async ValueTask InitializeAsync(CancellationToken token, string? folderName = null)
    {
        (Folder, FolderId) = await AddFolderAsync(token, folderName);
        foreach (StaticSeed seed in Input.Seeds)
            await SeedAsync(seed.Key, seed.Value, Folder, token);
        // An observer fetch proves access with the selected credential, not that
        // two opaque tokens belong to different service principals.
    }

    internal async ValueTask<(string Path, string Id)> AddFolderAsync(CancellationToken token, string? folderName = null)
    {
        string parent = Input.OwnedNamespace.TrimEnd('/');
        string name = folderName ?? "sk-" + Guid.NewGuid().ToString("N");
        string path = parent + "/" + name;
        var target = new SecretReference(Setup.Authority, new InfisicalFolderAddress(
            Input.ProjectId, Input.Environment, Input.EnvironmentId, parent, name: name));
        var receipt = new MutationReceipt(target);
        // Ownership is recorded before send, so a lost setup response still gets name-scoped cleanup.
        folders.Add((parent, name, null));
        SecretOutcome<InfisicalFolder> created = await Setup.CreateFolderAsync(target,
            Authority(Setup, NativeIdentityRole.Setup, parent), receipt, cancellationToken: token);
        probe.Contract(created.IsSuccess && receipt.Evidence == DispatchEvidence.Applied,
            NativeFailure.MissingPrerequisite);
        folders[^1] = (parent, name, created.Value.Id);
        var observedTarget = new SecretReference(Observer.Authority, new InfisicalFolderAddress(
            Input.ProjectId, Input.Environment, Input.EnvironmentId, parent, created.Value.Id, name));
        SecretOutcome<InfisicalFolder> observed = await Observer.GetFolderAsync(observedTarget, token);
        probe.Contract(observed.IsSuccess && observed.Value.Name == name &&
            observed.Value.Id == created.Value.Id, NativeFailure.ObserverUnavailable);
        return (path, created.Value.Id);
    }

    internal async ValueTask SeedAsync(string key, string value, string folder, CancellationToken token)
    {
        SecretReference target = Secret(Setup, key, folder);
        var receipt = new MutationReceipt(target);
        using SecretMaterial material = SecretMaterial.FromText(value);
        SecretOutcome<InfisicalStaticChange> seeded = await Setup.CreateAsync(target, material, receipt, token);
        probe.Contract(seeded.IsSuccess && seeded.Value.Disposition == InfisicalChangeDisposition.Applied &&
            receipt.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
        await ObserveAsync([new(key, SecretStatus.Success, value, null)], token, folder, recordEffect: false);
    }

    internal async ValueTask ObserveAsync(IReadOnlyList<StaticExpectedSecret> expected,
        CancellationToken token, string? folder = null, int? version = null,
        InfisicalResolution resolution = InfisicalResolution.Raw, bool imports = false,
        bool denied = false, bool recordEffect = true)
    {
        if (expected.Count is 0 or > 128)
            probe.Contract(false, NativeFailure.MissingInput);
        foreach (StaticExpectedSecret state in expected)
        {
            if (state.Status is not (SecretStatus.Success or SecretStatus.Absent) ||
                state.Status == SecretStatus.Success && state.Value is null)
                probe.Contract(false, NativeFailure.MissingInput);
            SecretOutcome<SecretRead> observation = await Observer.ReadAsync(
                Secret(Observer, state.Key, folder, version, resolution, imports), token);
            if (observation.IsSuccess)
            {
                using SecretRead read = observation.Value;
                Observation(state.Status == SecretStatus.Success && read.Material.Reveal() == state.Value &&
                    (state.Version is null || read.Observation.Version == state.Version.Value.ToString(CultureInfo.InvariantCulture))
                    ? NativeObservation.Matched : NativeObservation.Mismatched, recordEffect);
            }
            else
                Observation(observation.Status == state.Status ? NativeObservation.Matched :
                    observation.Status is SecretStatus.Denied or SecretStatus.Unavailable or SecretStatus.Unknown
                        ? NativeObservation.Unavailable : NativeObservation.Mismatched, recordEffect);

            InfisicalClient reader = denied ? Denied : Runtime;
            SecretOutcome<SecretRead> delivered = await reader.ReadAsync(
                Secret(reader, state.Key, folder, version, resolution, imports), token);
            if (delivered.IsSuccess)
            {
                using SecretRead read = delivered.Value;
                Observation(!denied && state.Status == SecretStatus.Success &&
                    read.Material.Reveal() == state.Value ? NativeObservation.Matched : NativeObservation.Mismatched, recordEffect);
            }
            else
                Observation(delivered.Status == (denied ? SecretStatus.Denied : state.Status)
                    ? NativeObservation.Matched : NativeObservation.Mismatched, recordEffect);
        }
        // Principal identity needs its own authority-bound witness; token selection
        // and a successful read must not be promoted into that prerequisite.
        // The origin is immutable, redirects are disabled, and the separately credentialed
        // folder-v2/secret-v4 reads actually fetched this fixture's owned scoped state.
        env.ConfirmPrerequisite(scope, "owned-origin-api-revision", NativeObservation.Matched);
    }

    private void Observation(NativeObservation observation, bool recordEffect)
    {
        if (recordEffect) probe.Effect(observation);
        else probe.Contract(observation == NativeObservation.Matched, observation == NativeObservation.Unavailable ?
            NativeFailure.ObserverUnavailable : NativeFailure.MissingPrerequisite);
    }

    public async ValueTask DisposeAsync()
    {
        bool clean = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            // Sibling source folders are created after the destination; remove its imports first.
            foreach (var folder in folders)
            {
                try
                {
                    var target = new SecretReference(Administrative.Authority, new InfisicalFolderAddress(
                        Input.ProjectId, Input.Environment, Input.EnvironmentId, folder.Parent,
                        folder.Id, folder.Name));
                    var receipt = new MutationReceipt(target);
                    SecretOutcome<InfisicalFolder> result = await Administrative.DeleteFolderAsync(target,
                        Authority(Administrative, NativeIdentityRole.Administrative, folder.Parent),
                        receipt, forceDelete: true, cancellationToken: deadline.Token);
                    var scopeTarget = new SecretReference(Observer.Authority, new InfisicalFolderAddress(
                        Input.ProjectId, Input.Environment, Input.EnvironmentId, folder.Parent));
                    SecretOutcome<InfisicalNativeList<InfisicalFolder>> remaining =
                        await Observer.ListFoldersAsync(scopeTarget, cancellationToken: deadline.Token);
                    clean &= (result.IsSuccess || result.Status == SecretStatus.Absent) &&
                        remaining.IsSuccess && remaining.Value.IsComplete &&
                        !remaining.Value.Items.Any(f => f.Name == folder.Name);
                }
                catch (Exception) { clean = false; }
            }
        }
        finally
        {
            foreach (InfisicalClient client in new[] { Setup, Runtime, Denied, Administrative, Observer })
            {
                try { await client.DisposeAsync(); }
                catch (Exception) { clean = false; }
            }
            env.ConfirmPrerequisite(scope, "approved-sandbox-cleanup",
                clean ? NativeObservation.Matched : NativeObservation.Mismatched);
            if (!clean) probe.Contract(false, NativeFailure.CleanupIncomplete);
        }
    }
}

// The SDK disables diagnostic propagation. HttpClient's BCL EventSource still exposes
// correlated request/header events without replacing transport or reflecting SDK members.
// HeadersStart is the send boundary, not proof of provider receipt. HeadersStop on
// the response loses the body before the SDK can acknowledge it; no mutation is replayed.
internal sealed class StaticSendBoundary : EventListener
{
    private static readonly AsyncLocal<StaticSendBoundary?> Current = new();
    private readonly StaticSendBoundary? previous;
    private readonly Uri? origin;
    private readonly CancellationTokenSource? cancellation;
    private readonly bool loseResponse;
    private bool selected;
    internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal StaticSendBoundary(Uri origin, CancellationTokenSource cancellation, bool loseResponse)
    {
        this.origin = origin;
        this.cancellation = cancellation;
        this.loseResponse = loseResponse;
        previous = Current.Value;
        Current.Value = this;
    }

    protected override void OnEventSourceCreated(EventSource source)
    {
        if (source.Name == "System.Net.Http")
            EnableEvents(source, EventLevel.Verbose, EventKeywords.All);
    }

    protected override void OnEventWritten(EventWrittenEventArgs value)
    {
        // EventListener can receive source callbacks during its base constructor.
        if (origin is null || cancellation is null || !ReferenceEquals(Current.Value, this)) return;
        // The execution context identifies this exact SDK dispatch even when EventSource
        // activity IDs are unavailable. Concurrent fixture/observer dispatches cannot match.
        if (value.EventName == "RequestStart" && value.Payload is { Count: >= 4 } fields &&
            fields[0] is string scheme && scheme == origin.Scheme &&
            fields[1] is string host && host == origin.Host &&
            fields[2] is int port && port == origin.Port &&
            fields[3] is string path && path.StartsWith("/api/v4/secrets", StringComparison.Ordinal))
            selected = true;
        bool reached = selected && value.EventName ==
            (loseResponse ? "ResponseHeadersStop" : "RequestHeadersStart");
        if (reached && Reached.TrySetResult()) cancellation.Cancel();
    }

    public override void Dispose()
    {
        if (ReferenceEquals(Current.Value, this)) Current.Value = previous;
        base.Dispose();
    }
}
