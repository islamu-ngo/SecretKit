using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalRotationClientEffects
{
    internal const string Family = "C08-IR-InfisicalRotationClient";
    private const string Prefix = "i.runtime.InfisicalRotationClient.";

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, IInfisicalRotationFixtureFactory? factory = null,
        IInfisicalRotationBackendObserver? backend = null, HttpMessageHandler? offlineTransport = null,
        Func<NativeEnvironment, InfisicalClient>? offlineConsumerFactory = null,
        IInfisicalRotationMaterialSource? rotationMaterials = null,
        Func<NativeIdentityRole, InfisicalClient>? rotationMaterialConsumers = null,
        IInfisicalRotationMutationSource? rotationMutations = null,
        Func<NativeIdentityRole, InfisicalClient>? rotationMutationConsumers = null)
    {
        foreach (var row in expected.Where(d => d.Key.Provider == "Infisical" &&
            d.Key.Operation.StartsWith(Prefix, StringComparison.Ordinal)))
            registry.Add(new(row, (probe, token) => InfisicalLifecycleFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, row, probe, factory, backend, offlineTransport, offlineConsumerFactory,
                    rotationMaterials, rotationMaterialConsumers, rotationMutations, rotationMutationConsumers, bounded))));
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition row, NativeCaseProbe probe,
        IInfisicalRotationFixtureFactory? factory, IInfisicalRotationBackendObserver? backend,
        HttpMessageHandler? offlineTransport, Func<NativeEnvironment, InfisicalClient>? offlineConsumerFactory,
        IInfisicalRotationMaterialSource? rotationMaterials,
        Func<NativeIdentityRole, InfisicalClient>? rotationMaterialConsumers,
        IInfisicalRotationMutationSource? rotationMutations,
        Func<NativeIdentityRole, InfisicalClient>? rotationMutationConsumers,
        CancellationToken token)
    {
        InfisicalLifecycleFamilies.Admission(row, probe);
        if (RotationMaterialEffects.Selected(env, row))
        {
            await RotationMaterialEffects.ExecuteAsync(env, row, probe, rotationMaterials,
                offlineTransport, rotationMaterialConsumers, token);
            return;
        }
        if (RotationMutationEffects.Selected(env, row))
        {
            await RotationMutationEffects.ExecuteAsync(env, row, probe, rotationMutations,
                offlineTransport, rotationMutationConsumers, token);
            return;
        }
        RotationInput input = InfisicalLifecycleFamilies.Input<RotationInput>(env, Family, row);
        backend ??= InfisicalLifecycleObservers.FromInputs(env, Family);
        ArgumentNullException.ThrowIfNull(input.Backend);
        string method = row.Key.Operation[Prefix.Length..];
        string variant = row.Key.Variant;
        probe.Contract(Enum.IsDefined(input.Profile) && input.MaximumItems is > 0 and <= 4096 &&
            input.Backend.Profile == input.Profile &&
            input.AllowedActions is { Length: > 0 } && input.DeniedActions is { Length: > 0 } &&
            (!variant.StartsWith("profile.", StringComparison.Ordinal) || variant == "profile." + input.Profile),
            NativeFailure.MissingInput);
        // A native send-boundary cancellation leaves server completion uncertain.
        // A current snapshot cannot rule out a later mutation. Controlled offline
        // transports prove their own pre-send behavior, not this native contract.
        if (row.Key.Case == "cancellation-boundary" && offlineTransport is null &&
            method is "RotateSecretsAsync" or "SetAutomaticRotationAsync" &&
            variant is not ("precondition.RequireCompareAndSwap.rejected" or "precondition.RequireIdempotency.rejected"))
            probe.Effect(NativeObservation.Unavailable);
        if (factory is null && input.Profile is not (InfisicalRotationProfile.PostgresCredentials or
            InfisicalRotationProfile.MysqlCredentials or InfisicalRotationProfile.MssqlCredentials))
            probe.Contract(false, NativeFailure.MissingPrerequisite);
        // The fixture factory is invoked only in Execute, never during registration.
        IInfisicalRotationOwnedFixture fixture = factory is null ?
            await DatabaseRotationFixture.CreateAsync(env, input, probe, row.Key.Scope, token) :
            await factory.CreateAsync(env, input, probe, token);
        try
        {
            InfisicalRotationAddress address = fixture.Address;
            probe.Contract(address.Profile == input.Profile && address.ProjectId == input.Sandbox.ProjectId &&
                address.Environment == input.Sandbox.Environment &&
                address.Folder != input.Sandbox.Parent, NativeFailure.MissingPrerequisite);
            bool denied = row.Key.Case == "denied-authority";
            bool cancel = row.Key.Case == "cancellation-boundary";
            bool lost = row.Key.Case == "lost-response-no-replay";
            bool mutation = method is "RotateSecretsAsync" or "SetAutomaticRotationAsync";
            bool enabled = variant == "enabled.true" || variant != "enabled.false" && input.Enabled;
            var precondition = variant switch
            {
                "precondition.RequireCompareAndSwap.rejected" => InfisicalRotationPrecondition.RequireCompareAndSwap,
                "precondition.RequireIdempotency.rejected" => InfisicalRotationPrecondition.RequireIdempotency,
                _ => InfisicalRotationPrecondition.None
            };
            using var transport = new LifecycleTransport(row.Key.Case, offlineTransport);
            using var http = new HttpClient(transport) { Timeout = Timeout.InfiniteTimeSpan };
            var authority = new SecretAuthority();
            var role = denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime;
            var client = new InfisicalRotationClient(env.Origin, http, authority,
                new(authority, env.Tokens(role), address.ProjectId));
            var target = new SecretReference(authority, address);
            InfisicalRotationReceipt? receipt = mutation ? new(target, method == "RotateSecretsAsync" ?
                InfisicalRotationAction.RotateSecrets : enabled ? InfisicalRotationAction.EnableAutomaticRotation :
                    InfisicalRotationAction.DisableAutomaticRotation) : null;

            using var observerHttp = new HttpClient(new LifecycleTransport(transport: offlineTransport))
            { Timeout = Timeout.InfiniteTimeSpan };
            var observerAuthority = new SecretAuthority();
            var observer = new InfisicalRotationClient(env.Origin, observerHttp, observerAuthority,
                new(observerAuthority, env.Tokens(NativeIdentityRole.Observer), address.ProjectId));
            var observerTarget = new SecretReference(observerAuthority, address);
            var before = await observer.GetAsync(observerTarget, token);
            probe.Contract(before.IsSuccess, NativeFailure.ObserverUnavailable);
            RotationBackendFacts? baseline = backend is null ? null :
                await backend.MeasureAsync(fixture.Coordinate, token);
            if (baseline is not null)
                probe.Contract(baseline.Coordinate == fixture.Coordinate &&
                    baseline.Authentication == BackendAuthentication.Accepted &&
                    baseline.PasswordGeneration >= 0, NativeFailure.ObserverUnavailable);
            // This subscription is a backend event, not a returned rotation job/status.
            await using IInfisicalRotationBackendSubscription? change = backend is null ? null :
                await backend.SubscribeAsync(fixture.Coordinate, token);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            Task boundary = transport.Reached.Task;
            Task? cancellationTask = cancel && precondition == InfisicalRotationPrecondition.None ?
                boundary.ContinueWith(_ => cancellation.Cancel(), CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default) : null;
            transport.Arm();
            SecretStatus status = SecretStatus.Unknown;
            try
            {
                switch (method)
                {
                    case "GetAsync":
                        var got = await client.GetAsync(target, cancellation.Token);
                        status = got.Status;
                        if (got.IsSuccess) probe.Contract(SameAddress(got.Value.Address, address) &&
                            !got.Value.ConsumerDeliveryVerified && !got.Value.FleetConvergenceVerified,
                            NativeFailure.ContractMismatch);
                        break;
                    case "ListAsync":
                        var list = await client.ListAsync(new(authority, new InfisicalRotationScope(address.ProjectId)),
                            input.MaximumItems, cancellation.Token);
                        status = list.Status;
                        if (list.IsSuccess) probe.Contract(list.Value.Items.Count <= input.MaximumItems &&
                            list.Value.Items.Any(p => SameAddress(p.Address, address)), NativeFailure.ContractMismatch);
                        break;
                    case "RotateSecretsAsync":
                        status = (await client.RotateSecretsAsync(target, receipt!, precondition, cancellation.Token)).Status;
                        break;
                    case "SetAutomaticRotationAsync":
                        status = (await client.SetAutomaticRotationAsync(target, enabled, receipt!, precondition,
                            cancellation.Token)).Status;
                        break;
                    default:
                        probe.Contract(false, NativeFailure.ContractMismatch);
                        break;
                }
            }
            catch (OperationCanceledException) when (cancel && boundary.IsCompletedSuccessfully && !token.IsCancellationRequested) { }
            if (cancellationTask is not null) await cancellationTask.WaitAsync(token);
            bool rejected = precondition != InfisicalRotationPrecondition.None;
            probe.Contract(status == (rejected ? SecretStatus.Unsupported : cancel || lost ? SecretStatus.Unknown :
                denied ? SecretStatus.Denied : SecretStatus.Success), NativeFailure.ContractMismatch);
            if ((cancel || lost) && !rejected) probe.Contract(boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            if (receipt is not null)
            {
                probe.Contract(receipt.Dispatch == (rejected ? InfisicalRotationDispatch.NotDispatched :
                    cancel || lost ? InfisicalRotationDispatch.ResponseUnknown :
                    denied ? InfisicalRotationDispatch.Rejected : InfisicalRotationDispatch.ResponseObserved),
                    NativeFailure.ContractMismatch);
                probe.Contract(receipt.Effect == (rejected || denied || cancel || lost ? InfisicalRotationEffect.Unknown :
                    method == "RotateSecretsAsync" ? InfisicalRotationEffect.AcceptedPending :
                    InfisicalRotationEffect.AutomaticRotationSettingApplied), NativeFailure.ContractMismatch);
            }
            transport.Disarm();
            var after = await observer.GetAsync(observerTarget, token);
            probe.Contract(after.IsSuccess && SameAddress(after.Value.Address, address), NativeFailure.ObserverUnavailable);
            if (method == "SetAutomaticRotationAsync" && !denied && !cancel && !rejected)
                probe.Contract(after.Value.AutoRotationEnabled == enabled, NativeFailure.EffectMismatch);
            // Provider configuration readback is necessary but never enough to pass.
            if (backend is null || change is null) probe.Effect(NativeObservation.Unavailable);
            RotationBackendFacts facts = mutation && !denied && !cancel && !rejected ?
                await change!.Observed.WaitAsync(token) : await backend!.MeasureAsync(fixture.Coordinate, token);
            if (facts.Authentication == BackendAuthentication.Unavailable)
                probe.Effect(NativeObservation.Unavailable);
            bool changed = (method == "RotateSecretsAsync" || method == "SetAutomaticRotationAsync" && enabled) &&
                !denied && !cancel && !rejected;
            bool twoAccountSql = input.Profile is InfisicalRotationProfile.PostgresCredentials or
                InfisicalRotationProfile.MysqlCredentials or InfisicalRotationProfile.MssqlCredentials;
            probe.Contract(facts.Coordinate == fixture.Coordinate &&
                facts.Authentication == BackendAuthentication.Accepted &&
                facts.AllowedActions.SequenceEqual(input.AllowedActions) &&
                facts.DeniedActions.SequenceEqual(input.DeniedActions) &&
                (changed ? facts.PasswordGeneration > baseline!.PasswordGeneration &&
                    (!twoAccountSql || facts.PasswordGeneration == baseline.PasswordGeneration + 1) &&
                    facts.PreviousActiveCredentialAuthentication == (twoAccountSql ?
                        BackendAuthentication.Accepted : BackendAuthentication.Rejected) :
                    facts.PasswordGeneration == baseline!.PasswordGeneration), NativeFailure.EffectMismatch);
            if (method == "SetAutomaticRotationAsync" && !denied && !cancel && !rejected)
                probe.Contract(facts.Event == (enabled ? RotationBackendEvent.ScheduledCredentialChange :
                    RotationBackendEvent.ScheduledOpportunityWithoutChange), NativeFailure.EffectMismatch);
            if (method == "RotateSecretsAsync" && !denied && !cancel && !rejected)
                probe.Contract(facts.Event == RotationBackendEvent.ManualCredentialChange, NativeFailure.EffectMismatch);
            // The selected intended consumer exports the two generated credential fields and
            // asks the backend to actually authenticate them; provider success is not delivery.
            await using var consumer = offlineConsumerFactory is null ? env.CreateRuntimeClient() : offlineConsumerFactory(env);
            var user = await consumer.ReadAsync(new(consumer.Authority, new InfisicalSecretAddress(address.ProjectId,
                address.Environment!, address.Folder!, fixture.UsernameKey)), token);
            using var ownedUser = user.IsSuccess ? user.Value : null;
            var password = await consumer.ReadAsync(new(consumer.Authority, new InfisicalSecretAddress(address.ProjectId,
                address.Environment!, address.Folder!, fixture.PasswordKey)), token);
            using var ownedPassword = password.IsSuccess ? password.Value : null;
            if (!user.IsSuccess || !password.IsSuccess)
                probe.Effect(NativeObservation.Unavailable);
            var acceptance = await backend!.AuthenticateAsync(fixture.Coordinate, ownedUser!.Material,
                ownedPassword!.Material, token);
            probe.Effect(acceptance == BackendAuthentication.Accepted ? NativeObservation.Matched :
                acceptance == BackendAuthentication.Unavailable ? NativeObservation.Unavailable : NativeObservation.Mismatched);
            // Retain receipt uncertainty. The independent observation never rewrites or replays it.
            if (lost && receipt is not null)
                probe.Contract(receipt.Dispatch == InfisicalRotationDispatch.ResponseUnknown &&
                    receipt.Effect == InfisicalRotationEffect.Unknown, NativeFailure.ContractMismatch);
        }
        finally
        {
            bool clean = true;
            try
            {
                await fixture.DisposeAsync();
                if (backend is not null)
                {
                    using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                    RotationBackendFacts remaining = await backend.MeasureAsync(fixture.Coordinate, cleanup.Token);
                    clean = remaining.Coordinate == fixture.Coordinate &&
                        remaining.Authentication == BackendAuthentication.Rejected;
                }
            }
            catch (Exception) { clean = false; }
            if (!clean) probe.Contract(false, NativeFailure.CleanupIncomplete);
        }
    }

    private static bool SameAddress(InfisicalRotationAddress left, InfisicalRotationAddress right) =>
        left.ProjectId == right.ProjectId && left.Environment == right.Environment &&
        left.Folder == right.Folder && left.RotationId == right.RotationId && left.Profile == right.Profile;

    internal sealed record RotationInput(LifecycleSandbox Sandbox, string OrganizationId,
        InfisicalRotationProfile Profile, string ConnectionId, RotationBackendCoordinate Backend,
        string Username1, string Username2, string? RotationStatement, int RotationInterval,
        bool Enabled, int MaximumItems, string[] AllowedActions, string[] DeniedActions)
    {
        public override string ToString() => "[RotationInput]";
    }

    internal sealed class DatabaseRotationFixture : IInfisicalRotationOwnedFixture
    {
        private readonly NativeEnvironment env;
        private readonly RotationInput input;
        private readonly NativeCaseProbe probe;
        private readonly LifecycleOwnedFolder folder;
        private readonly ManagementClient management;
        private readonly string name = "rotation-" + Guid.NewGuid().ToString("N");
        private bool attempted;
        private InfisicalRotationAddress? address;
        public InfisicalRotationAddress Address => address!;
        public RotationBackendCoordinate Coordinate => input.Backend;
        public string UsernameKey => name + "-user";
        public string PasswordKey => name + "-password";
        private DatabaseRotationFixture(NativeEnvironment env, RotationInput input, NativeCaseProbe probe, string scope)
        {
            this.env = env;
            this.input = input;
            this.probe = probe;
            folder = new(env, input.Sandbox, probe, scope);
            management = env.CreateManagementClient();
        }
        internal static async ValueTask<DatabaseRotationFixture> CreateAsync(NativeEnvironment env,
            RotationInput input, NativeCaseProbe probe, string scope, CancellationToken token)
        {
            var fixture = new DatabaseRotationFixture(env, input, probe, scope);
            try { await fixture.InitializeAsync(token); return fixture; }
            catch { await fixture.DisposeAsync(); throw; }
        }
        private async ValueTask InitializeAsync(CancellationToken token)
        {
            await folder.InitializeAsync(token);
            using var statement = input.RotationStatement is null ? null : SecretMaterial.FromText(input.RotationStatement);
            attempted = true;
            State? result;
            switch (input.Profile)
            {
                case InfisicalRotationProfile.PostgresCredentials:
                    using (var parameters = new PostgresRotationParameters(input.Username1, input.Username2, rotationStatement: statement))
                    using (var request = PostgresSecretRotationOperations.Create(input.OrganizationId, new(name,
                        input.Sandbox.ProjectId, input.Sandbox.Environment, folder.Path, input.ConnectionId,
                        input.RotationInterval, parameters, new(UsernameKey, PasswordKey), isAutoRotationEnabled: false)))
                        result = await ExecuteAsync(request, NativeIdentityRole.Setup, true,
                            r => new(r.Id, r.ConnectionId, r.Parameters.Username1, r.Parameters.Username2), token);
                    break;
                case InfisicalRotationProfile.MysqlCredentials:
                    using (var parameters = new MySqlRotationParameters(input.Username1, input.Username2, rotationStatement: statement))
                    using (var request = MySqlSecretRotationOperations.Create(input.OrganizationId, new(name,
                        input.Sandbox.ProjectId, input.Sandbox.Environment, folder.Path, input.ConnectionId,
                        input.RotationInterval, parameters, new(UsernameKey, PasswordKey), isAutoRotationEnabled: false)))
                        result = await ExecuteAsync(request, NativeIdentityRole.Setup, true,
                            r => new(r.Id, r.ConnectionId, r.Parameters.Username1, r.Parameters.Username2), token);
                    break;
                case InfisicalRotationProfile.MssqlCredentials:
                    using (var parameters = new MsSqlRotationParameters(input.Username1, input.Username2, rotationStatement: statement))
                    using (var request = MsSqlSecretRotationOperations.Create(input.OrganizationId, new(name,
                        input.Sandbox.ProjectId, input.Sandbox.Environment, folder.Path, input.ConnectionId,
                        input.RotationInterval, parameters, new(UsernameKey, PasswordKey), isAutoRotationEnabled: false)))
                        result = await ExecuteAsync(request, NativeIdentityRole.Setup, true,
                            r => new(r.Id, r.ConnectionId, r.Parameters.Username1, r.Parameters.Username2), token);
                    break;
                default: throw new NativeCaseFailureException("missing-prerequisite");
            }
            probe.Contract(result is not null, NativeFailure.MissingPrerequisite);
            address = new(input.Sandbox.ProjectId, input.Sandbox.Environment, folder.Path,
                input.Profile, result!.Id);
            var observed = await ReadAsync(NativeIdentityRole.Observer, token);
            probe.Contract(observed is not null && observed.ConnectionId == input.ConnectionId &&
                observed.Username1 == input.Username1 && observed.Username2 == input.Username2,
                NativeFailure.ObserverUnavailable);
        }
        private sealed record State(string Id, string ConnectionId, string Username1, string Username2)
        {
            public override string ToString() => "[RotationFixtureState]";
        }
        private async ValueTask<State?> ExecuteAsync<T>(ManagementRequest<T> request, NativeIdentityRole role,
            bool mutation, Func<T, State> project, CancellationToken token) where T : IDisposable
        {
            var authority = env.CreateManagementAuthority(management, role, input.OrganizationId, input.Sandbox.ProjectId);
            var receipt = mutation ? management.CreateReceipt(request) : null;
            var outcome = await management.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), receipt, token);
            if (outcome.IsSuccess)
            {
                using var result = outcome.Value;
                probe.Contract(!mutation || receipt!.Evidence == DispatchEvidence.Applied, NativeFailure.ContractMismatch);
                return project(result);
            }
            if (outcome.Status == SecretStatus.Absent) return null;
            throw new NativeCaseFailureException("observer-unavailable");
        }
        private async ValueTask<State?> ReadAsync(NativeIdentityRole role, CancellationToken token, bool delete = false)
        {
            switch (input.Profile)
            {
                case InfisicalRotationProfile.PostgresCredentials:
                    using (var request = delete ? PostgresSecretRotationOperations.Delete(input.OrganizationId, address!,
                        deleteSecrets: true, revokeGeneratedCredentials: true) : address is null ?
                        PostgresSecretRotationOperations.GetByName(input.OrganizationId, input.Sandbox.ProjectId,
                            input.Sandbox.Environment, folder.Path, name) : PostgresSecretRotationOperations.Get(input.OrganizationId, address))
                        return await ExecuteAsync(request, role, delete,
                            r => new(r.Id, r.ConnectionId, r.Parameters.Username1, r.Parameters.Username2), token);
                case InfisicalRotationProfile.MysqlCredentials:
                    using (var request = delete ? MySqlSecretRotationOperations.Delete(input.OrganizationId, address!,
                        deleteSecrets: true, revokeGeneratedCredentials: true) : address is null ?
                        MySqlSecretRotationOperations.GetByName(input.OrganizationId, input.Sandbox.ProjectId,
                            input.Sandbox.Environment, folder.Path, name) : MySqlSecretRotationOperations.Get(input.OrganizationId, address))
                        return await ExecuteAsync(request, role, delete,
                            r => new(r.Id, r.ConnectionId, r.Parameters.Username1, r.Parameters.Username2), token);
                case InfisicalRotationProfile.MssqlCredentials:
                    using (var request = delete ? MsSqlSecretRotationOperations.Delete(input.OrganizationId, address!,
                        deleteSecrets: true, revokeGeneratedCredentials: true) : address is null ?
                        MsSqlSecretRotationOperations.GetByName(input.OrganizationId, input.Sandbox.ProjectId,
                            input.Sandbox.Environment, folder.Path, name) : MsSqlSecretRotationOperations.Get(input.OrganizationId, address))
                        return await ExecuteAsync(request, role, delete,
                            r => new(r.Id, r.ConnectionId, r.Parameters.Username1, r.Parameters.Username2), token);
                default: throw new NativeCaseFailureException("missing-prerequisite");
            }
        }
        public async ValueTask DisposeAsync()
        {
            bool clean = true;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            try
            {
                if (attempted)
                {
                    var found = await ReadAsync(NativeIdentityRole.Administrative, deadline.Token);
                    if (found is not null)
                    {
                        address ??= new(input.Sandbox.ProjectId, input.Sandbox.Environment, folder.Path,
                            input.Profile, found.Id);
                        await ReadAsync(NativeIdentityRole.Administrative, deadline.Token, delete: true);
                    }
                    var remaining = await ReadAsync(NativeIdentityRole.Observer, deadline.Token);
                    clean &= remaining is null;
                }
            }
            catch (Exception) { clean = false; }
            finally
            {
                try { await folder.DisposeAsync(); }
                catch (Exception) { clean = false; }
                if (!clean) probe.Contract(false, NativeFailure.CleanupIncomplete);
            }
        }
    }
}

internal sealed record RotationBackendCoordinate(InfisicalRotationProfile Profile, string Host, int Port,
    string Database, string Account)
{
    public override string ToString() => "[RotationBackendCoordinate]";
}
internal enum RotationBackendEvent { Snapshot, ManualCredentialChange, ScheduledCredentialChange, ScheduledOpportunityWithoutChange }
internal sealed record RotationBackendFacts(RotationBackendCoordinate Coordinate, long PasswordGeneration,
    BackendAuthentication Authentication, BackendAuthentication PreviousActiveCredentialAuthentication,
    string[] AllowedActions, string[] DeniedActions, RotationBackendEvent Event, DateTimeOffset ObservedAt)
{
    public override string ToString() => "[RotationBackendFacts]";
}
internal interface IInfisicalRotationOwnedFixture : IAsyncDisposable
{
    InfisicalRotationAddress Address { get; }
    RotationBackendCoordinate Coordinate { get; }
    string UsernameKey { get; }
    string PasswordKey { get; }
}
internal interface IInfisicalRotationFixtureFactory
{
    ValueTask<IInfisicalRotationOwnedFixture> CreateAsync(NativeEnvironment env,
        InfisicalRotationClientEffects.RotationInput input, NativeCaseProbe probe, CancellationToken token);
}
internal interface IInfisicalRotationBackendSubscription : IAsyncDisposable
{
    Task<RotationBackendFacts> Observed { get; }
}
internal interface IInfisicalRotationBackendObserver
{
    ValueTask<IInfisicalRotationBackendSubscription> SubscribeAsync(RotationBackendCoordinate coordinate, CancellationToken token);
    ValueTask<RotationBackendFacts> MeasureAsync(RotationBackendCoordinate coordinate, CancellationToken token);
    ValueTask<BackendAuthentication> AuthenticateAsync(RotationBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token);
}
