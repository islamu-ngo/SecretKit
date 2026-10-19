using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.Security.KeyVault.Secrets;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Read-only source component, not a deployed observer service, provisioning
// authority, native event subscription, or proof of independently held principals.
internal sealed partial class RoleAdministrationCollector
{
    internal const string ArmOrigin = "https://management.azure.com";
    internal const string ArmRevision = "2022-04-01";
    internal const string SecretRevision = "2025-07-01";
    internal enum Phase { Baseline, After }
    internal enum Failure { None, Boundary, Budget, Unavailable, Deadline }

    internal sealed record Limits(int MaximumPages, int MaximumItems, int MaximumResponseBytes, TimeSpan Timeout);

    internal sealed record Authority(
        [property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential,
        [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[RoleCollectorAuthority]";
    }

    // Ancestor selectors are explicit borrowed inputs. They never confer ownership
    // or authorize writes; all assignments and definitions remain borrowed here.
    internal sealed record Binding(
        [property: JsonIgnore] FixtureSelector Selector,
        [property: JsonIgnore] Guid LeaseId,
        [property: JsonIgnore] VaultScope Vault,
        [property: JsonIgnore] RoleAssignmentScope Target,
        [property: JsonIgnore] Guid DefinitionId,
        [property: JsonIgnore] string SecretName,
        [property: JsonIgnore] string SecretVersion,
        [property: JsonIgnore] RoleAssignmentScope[] BorrowedAncestors)
    {
        public override string ToString() => "[RoleCollectorBinding]";
    }

    internal sealed class Window
    {
        internal Window(object owner, Binding binding, DateTimeOffset armedAt, long timestamp)
        {
            Owner = owner;
            Binding = binding;
            ArmedAt = armedAt;
            Timestamp = timestamp;
        }
        internal object Owner { get; }
        internal Binding Binding { get; }
        internal DateTimeOffset ArmedAt { get; }
        internal long Timestamp { get; }
        internal Guid Id { get; } = Guid.NewGuid();
        internal int Busy;
        internal int LastPhase = -1;
        public override string ToString() => "[RoleCollectorWindow]";
    }

    internal sealed record ReadEvidence(
        [property: JsonIgnore] SecretStatus Status,
        [property: JsonIgnore] string? Sha256,
        [property: JsonIgnore] string? NativeRequestId,
        [property: JsonIgnore] bool Complete)
    {
        public override string ToString() => "[RoleCollectorRead]";
    }

    internal sealed class Measurement
    {
        internal required Binding Binding { get; init; }
        internal required Guid WindowId { get; init; }
        internal required long Sequence { get; init; }
        internal required Phase Phase { get; init; }
        internal required DateTimeOffset ArmedAt { get; init; }
        internal required DateTimeOffset StartedAt { get; init; }
        internal required DateTimeOffset FinishedAt { get; init; }
        internal required Failure Failure { get; init; }
        internal required IReadOnlyList<RoleAdministrationEffects.Assignment> Assignments { get; init; }
        internal required IReadOnlyList<RoleAdministrationEffects.Definition> Definitions { get; init; }
        internal required ReadEvidence Intended { get; init; }
        internal required ReadEvidence Denied { get; init; }
        internal required ReadEvidence Observer { get; init; }
        internal bool Complete => Failure == Failure.None && Intended.Complete && Denied.Complete && Observer.Complete;
        internal bool AssignmentsComplete => Complete;
        internal bool DefinitionsComplete => Complete;
        internal bool? TargetPresent => Complete ? Assignments.Any(a => a.Id == Binding.Target.AssignmentId &&
            Same(a.ParentResourceId, RoleAdministrationEffects.ParentId(Binding.Target.Parent))) : null;
        public override string ToString() => "[RoleCollectorMeasurement]";
    }

    private readonly Authority arm;
    private readonly Authority intended;
    private readonly Authority denied;
    private readonly Authority observer;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object owner = new();
    private long sequence;

    internal RoleAdministrationCollector(Authority arm, Authority intended, Authority denied, Authority observer,
        Limits limits, TimeProvider? time = null)
    {
        Authority[] authorities = [arm, intended, denied, observer];
        if (authorities.Any(a => a is null || string.IsNullOrWhiteSpace(a.Label) || a.Label.Length > 128 ||
                a.Credential is null || a.Transport is null) ||
            authorities.Select(a => a.Label).Distinct(StringComparer.Ordinal).Count() != 4 ||
            authorities.Select(a => a.Credential).Distinct(ReferenceEqualityComparer.Instance).Count() != 4 ||
            authorities.Select(a => a.Transport).Distinct(ReferenceEqualityComparer.Instance).Count() != 4 ||
            limits is null || limits.MaximumPages is < 1 or > 100 || limits.MaximumItems is < 1 or > 10000 ||
            limits.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("role-collector-input");
        this.arm = arm;
        this.intended = intended;
        this.denied = denied;
        this.observer = observer;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    internal Window Arm(Binding binding)
    {
        ValidateBinding(binding);
        return new(owner, binding with { BorrowedAncestors = binding.BorrowedAncestors.ToArray() },
            time.GetUtcNow(), time.GetTimestamp());
    }

    // A phase is consumed even if canceled or incomplete. A second measurement
    // requires an explicitly armed independent window, never a hidden retry.
    internal async ValueTask<Measurement> CollectAsync(Window window, Binding binding, Phase phase,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateBinding(binding);
        if (window is null || !ReferenceEquals(window.Owner, owner) || !Matches(window.Binding, binding) ||
            !Enum.IsDefined(phase) || Interlocked.CompareExchange(ref window.Busy, 1, 0) != 0)
            throw new InvalidOperationException("role-collector-window");
        try
        {
            if ((int)phase <= window.LastPhase)
                throw new InvalidOperationException("role-collector-window");
            window.LastPhase = (int)phase;
            long number = Interlocked.Increment(ref sequence);
            DateTimeOffset started = time.GetUtcNow();
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            var assignments = new List<RoleAdministrationEffects.Assignment>();
            var definitions = new List<RoleAdministrationEffects.Definition>();
            ReadEvidence a = new(SecretStatus.Unknown, null, null, false);
            ReadEvidence d = a;
            ReadEvidence o = a;
            Failure failure = Failure.None;
            try
            {
                if (time.GetElapsedTime(window.Timestamp) > limits.Timeout) throw new Boundary(Failure.Deadline);
                await CollectAssignments(binding, assignments, linked.Token).ConfigureAwait(false);
                await CollectDefinitions(binding, definitions, linked.Token).ConfigureAwait(false);
                a = await ReadSecret(intended, binding, linked.Token).ConfigureAwait(false);
                d = await ReadSecret(denied, binding, linked.Token).ConfigureAwait(false);
                o = await ReadSecret(observer, binding, linked.Token).ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
                if (!a.Complete || !d.Complete || !o.Complete) failure = Failure.Boundary;
            }
            catch (Exception exception)
            {
                if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
                failure = deadline.IsCancellationRequested ? Failure.Deadline : FailureOf(exception);
            }
            return new()
            {
                Binding = window.Binding,
                WindowId = window.Id,
                Sequence = number,
                Phase = phase,
                ArmedAt = window.ArmedAt,
                StartedAt = started,
                FinishedAt = time.GetUtcNow(),
                Failure = failure,
                Assignments = Array.AsReadOnly(failure == Failure.None ? assignments.ToArray() : []),
                Definitions = Array.AsReadOnly(failure == Failure.None ? definitions.ToArray() : []),
                Intended = a,
                Denied = d,
                Observer = o
            };
        }
        finally { Volatile.Write(ref window.Busy, 0); }
    }

    private ArmClient ArmClient(BoundaryTransport transport)
    {
        var options = new ArmClientOptions
        {
            Environment = new(new Uri(ArmOrigin), ArmOrigin),
            Transport = transport
        };
        Quiet(options);
        options.SetApiVersion("Microsoft.Authorization/roleAssignments", ArmRevision);
        options.SetApiVersion("Microsoft.Authorization/roleDefinitions", ArmRevision);
        return new(new AudienceCredential(arm.Credential, ArmOrigin + "/.default"), null, options);
    }

    private async Task CollectAssignments(Binding binding, List<RoleAdministrationEffects.Assignment> rows, CancellationToken token)
    {
        string path = binding.Vault.ExportResourceId() + "/providers/Microsoft.Authorization/roleAssignments";
        using var boundary = new BoundaryTransport(arm.Transport, binding, limits, path, Collection.Assignments);
        var client = ArmClient(boundary);
        await foreach (var page in client.GetRoleAssignments(new ResourceIdentifier(binding.Vault.ExportResourceId()))
            .GetAllAsync(filter: "atScope()", cancellationToken: token).AsPages().ConfigureAwait(false))
        {
            using var response = page.GetRawResponse();
            token.ThrowIfCancellationRequested();
            boundary.CheckPage(page.ContinuationToken, page.Values.Count);
            foreach (var resource in page.Values)
            {
                var data = resource.Data;
                string parent = data.Scope;
                Guid id = AssignmentIdentifier(data.Id?.ToString(), parent, binding);
                Guid definition = DefinitionIdentifier(data.RoleDefinitionId?.ToString(), binding);
                if (data.PrincipalId is not { } principal || principal == Guid.Empty) throw new Boundary();
                rows.Add(new(id, parent, definition, principal, data.PrincipalType?.ToString(),
                    data.Description, data.Condition, data.ConditionVersion));
            }
        }
        boundary.RequireComplete(rows.Count);
    }

    private async Task CollectDefinitions(Binding binding, List<RoleAdministrationEffects.Definition> rows, CancellationToken token)
    {
        string subscription = Subscription(binding);
        using var boundary = new BoundaryTransport(arm.Transport, binding, limits,
            subscription + "/providers/Microsoft.Authorization/roleDefinitions", Collection.Definitions);
        var client = ArmClient(boundary);
        await foreach (var page in client.GetAuthorizationRoleDefinitions(new ResourceIdentifier(subscription))
            .GetAllAsync(cancellationToken: token).AsPages().ConfigureAwait(false))
        {
            using var response = page.GetRawResponse();
            token.ThrowIfCancellationRequested();
            boundary.CheckPage(page.ContinuationToken, page.Values.Count);
            foreach (var resource in page.Values)
            {
                var data = resource.Data;
                Guid id = DefinitionIdentifier(data.Id?.ToString(), binding);
                rows.Add(new(id, data.RoleName, data.Description, data.RoleType?.ToString(),
                    data.AssignableScopes.ToArray(), data.Permissions.Select(p =>
                        new RoleAdministrationEffects.Permission(p.Actions.ToArray(), p.NotActions.ToArray(),
                            p.DataActions.ToArray(), p.NotDataActions.ToArray())).ToArray()));
            }
        }
        boundary.RequireComplete(rows.Count);
    }

    private async Task<ReadEvidence> ReadSecret(Authority authority, Binding binding, CancellationToken token)
    {
        using var boundary = new BoundaryTransport(authority.Transport, binding, limits,
            $"/secrets/{binding.SecretName}/{binding.SecretVersion}", Collection.Secret);
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
        {
            Transport = boundary,
            DisableChallengeResourceVerification = false
        };
        Quiet(options);
        var client = new SecretClient(new Uri(SecretOrigin(binding)),
            new AudienceCredential(authority.Credential, "https://vault.azure.net/.default"), options);
        try
        {
            var response = await client.GetSecretAsync(binding.SecretName, binding.SecretVersion, token).ConfigureAwait(false);
            using var raw = response.GetRawResponse();
            token.ThrowIfCancellationRequested();
            var secret = response.Value;
            if (secret.Id is null || !Same(secret.Id.OriginalString, SecretOrigin(binding) +
                    $"/secrets/{binding.SecretName}/{binding.SecretVersion}") ||
                secret.Name != binding.SecretName || secret.Properties.Version != binding.SecretVersion ||
                secret.Value is null || secret.Properties.Enabled == false ||
                secret.Properties.NotBefore > time.GetUtcNow() || secret.Properties.ExpiresOn <= time.GetUtcNow())
                throw new Boundary();
            byte[] bytes = Encoding.UTF8.GetBytes(secret.Value);
            byte[]? digest = null;
            try
            {
                digest = SHA256.HashData(bytes);
                return new(SecretStatus.Success, Convert.ToHexString(digest), boundary.RequestId,
                    boundary.LastStatus == 200 && boundary.RequestId is not null);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
                if (digest is not null) CryptographicOperations.ZeroMemory(digest);
                // Native SDK strings cannot be erased. No value escapes this read.
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException && !token.IsCancellationRequested)
        {
            if (exception is RequestFailedException native && native.Status == boundary.LastStatus &&
                boundary.ValidResponse && boundary.RequestId is not null)
            {
                SecretStatus status = native.Status switch
                {
                    401 or 403 => SecretStatus.Denied,
                    404 => SecretStatus.Absent,
                    429 => SecretStatus.Throttled,
                    >= 500 and <= 599 => SecretStatus.Unavailable,
                    _ => SecretStatus.Unknown
                };
                return new(status, null, boundary.RequestId, status != SecretStatus.Unknown);
            }
            return new(SecretStatus.Unknown, null, boundary.RequestId, false);
        }
    }

    private static void Quiet(ClientOptions options)
    {
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
    }

    private static void ValidateBinding(Binding b)
    {
        if (b is null || b.Selector is null || b.Selector.Nonce == Guid.Empty || b.LeaseId == Guid.Empty ||
            b.Vault is null || b.Target is null || b.DefinitionId == Guid.Empty || b.BorrowedAncestors is null ||
            new[] { b.Selector.Scope, b.Selector.Operation, b.Selector.Variant, b.Selector.Case }
                .Any(s => string.IsNullOrWhiteSpace(s) || s.Length > 256) ||
            string.IsNullOrEmpty(b.SecretName) || b.SecretName.Length > 127 ||
            !b.SecretName.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') ||
            b.SecretVersion is null || b.SecretVersion.Length != 32 || !b.SecretVersion.All(char.IsAsciiHexDigit))
            throw new ArgumentException("role-collector-binding");
        string parent = RoleAdministrationEffects.ParentId(b.Target.Parent);
        string[] ancestors = [Subscription(b), RoleAdministrationEffects.ParentId(b.Vault.ResourceGroup)];
        if (!Same(parent, b.Vault.ExportResourceId()) && !ancestors.Contains(parent, StringComparer.OrdinalIgnoreCase) ||
            b.BorrowedAncestors.Length > 100 ||
            b.BorrowedAncestors.Any(a => a is null ||
                !ancestors.Contains(RoleAdministrationEffects.ParentId(a.Parent), StringComparer.OrdinalIgnoreCase)) ||
            b.BorrowedAncestors.Select(AssignmentResourceId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != b.BorrowedAncestors.Length ||
            !Same(parent, b.Vault.ExportResourceId()) &&
                !b.BorrowedAncestors.Any(a => Same(AssignmentResourceId(a), AssignmentResourceId(b.Target))))
            throw new ArgumentException("role-collector-binding");
    }

    private static bool Matches(Binding a, Binding b) => a.Selector == b.Selector && a.LeaseId == b.LeaseId &&
        Same(a.Vault.ExportResourceId(), b.Vault.ExportResourceId()) &&
        Same(AssignmentResourceId(a.Target), AssignmentResourceId(b.Target)) && a.DefinitionId == b.DefinitionId &&
        a.SecretName == b.SecretName && a.SecretVersion == b.SecretVersion &&
        a.BorrowedAncestors.Select(AssignmentResourceId).SequenceEqual(b.BorrowedAncestors.Select(AssignmentResourceId),
            StringComparer.OrdinalIgnoreCase);
    private static string AssignmentResourceId(RoleAssignmentScope scope) =>
        RoleAdministrationEffects.ParentId(scope.Parent) + $"/providers/Microsoft.Authorization/roleAssignments/{scope.AssignmentId:D}";
    private static string Subscription(Binding b) => $"/subscriptions/{b.Vault.ResourceGroup.Subscription.SubscriptionId:D}";
    private static string SecretOrigin(Binding b) => $"https://{b.Vault.VaultName}.vault.azure.net";
    private static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static Guid AssignmentIdentifier(string? id, string? parent, Binding binding)
    {
        string[] parents = [binding.Vault.ExportResourceId(), RoleAdministrationEffects.ParentId(binding.Vault.ResourceGroup), Subscription(binding)];
        if (parent is null || !parents.Contains(parent, StringComparer.OrdinalIgnoreCase)) throw new Boundary();
        return Identifier(id, parent + "/providers/Microsoft.Authorization/roleAssignments/");
    }
    private static Guid DefinitionIdentifier(string? id, Binding binding) =>
        Identifier(id, Subscription(binding) + "/providers/Microsoft.Authorization/roleDefinitions/");
    private static Guid Identifier(string? id, string prefix)
    {
        // Validate the entire native ID, without ResourceIdentifier normalization,
        // before reducing its final segment to a GUID.
        if (id is null || id.Length != prefix.Length + 36 || !id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParseExact(id[prefix.Length..], "D", out Guid value) || value == Guid.Empty)
            throw new Boundary();
        return value;
    }
    private static Failure FailureOf(Exception e) => e switch
    {
        Boundary boundary => boundary.Reason,
        RequestFailedException { InnerException: Boundary boundary } => boundary.Reason,
        RequestFailedException or HttpRequestException or IOException => Failure.Unavailable,
        _ => Failure.Boundary
    };

    private sealed class Boundary(Failure reason = Failure.Boundary) : Exception("role-collector-boundary")
    {
        internal Failure Reason { get; } = reason;
    }

    private sealed class AudienceCredential(TokenCredential inner, string audience) : TokenCredential
    {
        private void Validate(TokenRequestContext context, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (context.Scopes.Length != 1 || context.Scopes[0] != audience) throw new Boundary();
        }
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Validate(requestContext, cancellationToken);
            return inner.GetToken(requestContext, cancellationToken);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Validate(requestContext, cancellationToken);
            return inner.GetTokenAsync(requestContext, cancellationToken);
        }
    }
}
