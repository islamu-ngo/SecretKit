using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class AzureManagementFamilies
{
    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        AuditDiagnosticsEffects.Register(registry, env, expected);
        ManagementOperationEffects.Register(registry, env, expected);
        VaultAdministrationEffects.Register(registry, env, expected);
        NotificationAdministrationEffects.Register(registry, env, expected);
        RoleAdministrationEffects.Register(registry, env, expected);
    }
}

internal sealed record ManagementMember(string Operation, string Member, string[] Variants, bool Mutation);

internal static class ManagementAdmission
{
    internal static readonly JsonSerializerOptions Json = new(NativeRunProtocol.JsonOptions)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    internal static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, ManagementMember[] members,
        Func<NativeCaseDefinition, NativeCaseProbe, CancellationToken, ValueTask> execute)
    {
        foreach (NativeCaseDefinition definition in expected)
        {
            ManagementMember? member = members.SingleOrDefault(m => m.Operation == definition.Key.Operation);
            if (member is null) continue;
            string[] cases = member.Mutation
                ? ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]
                : ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"];
            if (definition.Key.Provider != "AzureKeyVault" || definition.Member != member.Member ||
                !member.Variants.Contains(definition.Key.Variant, StringComparer.Ordinal) ||
                !cases.Contains(definition.Key.Case, StringComparer.Ordinal))
                throw new InvalidOperationException("management-registration-contract");
            registry.Add(new(definition, async (probe, token) =>
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
                try { await execute(definition, probe, linked.Token).ConfigureAwait(false); }
                catch (NativeCaseFailureException failure)
                {
                    probe.Contract(false, failure.Message switch
                    {
                        "missing-input" => NativeFailure.MissingInput,
                        "missing-prerequisite" => NativeFailure.MissingPrerequisite,
                        "observer-unavailable" => NativeFailure.ObserverUnavailable,
                        "contract-mismatch" => NativeFailure.ContractMismatch,
                        "effect-mismatch" => NativeFailure.EffectMismatch,
                        "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                        _ => NativeFailure.UnexpectedFailure
                    });
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    probe.Contract(false, NativeFailure.DeadlineExceeded);
                }
            }));
        }
    }

    internal static T Input<T>(OwnedAzureEnvironment env, string family) where T : class
    {
        try
        {
            return env.RequireFamilyInput(family).Deserialize<T>(Json)
                ?? throw new NativeCaseFailureException("missing-input");
        }
        catch (JsonException)
        {
            throw new NativeCaseFailureException("missing-input");
        }
    }

    internal static void Require(bool condition, NativeFailure failure = NativeFailure.MissingInput)
    {
        if (!condition) throw new NativeCaseFailureException(NativeCaseProbe.Reason(failure));
    }

    internal static T Value<T>(SecretOutcome<T> outcome) where T : notnull
    {
        Require(outcome.IsSuccess, NativeFailure.EffectMismatch);
        return outcome.Value;
    }

    internal static bool SameVault(VaultScope a, VaultScope b) =>
        a.ExportResourceId().Equals(b.ExportResourceId(), StringComparison.OrdinalIgnoreCase);

    internal static void Receipt(ManagementReceipt receipt, string @case)
    {
        if (@case == "lost-response-no-replay")
            Require(receipt.Evidence == DispatchEvidence.PossiblyDispatched, NativeFailure.ContractMismatch);
        else if (@case == "cancellation-boundary")
            Require(receipt.Evidence is DispatchEvidence.PossiblyDispatched or DispatchEvidence.Pending or DispatchEvidence.Applied,
                NativeFailure.ContractMismatch);
        else if (@case == "denied-authority")
            Require(receipt.Evidence == DispatchEvidence.Rejected, NativeFailure.ContractMismatch);
        else
            Require(receipt.Evidence is DispatchEvidence.Applied or DispatchEvidence.Pending, NativeFailure.ContractMismatch);
    }

    internal static void ConfirmInfrastructure(OwnedAzureEnvironment env, NativeCaseDefinition definition,
        LeaseFacts facts)
    {
        // Facts have been validated against the fresh selector and independent
        // post-operation measurement. Rights/entitlements are not inferred here.
        // A nonempty identity string and a subscription-shaped resource ID do not
        // bind the selected tenant or prove an independently authenticated principal.
        foreach (string prerequisite in new[] { "owned-origin-api-revision",
            "azure-selected-cloud-endpoint" })
            env.ConfirmPrerequisite(definition.Key.Scope, prerequisite, NativeObservation.Matched);
    }

    internal static void Confirm(OwnedAzureEnvironment env, NativeCaseDefinition definition, params string[] prerequisites)
    {
        foreach (string prerequisite in prerequisites)
            env.ConfirmPrerequisite(definition.Key.Scope, prerequisite, NativeObservation.Matched);
    }
}

// This is a host fixture protocol, not an Azure endpoint or an asserted vendor
// contract. The independently operated HTTPS service leases fresh sandbox resources,
// subscribes to native/backend events, and returns measured facts, not pass flags.
// No host service implementation or deployment is implied by these client contracts.
internal sealed record ObserverEndpoint(Uri Endpoint, string Token, TimeSpan Timeout)
{
    public override string ToString() => "[ObserverEndpoint]";
    internal void Validate()
    {
        ManagementAdmission.Require(Endpoint.IsAbsoluteUri && Endpoint.Scheme == "https" &&
            Endpoint.UserInfo.Length == 0 && Endpoint.Query.Length == 0 && Endpoint.Fragment.Length == 0 &&
            Endpoint.AbsolutePath.EndsWith('/') && !string.IsNullOrWhiteSpace(Token) &&
            Timeout >= TimeSpan.FromSeconds(1) && Timeout <= TimeSpan.FromMinutes(2));
    }
}

internal sealed record AudienceToken(string Token, DateTimeOffset ExpiresAt, string Audience)
{
    public override string ToString() => "[AudienceToken]";
}

internal sealed record ManagementIdentities(AudienceToken Setup, AudienceToken Administrative,
    AudienceToken Denied, AudienceToken Observer)
{
    public override string ToString() => "[ManagementIdentities]";
    internal SelectedAudienceCredential Select(NativeIdentityRole role, string audience = "https://management.azure.com/.default")
    {
        AudienceToken[] selected = [Setup, Administrative, Denied, Observer];
        ManagementAdmission.Require(selected.All(t => t.Audience == audience &&
            !string.IsNullOrWhiteSpace(t.Token) && t.ExpiresAt > DateTimeOffset.UtcNow) &&
            selected.Select(t => t.Token).Distinct(StringComparer.Ordinal).Count() == 4);
        return new(role switch
        {
            NativeIdentityRole.Setup => Setup,
            NativeIdentityRole.Administrative => Administrative,
            NativeIdentityRole.Denied => Denied,
            NativeIdentityRole.Observer => Observer,
            _ => throw new NativeCaseFailureException("missing-input")
        });
    }
}

internal sealed class SelectedAudienceCredential : TokenCredential, IDisposable
{
    private readonly SecretMaterial token;
    private readonly DateTimeOffset expires;
    private readonly string audience;
    internal SelectedAudienceCredential(AudienceToken input)
    {
        token = SecretMaterial.FromText(input.Token);
        expires = input.ExpiresAt;
        audience = input.Audience;
    }
    public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ManagementAdmission.Require(context.Scopes.Length == 1 && context.Scopes[0] == audience &&
            expires > DateTimeOffset.UtcNow);
        return new(token.Reveal(), expires);
    }
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(GetToken(context, cancellationToken));
    public void Dispose() => token.Dispose();
    public override string ToString() => "[SelectedAudienceCredential]";
}

internal sealed record FixtureSelector(Guid Nonce, string Scope, string Operation, string Variant, string Case)
{
    public override string ToString() => "[FixtureSelector]";
    internal static FixtureSelector For(NativeCaseDefinition definition) =>
        new(Guid.NewGuid(), definition.Key.Scope, definition.Key.Operation, definition.Key.Variant, definition.Key.Case);
}

internal sealed record LeaseFacts(Guid Nonce, Guid LeaseId, string ObserverIdentity, string Origin,
    string ApiRevision, DateTimeOffset PreparedAt, string[] OwnedResourceIds)
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> UsedLeases = new();
    public override string ToString() => "[LeaseFacts]";
    internal void Claim(FixtureSelector selector)
    {
        // Claim only the service lease bound to this fresh request. Releasing by
        // lease/nonce does not grant authority over returned resource coordinates.
        ManagementAdmission.Require(Nonce == selector.Nonce && LeaseId != Guid.Empty &&
            UsedLeases.TryAdd(LeaseId, 0), NativeFailure.MissingPrerequisite);
    }
    internal void Validate(FixtureSelector selector, string revision)
    {
        ManagementAdmission.Require(Nonce == selector.Nonce && LeaseId != Guid.Empty &&
            !string.IsNullOrWhiteSpace(ObserverIdentity) && Origin == "https://management.azure.com" &&
            ApiRevision == revision && PreparedAt > DateTimeOffset.UtcNow.AddMinutes(-2) &&
            PreparedAt <= DateTimeOffset.UtcNow && OwnedResourceIds.Length > 0 &&
            OwnedResourceIds.All(r => r.StartsWith("/subscriptions/", StringComparison.Ordinal)) &&
            OwnedResourceIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() == OwnedResourceIds.Length,
            NativeFailure.MissingPrerequisite);
    }
}

internal sealed record ObserveLease(Guid LeaseId, Guid Nonce, string Phase, Guid? SubscriptionId = null)
{
    public override string ToString() => "[ObserveLease]";
}
internal sealed record ObservationSubscription(Guid LeaseId, Guid Nonce, Guid SubscriptionId, DateTimeOffset ArmedAt);
internal sealed record CleanupMeasurement(Guid LeaseId, Guid Nonce, DateTimeOffset ObservedAt,
    string ObserverIdentity, string[] AbsentResourceIds, string[] RemainingResourceIds)
{
    public override string ToString() => "[CleanupMeasurement]";
}

internal sealed class OwnedManagementObserver : IDisposable
{
    private readonly ObserverEndpoint input;
    private readonly HttpClient client;
    internal OwnedManagementObserver(ObserverEndpoint input, HttpMessageHandler? handler = null)
    {
        input.Validate();
        this.input = input;
        client = new(handler ?? new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = input.Timeout };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", input.Token);
    }

    internal async ValueTask<ObservationSubscription> SubscribeAsync(string family, LeaseFacts lease, CancellationToken token)
    {
        ObservationSubscription subscription = await PostAsync<ObserveLease, ObservationSubscription>(family + "/arm",
            new(lease.LeaseId, lease.Nonce, "subscribe-before-trigger"), token).ConfigureAwait(false);
        ManagementAdmission.Require(subscription.LeaseId == lease.LeaseId && subscription.Nonce == lease.Nonce &&
            subscription.SubscriptionId != Guid.Empty && subscription.ArmedAt >= lease.PreparedAt,
            NativeFailure.ObserverUnavailable);
        return subscription;
    }

    internal async ValueTask<TResponse> PostAsync<TRequest, TResponse>(string action, TRequest request,
        CancellationToken token) where TRequest : notnull where TResponse : notnull
    {
        // Each family statically selects its request and response DTOs.
        using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(input.Endpoint, action));
        message.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(request, ManagementAdmission.Json));
        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var deadline = new CancellationTokenSource(input.Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, linked.Token)
            .ConfigureAwait(false);
        ManagementAdmission.Require(response.IsSuccessStatusCode, NativeFailure.ObserverUnavailable);
        await using var stream = await response.Content.ReadAsStreamAsync(linked.Token).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(chunk, linked.Token).ConfigureAwait(false)) != 0)
        {
            ManagementAdmission.Require(buffer.Length + count <= 1024 * 1024, NativeFailure.ObserverUnavailable);
            buffer.Write(chunk, 0, count);
        }
        try
        {
            return JsonSerializer.Deserialize<TResponse>(buffer.ToArray(), ManagementAdmission.Json)
                ?? throw new NativeCaseFailureException("observer-unavailable");
        }
        catch (JsonException)
        {
            throw new NativeCaseFailureException("observer-unavailable");
        }
    }

    internal async ValueTask CleanupAsync(LeaseFacts lease, NativeCaseProbe probe,
        OwnedAzureEnvironment? env = null, NativeCaseDefinition? definition = null)
    {
        try
        {
            CleanupMeasurement result = await PostAsync<ObserveLease, CleanupMeasurement>("cleanup",
                new(lease.LeaseId, lease.Nonce, "cleanup"), CancellationToken.None).ConfigureAwait(false);
            ManagementAdmission.Require(result.LeaseId == lease.LeaseId && result.Nonce == lease.Nonce &&
                result.ObserverIdentity == lease.ObserverIdentity && result.ObservedAt >= lease.PreparedAt &&
                result.RemainingResourceIds.Length == 0 &&
                lease.OwnedResourceIds.All(id => result.AbsentResourceIds.Contains(id, StringComparer.OrdinalIgnoreCase)),
                NativeFailure.CleanupIncomplete);
            if (env is not null && definition is not null)
                env.ConfirmPrerequisite(definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Matched);
        }
        catch (Exception)
        {
            if (env is not null && definition is not null)
                env.ConfirmPrerequisite(definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Mismatched);
            probe.Contract(false, NativeFailure.CleanupIncomplete);
        }
    }
    public void Dispose() => client.Dispose();
    public override string ToString() => "[OwnedManagementObserver]";
}

internal sealed class ManagementBoundaryTransport : HttpPipelineTransport
{
    private readonly HttpPipelineTransport inner;
    private readonly string @case;
    private readonly CancellationTokenSource cancellation;
    private readonly Func<HttpMessage, bool> select;
    private int delivered;
    private readonly TaskCompletionSource responseReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task ResponseReceived => responseReceived.Task;
    internal ManagementBoundaryTransport(HttpPipelineTransport inner, string @case,
        CancellationTokenSource cancellation, Func<HttpMessage, bool>? select = null)
    {
        this.inner = inner;
        this.@case = @case;
        this.cancellation = cancellation;
        this.select = select ?? (_ => true);
    }
    public override Request CreateRequest() => inner.CreateRequest();
    public override void Process(HttpMessage message) => ProcessAsync(message).AsTask().GetAwaiter().GetResult();
    public override async ValueTask ProcessAsync(HttpMessage message)
    {
        await inner.ProcessAsync(message).ConfigureAwait(false);
        if (select(message) && message.Response.Status is not (401 or 403) &&
            Interlocked.CompareExchange(ref delivered, 1, 0) == 0)
        {
            // The event source and fault subscriber are installed before SDK invocation.
            responseReceived.TrySetResult();
            if (@case == "cancellation-boundary") cancellation.Cancel();
            if (@case == "lost-response-no-replay")
            {
                message.Response.Dispose();
                throw new IOException("owned-response-withheld");
            }
        }
    }
}

internal sealed class ManagementClients : IDisposable
{
    private readonly HttpClient? http;
    private readonly SelectedAudienceCredential administrative;
    private readonly SelectedAudienceCredential observer;
    internal CancellationTokenSource Cancellation { get; }
    internal ManagementBoundaryTransport Boundary { get; }
    internal VaultAdministration Selected { get; }
    internal VaultAdministration Observer { get; }
    internal ManagementClients(ManagementIdentities identities, string @case, CancellationToken token,
        Func<HttpMessage, bool>? select = null, HttpPipelineTransport? hostTransport = null)
    {
        Cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var transport = hostTransport;
        if (transport is null)
        {
            http = new(new HttpClientHandler { AllowAutoRedirect = false });
            transport = new HttpClientTransport(http);
        }
        administrative = identities.Select(@case == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative);
        observer = identities.Select(NativeIdentityRole.Observer);
        Boundary = new(transport, @case, Cancellation, select);
        Selected = new(administrative, Boundary);
        Observer = new(observer, transport);
    }
    public void Dispose()
    {
        Cancellation.Dispose();
        administrative.Dispose();
        observer.Dispose();
        http?.Dispose();
    }
}
