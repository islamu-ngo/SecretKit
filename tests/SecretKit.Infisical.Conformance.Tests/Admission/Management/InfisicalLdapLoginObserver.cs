using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// An owned-source bridge client, not an LDAP server or native qualification.
internal sealed class InfisicalLdapLoginObserver : ILdapLoginObserver
{
    private readonly InfisicalLifecycleObservers channel;
    private readonly string sourceIdentity;
    private readonly LdapLoginSource source;
    private readonly Dictionary<string, Session> sessions = new(StringComparer.Ordinal);
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private readonly HashSet<string> attemptIds = new(StringComparer.Ordinal);
    private readonly HashSet<string> eventIds = new(StringComparer.Ordinal);
    private readonly HashSet<string> requestIds = new(StringComparer.Ordinal);
    private bool busy;

    internal InfisicalLdapLoginObserver(InfisicalLifecycleObservers channel, string sourceIdentity,
        LdapLoginSource source = LdapLoginSource.NativeProvider)
    {
        if (channel is null || !Text(sourceIdentity) || !Enum.IsDefined(source) ||
            sourceIdentity is "setup" or "runtime" or "denied" or "administrative" or "observer")
            throw new NativeCaseFailureException("missing-input");
        this.channel = channel;
        this.sourceIdentity = sourceIdentity;
        this.source = source;
    }

    internal static InfisicalLdapLoginObserver? FromInputs(NativeEnvironment environment, string family)
    {
        JsonElement input = environment.RequireFamilyInput(family);
        if (!input.TryGetProperty("observer", out JsonElement settings)) return null;
        if (settings.ValueKind != JsonValueKind.Object ||
            settings.TryGetProperty("source", out JsonElement selected) &&
            !(selected.ValueKind == JsonValueKind.Number && selected.TryGetInt32(out int value) &&
                value == (int)LdapLoginSource.NativeProvider ||
                selected.ValueKind == JsonValueKind.String && selected.GetString() == "NativeProvider") ||
            !settings.TryGetProperty("identity", out JsonElement identity) ||
            identity.ValueKind != JsonValueKind.String || !Text(identity.GetString()) ||
            !settings.TryGetProperty("endpoint", out JsonElement endpoint) ||
            endpoint.ValueKind != JsonValueKind.String ||
            !Uri.TryCreate(endpoint.GetString(), UriKind.Absolute, out Uri? uri) ||
            !settings.TryGetProperty("token", out JsonElement credential) ||
            credential.ValueKind != JsonValueKind.String || credential.GetString() is null ||
            !settings.TryGetProperty("timeoutSeconds", out JsonElement timeout) ||
            timeout.ValueKind != JsonValueKind.Number || !timeout.TryGetInt32(out int seconds))
            throw new NativeCaseFailureException("missing-input");
        return new(new(new(uri, credential.GetString()!, identity.GetString()!, seconds)), identity.GetString()!);
    }

    public async ValueTask<LdapDirectoryBinding> OpenAsync(LdapDirectoryAttempt attempt,
        LdapDirectoryCredentials credentials, CancellationToken token)
    {
        if (!ValidAttempt(attempt) || credentials is null)
            throw new NativeCaseFailureException("missing-input");
        Session session;
        lock (sessions)
        {
            if (busy || sessions.ContainsKey(attempt.Id) || !attemptIds.Add(attempt.Id)) throw Unavailable();
            session = new(attempt);
            sessions.Add(attempt.Id, session);
            busy = true;
        }
        try
        {
            // Acquire each clearable export transactionally. A later disposed input
            // cannot strand earlier exports; no private string exports are created.
            char[] original = credentials.Original.ExportCharacters();
            try
            {
                char[] rotated = credentials.Rotated.ExportCharacters();
                try
                {
                    char[] wrongService = credentials.WrongService.ExportCharacters();
                    try
                    {
                        char[] user = credentials.User.ExportCharacters();
                        try
                        {
                            char[] wrongUser = credentials.WrongUser.ExportCharacters();
                            try
                            {
                                if (!Private(original) || !Private(rotated) || !Private(wrongService) ||
                                    !Private(user) || !Private(wrongUser) ||
                                    original.AsSpan().SequenceEqual(rotated) ||
                                    original.AsSpan().SequenceEqual(wrongService) ||
                                    rotated.AsSpan().SequenceEqual(wrongService) ||
                                    user.AsSpan().SequenceEqual(wrongUser))
                                    throw new NativeCaseFailureException("missing-input");
                                LdapDirectoryBinding facts = await Post<LdapDirectoryBinding>(session, "open", writer =>
                                {
                                    Write(writer, "attempt", attempt);
                                    writer.WriteStartObject("credentials");
                                    writer.WriteString("original", original.AsSpan());
                                    writer.WriteString("rotated", rotated.AsSpan());
                                    writer.WriteString("wrongService", wrongService.AsSpan());
                                    writer.WriteString("user", user.AsSpan());
                                    writer.WriteString("wrongUser", wrongUser.AsSpan());
                                    writer.WriteBase64String("correlationKey", credentials.CorrelationKey);
                                    writer.WriteEndObject();
                                }, token);
                                if (facts.Attempt != attempt || !Unique(registrations, facts.RegistrationId) ||
                                    facts.SourceIdentity != sourceIdentity || !Text(facts.ClockAuthority) ||
                                    !Text(facts.ClockEpoch) || !Utc(facts.OpenedAt) || facts.Sequence < 0 ||
                                    !facts.OwnedRootCreated || !facts.RootInitiallyAbsent || !facts.ServiceBindAccepted ||
                                    !facts.WrongServiceBindRejected || !facts.UserBindAccepted || !facts.WrongUserBindRejected)
                                    throw Unavailable();
                                facts = facts with { Attempt = attempt };
                                session.Directory = facts;
                                session.Sequence = facts.Sequence;
                                session.Time = facts.OpenedAt;
                                session.Unsettled = false;
                                return facts;
                            }
                            finally { Array.Clear(wrongUser); }
                        }
                        finally { Array.Clear(user); }
                    }
                    finally { Array.Clear(wrongService); }
                }
                finally { Array.Clear(rotated); }
            }
            finally { Array.Clear(original); }
        }
        catch (ObjectDisposedException) { throw new NativeCaseFailureException("missing-input"); }
        finally { Release(session); }
    }

    public async ValueTask<LdapDirectoryRotation> RotateAsync(LdapDirectoryBinding directory, CancellationToken token)
    {
        Session session = Acquire(directory);
        try
        {
            if (session.Sealed || session.Rotated || Outstanding(session)) throw Unavailable();
            // Consumed before dispatch; even a lost rotation reply cannot rotate twice.
            session.Rotated = true;
            var facts = await Post<LdapDirectoryRotation>(session, "rotate",
                writer => Write(writer, "directory", directory), token);
            if (!Bound(facts.Binding, directory) || !Next(session, facts.Sequence) || !Unique(eventIds, facts.EventId) ||
                !facts.OriginalServiceRejected || !facts.RotatedServiceAccepted ||
                !facts.UserCredentialUnchanged || !facts.OwnedRootOnly) throw Unavailable();
            session.Unsettled = false;
            return facts;
        }
        finally { Release(session); }
    }

    public async ValueTask<LdapLoginArm> ArmAsync(LdapLoginAttempt attempt, CancellationToken token)
    {
        Session session = Acquire(attempt?.Directory);
        try
        {
            if (session.Sealed || Outstanding(session) || attempt is null || !Text(attempt.Id) ||
                !Id(attempt.IdentityId) || !Id(attempt.MembershipId) || !Id(attempt.TemplateId) ||
                !Enum.IsDefined(attempt.ServiceCredential) || !attemptIds.Add(attempt.Id)) throw Unavailable();
            var arm = await Post<LdapLoginArm>(session, "arm", writer => Write(writer, "attempt", attempt), token);
            if (arm.Attempt != attempt || !Bound(arm.Attempt?.Directory, attempt.Directory) ||
                !Unique(registrations, arm.RegistrationId) ||
                !Next(session, arm.Cursor) || !Utc(arm.ArmedAt) || arm.ArmedAt < session.Time || !arm.CaptureArmed)
                throw Unavailable();
            session.Time = arm.ArmedAt;
            arm = arm with { Attempt = attempt };
            session.LoginArm = arm;
            session.Unsettled = false;
            return arm;
        }
        finally { Release(session); }
    }

    public async ValueTask<LdapLoginFence> CompleteAsync(LdapLoginArm arm, DispatchEvidence receipt,
        SecretStatus status, CancellationToken token)
    {
        Session session = Acquire(arm?.Attempt?.Directory);
        try
        {
            if (arm is null || !ReferenceEquals(arm, session.LoginArm) ||
                !Receipt(receipt) || !Enum.IsDefined(status) ||
                status == SecretStatus.Success && receipt != DispatchEvidence.Applied ||
                status != SecretStatus.Success && receipt == DispatchEvidence.Applied) throw Unavailable();
            var facts = await Post<LdapLoginFence>(session, "complete", writer =>
            {
                Write(writer, "arm", arm);
                Write(writer, "receipt", receipt);
                Write(writer, "status", status);
            }, token);
            if (facts.Arm != arm || !Utc(facts.Arm.ArmedAt) ||
                !Bound(facts.Arm.Attempt?.Directory, arm.Attempt.Directory) ||
                facts.Disposition != receipt || facts.Status != status ||
                !Next(session, facts.Sequence) || !Unique(eventIds, facts.EventId) ||
                !facts.ProviderClockObserved || !facts.ExcludesLateCommit ||
                !ValidLogin(facts, receipt, status, session)) throw Unavailable();
            if (facts.MatchedRequests == 1 && !Unique(requestIds, facts.ProviderRequestId)) throw Unavailable();
            if (facts.LastLoginAt is { } time)
            {
                session.LastLogins[arm.Attempt.IdentityId] = time;
                if (time > session.Time) session.Time = time;
            }
            session.LoginEvents += facts.MatchedRequests;
            session.LoginArm = null;
            session.Unsettled = false;
            return facts;
        }
        finally { Release(session); }
    }

    public async ValueTask<LdapTemplateArm> ArmTemplateAsync(LdapTemplateAttempt attempt, CancellationToken token)
    {
        Session session = Acquire(attempt?.Directory);
        try
        {
            if (session.Sealed || Outstanding(session) || attempt is null ||
                !Text(attempt.Id) || !Text(attempt.Operation) || !Text(attempt.Member) ||
                !Text(attempt.Variant) || !Text(attempt.Case) || !Text(attempt.TemplateName) ||
                attempt.TemplateId is not null && !Id(attempt.TemplateId) ||
                attempt.SelectedCredential is { } credential && !Enum.IsDefined(credential) ||
                !attemptIds.Add(attempt.Id)) throw Unavailable();
            var arm = await Post<LdapTemplateArm>(session, "arm-template", writer => Write(writer, "attempt", attempt), token);
            if (arm.Attempt != attempt || !Bound(arm.Attempt?.Directory, attempt.Directory) ||
                !Unique(registrations, arm.RegistrationId) ||
                !Next(session, arm.Cursor) || !arm.CaptureArmed) throw Unavailable();
            arm = arm with { Attempt = attempt };
            session.TemplateArm = arm;
            session.Unsettled = false;
            return arm;
        }
        finally { Release(session); }
    }

    public async ValueTask<LdapTemplateFence> CompleteTemplateAsync(LdapTemplateArm arm,
        DispatchEvidence receipt, CancellationToken token)
    {
        Session session = Acquire(arm?.Attempt?.Directory);
        try
        {
            if (arm is null || !ReferenceEquals(arm, session.TemplateArm) || !Receipt(receipt)) throw Unavailable();
            var facts = await Post<LdapTemplateFence>(session, "complete-template", writer =>
            {
                Write(writer, "arm", arm);
                Write(writer, "receipt", receipt);
            }, token);
            if (facts.Arm != arm || !Bound(facts.Arm.Attempt?.Directory, arm.Attempt.Directory) ||
                facts.Disposition != receipt || !Next(session, facts.Sequence) ||
                !facts.ExcludesLateCommit || !facts.NoReplay ||
                facts.MatchedMutations != (receipt == DispatchEvidence.NotDispatched ? 0 : 1) ||
                receipt is DispatchEvidence.NotDispatched or DispatchEvidence.Rejected && facts.Applied ||
                receipt == DispatchEvidence.Applied && !facts.Applied ||
                facts.MatchedMutations == 0 && facts.ProviderRequestId is not null ||
                facts.MatchedMutations == 1 && !Unique(requestIds, facts.ProviderRequestId) ||
                facts.TemplateId is not null && !Id(facts.TemplateId) ||
                arm.Attempt.TemplateId is { } expected && facts.TemplateId != expected ||
                arm.Attempt.TemplateId is null && !facts.Applied && facts.TemplateId is not null ||
                facts.Applied && !Id(facts.TemplateId)) throw Unavailable();
            session.TemplateArm = null;
            session.Unsettled = false;
            return facts;
        }
        finally { Release(session); }
    }

    public async ValueTask<LdapLoginVisibility> SealAsync(LdapDirectoryBinding directory, CancellationToken token)
    {
        Session session = Acquire(directory);
        try
        {
            if (session.Sealed || Outstanding(session)) throw Unavailable();
            var facts = await Post<LdapLoginVisibility>(session, "seal",
                writer => Write(writer, "directory", directory), token);
            if (!Bound(facts.Directory, directory) || !Next(session, facts.Sequence) ||
                !Text(facts.Watermark) || !Utc(facts.ClosedAt) || facts.ClosedAt < session.Time ||
                facts.LoginEvents != session.LoginEvents || !facts.Complete || !facts.NoFurtherLogins ||
                !facts.SearchVisibilityEstablished) throw Unavailable();
            session.Sealed = true;
            session.Unsettled = false;
            return facts;
        }
        finally { Release(session); }
    }

    public async ValueTask<LdapDirectoryCleanup> CloseAsync(LdapDirectoryAttempt attempt, CancellationToken token)
    {
        Session session = Acquire(attempt, cleanup: true);
        try
        {
            // Cleanup addresses the original attempt even if Open never returned.
            // Its deadline is independent of the cancelled public SDK operation.
            session.CloseStarted = true;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            LdapDirectoryCleanup facts;
            try
            {
                facts = await Post<LdapDirectoryCleanup>(session, "close",
                    writer => Write(writer, "attempt", session.Attempt), deadline.Token);
            }
            catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
            { throw new NativeCaseFailureException("cleanup-incomplete"); }
            if (facts.Attempt != session.Attempt || !facts.Closed || !facts.OwnedRootRemoved ||
                !facts.UnrelatedRootsPreserved || !facts.CredentialsDestroyed || !facts.MutationSettled ||
                !facts.LateCreationFenced || facts.RemainingRegistrations != 0 || facts.PendingDeliveries != 0)
                throw new NativeCaseFailureException("cleanup-incomplete");
            session.Unsettled = false;
            return facts;
        }
        finally { Release(session); }
    }

    private bool ValidAttempt(LdapDirectoryAttempt? attempt) =>
        attempt is not null && Text(attempt.Id) && Text(attempt.CaseIdentity) &&
        attempt.ProviderVersion == "v0.166.3" && Text(attempt.DeploymentId) && Id(attempt.OrganizationId) &&
        Text(attempt.RootNonce) && Text(attempt.BindDn) && Text(attempt.SearchBase) && Text(attempt.Username) &&
        Text(attempt.Url) && Uri.TryCreate(attempt.Url, UriKind.Absolute, out Uri? uri) &&
        uri.Scheme is "ldap" or "ldaps" && uri.Host.Length != 0 && uri.UserInfo.Length == 0 &&
        uri.Query.Length == 0 && uri.Fragment.Length == 0 && attempt.Source == source;

    private static bool ValidLogin(LdapLoginFence facts, DispatchEvidence receipt, SecretStatus status,
        Session session)
    {
        if (facts.MatchedRequests != (receipt == DispatchEvidence.NotDispatched ? 0 : 1) ||
            facts.MatchedRequests == 0 && facts.ProviderRequestId != "" ||
            facts.MatchedRequests == 1 && !Text(facts.ProviderRequestId)) return false;
        if (status == SecretStatus.Success)
            return facts.ServiceBindAccepted && facts.UserBindAttempted && facts.UserBindAccepted &&
                !facts.Arm.Attempt.WrongUser && facts.TokenIssued && facts.MatchedIssuances == 1 &&
                Id(facts.TokenMetadataId) && facts.LastLoginAt is { } time && Utc(time) &&
                Witness(facts.CredentialWitness) &&
                (time >= facts.Arm.ArmedAt ||
                    session.LastLogins.TryGetValue(facts.Arm.Attempt.IdentityId, out DateTimeOffset prior) &&
                    time == prior && facts.Arm.ArmedAt - prior < TimeSpan.FromSeconds(10)) &&
                facts.LastLoginAuthMethod == "ldap-auth";
        return !facts.TokenIssued && facts.MatchedIssuances == 0 && facts.TokenMetadataId is null &&
            facts.CredentialWitness is null &&
            facts.LastLoginAt is null && facts.LastLoginAuthMethod is null &&
            (!facts.UserBindAttempted || facts.ServiceBindAccepted) &&
            (!facts.UserBindAccepted || facts.UserBindAttempted && !facts.Arm.Attempt.WrongUser) &&
            (receipt != DispatchEvidence.NotDispatched ||
                !facts.ServiceBindAccepted && !facts.UserBindAttempted && !facts.UserBindAccepted);
    }

    private Session Acquire(LdapDirectoryBinding? directory)
    {
        Session session = Acquire(directory?.Attempt);
        if (directory is not null && ReferenceEquals(directory, session.Directory)) return session;
        Release(session);
        throw Unavailable();
    }

    private Session Acquire(LdapDirectoryAttempt? attempt, bool cleanup = false)
    {
        lock (sessions)
        {
            if (attempt is null || !Text(attempt.Id) || !sessions.TryGetValue(attempt.Id, out Session? session) ||
                !ReferenceEquals(attempt, session.Attempt) || busy || session.CloseStarted ||
                !cleanup && (session.Unsettled || session.Directory is null)) throw Unavailable();
            busy = true;
            return session;
        }
    }

    private void Release(Session session)
    {
        lock (sessions) busy = false;
    }

    private ValueTask<T> Post<T>(Session session, string route, Action<Utf8JsonWriter> fields,
        CancellationToken token) where T : notnull
    {
        session.Unsettled = true;
        return channel.PostAsync<T>("ldap-login/" + route, fields, token);
    }

    private static void Write(Utf8JsonWriter writer, string name, object value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }

    private static bool Next(Session session, long sequence)
    {
        if (sequence <= session.Sequence) return false;
        session.Sequence = sequence;
        return true;
    }
    private static bool Outstanding(Session session) => session.LoginArm is not null || session.TemplateArm is not null;
    private static bool Bound(LdapDirectoryBinding? value, LdapDirectoryBinding expected) =>
        value == expected && value is not null && Utc(value.OpenedAt);
    private static bool Receipt(DispatchEvidence receipt) => receipt is DispatchEvidence.NotDispatched or
        DispatchEvidence.Rejected or DispatchEvidence.Applied or DispatchEvidence.PossiblyDispatched;
    private static bool Unique(HashSet<string> values, string? value) => Text(value) && values.Add(value!);
    private static bool Text(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Id(string? value) => Text(value) && Guid.TryParseExact(value, "D", out Guid id) &&
        id != Guid.Empty && id.ToString("D") == value;
    private static bool Utc(DateTimeOffset time) => time != default && time.Offset == TimeSpan.Zero;
    private static bool Private(char[] value) => value.Length is > 0 and <= 16384;
    private static bool Witness(string? value)
    {
        Span<byte> decoded = stackalloc byte[32];
        try
        {
            return value is { Length: 44 } && Convert.TryFromBase64String(value, decoded, out int count) &&
                count == decoded.Length;
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded); }
    }
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[InfisicalLdapLoginObserver]";

    private sealed class Session(LdapDirectoryAttempt attempt)
    {
        internal LdapDirectoryAttempt Attempt { get; } = attempt;
        internal LdapDirectoryBinding? Directory { get; set; }
        internal LdapLoginArm? LoginArm { get; set; }
        internal LdapTemplateArm? TemplateArm { get; set; }
        internal Dictionary<string, DateTimeOffset> LastLogins { get; } = new(StringComparer.Ordinal);
        internal long Sequence { get; set; }
        internal DateTimeOffset Time { get; set; }
        internal int LoginEvents { get; set; }
        internal bool Rotated { get; set; }
        internal bool Sealed { get; set; }
        internal bool Unsettled { get; set; }
        internal bool CloseStarted { get; set; }
        public override string ToString() => "[LdapSourceSession]";
    }
}
