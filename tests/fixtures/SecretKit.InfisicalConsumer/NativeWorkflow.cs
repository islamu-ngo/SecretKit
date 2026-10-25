using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical;

// Shared with the nonpackable conformance host. No management or database dependency.
internal static class NativeWorkflow
{
    internal static readonly string[] CaseIds =
    [
        "read", "read-native", "inspect", "repeat-revision", "selected-revision",
        "denied-read", "runtime-write-denied", "create", "update-value",
        "pending-approval", "recreation", "universal-login", "get-token",
        "renew-token", "expired-token", "explicit-recovery", "network", "cleanup",
        "deployment-binding", "actor-binding", "policy-binding"
    ];
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        MaxDepth = 16
    };

    internal static LocalNativeInput Parse(byte[] bytes)
    {
        try
        {
            Require(bytes.Length is > 0 and <= 131072);
            using JsonDocument document = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
            Unique(document.RootElement);
            LocalNativeWire wire = JsonSerializer.Deserialize<LocalNativeWire>(bytes, JsonOptions)!;
            Require(wire.SchemaVersion == 1 && wire.Kind == "local-native-run" &&
                wire.ProfileId == "infisical-runtime" && wire.Authority == "owned-local-native-execution");
            LocalNativeSettings settings = wire.Settings.Deserialize<LocalNativeSettings>(JsonOptions)!;
            Validate(settings);
            ValidateBinding(wire.Binding);
            if (settings.Issuance is { } proof)
            {
                Require(proof.Kind == "owned-causal-issuance-v1" && Guid.TryParseExact(proof.RunId, "N", out _) &&
                    proof.Owner == settings.Owner && proof.ProjectId == settings.ProjectId &&
                    proof.RecordSha256 == wire.Binding.RecordSha256 &&
                    proof.Environment == settings.Environment && proof.Folder == settings.Folder &&
                    proof.ForeignProjectId != settings.ProjectId &&
                    Guid.TryParseExact(proof.ForeignProjectId, "D", out _) &&
                    proof.ForeignEnvironment == "dev" && proof.ForeignFolder == "/" &&
                    proof.ForeignKey.StartsWith("SDK_", StringComparison.Ordinal) &&
                    proof.ExpectedReadValue.Length == 64 && proof.ForeignValue.Length == 64 &&
                    proof.TrialIds.SequenceEqual(NativeLifetimeTrials.Ids));
            }
            return new(wire.Binding, settings);
        }
        catch (Exception error) when (error is JsonException or ArgumentException or
            InvalidOperationException or NullReferenceException)
        {
            throw new InvalidOperationException("local-native-admission");
        }
    }

    internal static void ValidateBinding(LocalNativeBinding binding)
    {
        string[] packages = ["SecretKit.Core", "SecretKit.Infisical",
            "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting"];
        Require(binding.Version == "0.1.0-local.20261024.1" && Hash(binding.ProfileSha256) &&
            Hash(binding.SourceSha256) && Hash(binding.RecordSha256) &&
            binding.Packages.Length == 4 && binding.Packages.All(p => Hash(p.Sha256)) &&
            binding.Packages.Select(p => p.Id).Order(StringComparer.Ordinal)
                .SequenceEqual(packages.Order(StringComparer.Ordinal)));
    }

    private static void Validate(LocalNativeSettings s)
    {
        var origin = new Uri(s.Origin, UriKind.Absolute);
        Require(origin.UserInfo.Length == 0 && origin.AbsolutePath == "/" &&
            origin.Query.Length == 0 && origin.Fragment.Length == 0 &&
            (origin.Scheme == "https" && !s.AllowLoopbackDevelopmentHttp ||
                origin.Scheme == "http" && origin.Host == "127.0.0.1" &&
                !origin.IsDefaultPort && s.AllowLoopbackDevelopmentHttp));
        Require(s.Owner.Length == 22 && s.Owner.StartsWith("secretkit-sdk-", StringComparison.Ordinal) &&
            s.Owner[14..].All(char.IsAsciiHexDigit) && Guid.TryParseExact(s.OrganizationId, "D", out _) &&
            Guid.TryParseExact(s.ProjectId, "D", out _) && Text(s.Environment, 128) &&
            s.Folder == "/" + s.Owner && s.Edition is "oss" or "enterprise" or "cloud" &&
            Version.TryParse(s.ServerVersion, out _) && s.SelectedVersion is null or > 0);
        string prefix = "SDK_" + s.Owner[14..].ToUpperInvariant() + "_";
        string[] keys = s.ApprovalKey is null ? [s.ReadKey, s.WriteKey] : [s.ReadKey, s.WriteKey, s.ApprovalKey];
        Require(keys.Distinct(StringComparer.Ordinal).Count() == keys.Length &&
            keys.All(k => Text(k, 128) && k.StartsWith(prefix, StringComparison.Ordinal) &&
                k.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')));
        LocalNativeActor[] actors = [s.Setup, s.Runtime, s.Denied, s.Writer, s.Observer];
        Require(actors.All(a => Guid.TryParseExact(a.Id, "D", out _) && Text(a.Token, 16384) &&
                a.Token.All(c => c > ' ' && c < 127)) &&
            actors.Select(a => a.Id).Distinct(StringComparer.Ordinal).Count() == 5 &&
            actors.Select(a => a.Token).Distinct(StringComparer.Ordinal).Count() == 5);
        if (s.Authentication is { } auth)
        {
            Require(auth.ActorId == s.Runtime.Id && Text(auth.ClientId, 1024) &&
                Text(auth.ClientSecret, 16384) && Hash(auth.PolicyEvidenceSha256) &&
                (auth.Lifetime == "finite" && auth.PeriodSeconds is null ||
                    auth.Lifetime == "periodic" && auth.PeriodSeconds is > 0 and <= 86400) &&
                (auth.RecoveryClientSecret is null || Text(auth.RecoveryClientSecret, 16384) &&
                    auth.RecoveryClientSecret != auth.ClientSecret));
        }
    }

    internal static LocalNativeReport EmptyReport(LocalNativeInput input) =>
        new(1, "local-native-observation-not-public-approval", input.Binding, input.Settings.ServerVersion,
            "v4", input.Settings.Edition, System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier,
            CaseIds.Select(id => new LocalNativeCase(id, "unavailable",
                id is "deployment-binding" or "actor-binding" or "policy-binding" ?
                    "authoritative-proof-unavailable" : "not-observed")).ToArray())
        { ProofRun = input.Settings.Issuance?.RunId };

    internal static async Task<int> RunAsync(string[] args)
    {
        if (args.Length != 1 || !Path.IsPathFullyQualified(args[0]) || File.Exists(args[0]))
            return 2;
        LocalNativeReport? report = null;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4));
            byte[] bytes = await ReadEnvelopeAsync(Console.In, deadline.Token);
            LocalNativeInput input;
            try { input = Parse(bytes); }
            finally { Array.Clear(bytes); }
            report = EmptyReport(input);
            // Persist the complete denominator before credentials can leave the process.
            await WriteReportAsync(args[0], report, create: true);
            await ExecuteAsync(input, report, deadline.Token,
                () => WriteReportAsync(args[0], report, create: false));
            await WriteReportAsync(args[0], report, create: false);
            // Host teardown is deliberately a separate final observation.
            return report.Cases.Where(c => c.Id != "cleanup").All(c => c.Status == "passed") &&
                report.SupplementalCases.All(c => c.Status == "passed") ? 0 : 1;
        }
        catch
        {
            if (report is not null)
            {
                for (int i = 0; i < report.Cases.Length; i++)
                    if (report.Cases[i].Reason == "not-observed")
                        report.Cases[i] = report.Cases[i] with { Status = "unavailable", Reason = "execution-incomplete" };
                await WriteReportAsync(args[0], report, create: false);
            }
            // Never render exception text, response bodies, credentials or coordinates.
            return 1;
        }
    }

    internal static async Task ExecuteAsync(LocalNativeInput input, LocalNativeReport report, CancellationToken token,
        Func<Task> persist,
        Func<string, string, CancellationToken, Task<LocalTrialExchange>>? exchange = null,
        Func<string, string?, DispatchEvidence, CancellationToken, Task>? acknowledgeRenewal = null,
        TimeProvider? timeProvider = null, Func<DateTimeOffset, CancellationToken, Task>? probeArmed = null)
    {
        LocalNativeSettings s = input.Settings;
        using var runtime = new LocalNativeTokens(s.Runtime.Token);
        using var denied = new LocalNativeTokens(s.Denied.Token);
        using var writer = new LocalNativeTokens(s.Writer.Token);
        using var observer = new LocalNativeTokens(s.Observer.Token);
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ActivityHeadersPropagator = null
        };
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = s.AllowLoopbackDevelopmentHttp };
        Uri origin = new(s.Origin);
        await using var reader = new InfisicalClient(origin, handler, runtime, network);
        await using var deniedReader = new InfisicalClient(origin, handler, denied, network);
        await using var writeClient = new InfisicalClient(origin, handler, writer, network);
        await using var witness = new InfisicalClient(origin, handler, observer, network);
        SecretReference Select(InfisicalClient client, string key, int? version = null) =>
            new(client.Authority, new InfisicalSecretAddress(s.ProjectId, s.Environment, s.Folder, key, version));
        async Task Observe(string id, Func<Task<bool>> action, bool independentlyObserved = true)
        {
            try
            {
                if (await action())
                    Set(id, independentlyObserved ? "passed" : "unavailable",
                        independentlyObserved ? "observed" : "observation-unavailable");
                else Set(id, "failed", "observed");
            }
            catch (OperationCanceledException) { Set(id, "unavailable", "deadline-or-cancellation"); }
            catch { Set(id, "unavailable", "observation-unavailable"); }
        }
        void Set(string id, string status, string reason) =>
            report.Cases[Array.IndexOf(CaseIds, id)] = new(id, status, reason);

        InfisicalSecretRevision? initial = null;
        await Observe("read-native", async () =>
        {
            var result = await reader.ReadNativeAsync(Select(reader, s.ReadKey), token);
            if (!result.IsSuccess) return false;
            using var read = result.Value;
            initial = read.Revision;
            return read.Revision.Version > 0 && (s.Issuance is null ||
                read.Material.Reveal() == s.Issuance.ExpectedReadValue);
        });
        await Observe("read", async () =>
        {
            var result = await reader.ReadAsync(Select(reader, s.ReadKey), token);
            if (!result.IsSuccess) return false;
            using var read = result.Value;
            return true;
        });
        await Observe("inspect", async () =>
        {
            var result = await reader.InspectAsync(new InfisicalInventoryScope(reader.Authority,
                s.ProjectId, s.Environment, s.Folder), token);
            return result.IsSuccess && result.Value.IsComplete;
        });
        await Observe("repeat-revision", async () =>
        {
            var result = await witness.ReadNativeAsync(Select(witness, s.ReadKey), token);
            if (!result.IsSuccess) return false;
            using var read = result.Value;
            return initial is not null && initial == read.Revision;
        });
        if (s.SelectedVersion is int version)
            await Observe("selected-revision", async () =>
            {
                var result = await reader.ReadNativeAsync(Select(reader, s.ReadKey, version), token);
                if (!result.IsSuccess) return false;
                using var read = result.Value;
                return read.Revision.Version == version;
            });
        await Observe("denied-read", async () =>
        {
            var result = await deniedReader.ReadNativeAsync(Select(deniedReader, s.ReadKey), token);
            if (result.IsSuccess) result.Value.Dispose();
            return result.Status == SecretStatus.Denied;
        });
        using var material = SecretMaterial.FromText(Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
        using var replacementMaterial = SecretMaterial.FromText(Convert.ToHexString(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
        Require(material.Reveal() != replacementMaterial.Reveal());
        await Observe("runtime-write-denied", async () =>
        {
            SecretReference reference = Select(reader, s.ReadKey);
            var receipt = new MutationReceipt(reference);
            var result = await reader.UpdateValueAsync(reference, material, receipt, token);
            return result.Status == SecretStatus.Denied && receipt.Evidence == DispatchEvidence.Rejected;
        });
        InfisicalSecretRevision? writtenRevision = null;
        await Observe("create", () => Change(s.WriteKey, create: true, pending: false));
        if (report.Cases[Array.IndexOf(CaseIds, "create")].Status == "passed")
            await Observe("update-value", () => Change(s.WriteKey, create: false, pending: false));
        if (s.ApprovalKey is not null)
            // Preserve the submission receipt, but no supported independent
            // approval-state observation contract is established on this surface.
            await Observe("pending-approval", () => Change(s.ApprovalKey, create: false, pending: true),
                independentlyObserved: false);
        if (s.Recreate && initial is { Version: 1 })
            await Observe("recreation", async () =>
            {
                Console.WriteLine("LOCAL_RECREATE");
                await Console.Out.FlushAsync(token);
                Require(await Console.In.ReadLineAsync(token) == "continue");
                var result = await reader.ReadNativeAsync(Select(reader, s.ReadKey), token);
                if (!result.IsSuccess) return false;
                using var read = result.Value;
                return read.Revision.Version == initial.Version && read.Revision != initial;
            });
        Set("network", report.Cases[1].Status, "selected-origin-system-trust-and-proxy");
        if (s.Authentication is { } auth)
            await Authentication(auth);
        if (s.Issuance is { } issuance)
        {
            bool foreignDenied = false;
            try
            {
                SecretReference Foreign(InfisicalClient client) => new(client.Authority,
                    new InfisicalSecretAddress(issuance.ForeignProjectId, issuance.ForeignEnvironment,
                        issuance.ForeignFolder, issuance.ForeignKey));
                var populated = await witness.ReadNativeAsync(Foreign(witness), token);
                if (populated.IsSuccess)
                {
                    using var value = populated.Value;
                    var challenged = await reader.ReadNativeAsync(Foreign(reader), token);
                    if (challenged.IsSuccess) challenged.Value.Dispose();
                    foreignDenied = value.Material.Reveal() == issuance.ForeignValue &&
                        challenged.Status == SecretStatus.Denied;
                }
            }
            catch (OperationCanceledException) { }
            bool allowed = report.Cases.Single(c => c.Id == "read-native").Status == "passed";
            bool policy = allowed && foreignDenied &&
                report.Cases.Single(c => c.Id == "runtime-write-denied").Status == "passed" &&
                report.Cases.Single(c => c.Id == "denied-read").Status == "passed";
            Set("deployment-binding", "passed", "owned-causal-observation");
            Set("actor-binding", allowed && foreignDenied ? "passed" : "failed", "owned-causal-observation");
            Set("policy-binding", policy ? "passed" : "failed", "owned-causal-observation");
            Set("universal-login", allowed ? "passed" : "failed", "owned-causal-observation");
            Set("get-token", allowed ? "passed" : "failed", "observed");
            foreach (string id in NativeLifetimeTrials.Ids)
            {
                int index = Array.IndexOf(NativeLifetimeTrials.Ids, id);
                try
                {
                    LocalTrialExchange started = await Exchange(id, "start", token);
                    Require(started.Issued is null || started.Issued.Id == id);
                    report.SupplementalCases[index] = started.Status == SecretStatus.Success &&
                        started.Effect == DispatchEvidence.Applied && started.Issued is { } trial ?
                        await NativeLifetimeTrials.RunAsync(trial, s, handler, timeProvider ?? TimeProvider.System,
                            (operation, ct) => Exchange(id, operation, ct),
                            (value, effect, ct) => Acknowledge(id, value, effect, ct), token, probeArmed) :
                        new(id, "unavailable", "trial-unavailable");
                }
                catch (OperationCanceledException)
                { report.SupplementalCases[index] = new(id, "unavailable", "deadline-or-cancellation"); }
                catch { report.SupplementalCases[index] = new(id, "unavailable", "trial-unavailable"); }
                await persist();
            }
            foreach (var mapping in new[] { ("renew-token", "Q01"), ("expired-token", "Q03"), ("explicit-recovery", "Q06") })
            {
                var observed = report.SupplementalCases.Single(c => c.Id == mapping.Item2);
                Set(mapping.Item1, observed.Status, observed.Reason);
            }
        }
        report.ExecutionCompleted = true;
        // Setup and cleanup belong to the independently selected host, never this consumer.

        async Task<bool> Change(string key, bool create, bool pending)
        {
            SecretMaterial selectedMaterial = create ? material : replacementMaterial;
            SecretReference reference = Select(writeClient, key);
            var receipt = new MutationReceipt(reference);
            var result = create ? await CaptureCreateAsync(report, receipt,
                () => writeClient.CreateAsync(reference, selectedMaterial, receipt, token).AsTask(), persist) :
                await CaptureChangeAsync(report, receipt, pending,
                    () => writeClient.UpdateValueAsync(reference, selectedMaterial, receipt, token).AsTask(), persist);
            if (!result.IsSuccess) return false;
            if (pending) return result.Value.Disposition == InfisicalChangeDisposition.SubmittedForApproval &&
                receipt.Evidence == DispatchEvidence.Pending;
            if (result.Value.Disposition != InfisicalChangeDisposition.Applied || receipt.Evidence != DispatchEvidence.Applied)
                return false;
            var observed = await witness.ReadNativeAsync(Select(witness, key), token);
            if (!observed.IsSuccess) return false;
            using var value = observed.Value;
            bool matched = value.Material.Reveal() == selectedMaterial.Reveal();
            if (create) writtenRevision = value.Revision;
            else matched &= writtenRevision is not null && value.Revision != writtenRevision;
            return matched;
        }

        async Task<LocalTrialExchange> Exchange(string id, string operation, CancellationToken ct)
        {
            if (exchange is not null) return await exchange(id, operation, ct);
            await Console.Out.WriteLineAsync($"LOCAL_TRIAL {id} {operation}".AsMemory(), ct);
            await Console.Out.FlushAsync(ct);
            byte[] response = await ReadEnvelopeAsync(Console.In, ct);
            try
            {
                using var doc = JsonDocument.Parse(response);
                Unique(doc.RootElement);
                return JsonSerializer.Deserialize<LocalTrialExchange>(response, JsonOptions)!;
            }
            finally { Array.Clear(response); }
        }
        async Task Acknowledge(string id, string? value, DispatchEvidence effect, CancellationToken ct)
        {
            if (acknowledgeRenewal is not null) { await acknowledgeRenewal(id, value, effect, ct); return; }
            // This is protected parent/child IPC, not a report or diagnostic sink.
            await Console.Out.WriteLineAsync(("LOCAL_RENEWED " + id + " " + effect + " " +
                JsonSerializer.Serialize(value, JsonOptions)).AsMemory(), ct);
            await Console.Out.FlushAsync(ct);
            Require(await Console.In.ReadLineAsync(ct) == "acknowledged");
        }

        async Task Authentication(LocalNativeAuthentication auth)
        {
            using var authentication = new InfisicalUniversalAuthentication(origin, handler, network);
            InfisicalUniversalLogin? login = null;
            try
            {
                await Observe("universal-login", async () =>
                {
                    using var secret = SecretMaterial.FromText(auth.ClientSecret);
                    var receipt = authentication.CreateReceipt();
                    var result = await authentication.LoginAsync(auth.ClientId, secret, receipt, cancellationToken: token);
                    if (!result.IsSuccess) return false;
                    login = result.Value;
                    return receipt.Evidence == DispatchEvidence.Applied;
                });
                if (login is not null && (auth.Lifetime == "periodic" || login.AccessTokenMaxTTL > 0))
                {
                    var evidence = login.BindLifetimeEvidence(new()
                    {
                        OriginalIssuedAt = login.RequestStartedAt,
                        ExpiresAt = login.Token.ExpiresAt!.Value,
                        Lifetime = auth.Lifetime == "periodic" ? InfisicalTokenLifetime.Periodic : InfisicalTokenLifetime.Finite,
                        Period = auth.PeriodSeconds is int period ? TimeSpan.FromSeconds(period) : null,
                        ReportedMaximumTtl = TimeSpan.FromSeconds(login.AccessTokenMaxTTL)
                    });
                    await using var session = new InfisicalPeriodicTokenSession(login, evidence,
                        TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(10), handler, network);
                    await using var authenticated = new InfisicalClient(origin, handler, session, network);
                    await Observe("get-token", async () =>
                    {
                        var result = await authenticated.ReadNativeAsync(Select(authenticated, s.ReadKey), token);
                        if (!result.IsSuccess) return false;
                        using var read = result.Value;
                        return true;
                    });
                    if (!auth.ObserveExpiry)
                        await Observe("renew-token", async () =>
                            await session.RenewAsync(token) == SecretStatus.Success &&
                            session.LastRenewal?.Evidence == InfisicalRenewalEvidence.Applied);
                    else if (login.ExpiresIn <= 45)
                        await Observe("expired-token", async () =>
                        {
                            // Time itself is the native behavior under observation. The response
                            // completion plus TTL is a conservative upper bound, not a reset
                            // of the session's original issue/expiry evidence.
                            DateTimeOffset upperExpiry = DateTimeOffset.UtcNow.AddSeconds(login.ExpiresIn);
                            await Task.Delay(upperExpiry - DateTimeOffset.UtcNow, token);
                            using var expired = new LocalNativeTokens(login.Token.Material.Reveal());
                            await using var expiredReader = new InfisicalClient(origin, handler, expired, network);
                            var rejected = await expiredReader.ReadNativeAsync(Select(expiredReader, s.ReadKey), token);
                            if (rejected.IsSuccess) rejected.Value.Dispose();
                            var local = await session.GetTokenAsync(token);
                            if (local.IsSuccess) local.Value.Dispose();
                            return rejected.Status == SecretStatus.Denied && local.Status == SecretStatus.RecoveryRequired;
                        });
                }
                if (auth.RecoveryClientSecret is not null &&
                    report.Cases[Array.IndexOf(CaseIds, "expired-token")].Status == "passed")
                    await Observe("explicit-recovery", async () =>
                    {
                        using var replacement = SecretMaterial.FromText(auth.RecoveryClientSecret);
                        var result = await authentication.LoginAsync(auth.ClientId, replacement,
                            authentication.CreateReceipt(), cancellationToken: token);
                        if (!result.IsSuccess) return false;
                        using var recovered = result.Value;
                        using var selected = new LocalNativeTokens(recovered.Token.Material.Reveal());
                        await using var recoveredReader = new InfisicalClient(origin, handler, selected, network);
                        var read = await recoveredReader.ReadNativeAsync(Select(recoveredReader, s.ReadKey), token);
                        if (!read.IsSuccess) return false;
                        read.Value.Dispose();
                        if (recovered.AccessTokenMaxTTL > 0 || auth.Lifetime == "periodic")
                        {
                            var evidence = recovered.BindLifetimeEvidence(new()
                            {
                                OriginalIssuedAt = recovered.RequestStartedAt,
                                ExpiresAt = recovered.Token.ExpiresAt!.Value,
                                Lifetime = auth.Lifetime == "periodic" ? InfisicalTokenLifetime.Periodic : InfisicalTokenLifetime.Finite,
                                Period = auth.PeriodSeconds is int period ? TimeSpan.FromSeconds(period) : null,
                                ReportedMaximumTtl = TimeSpan.FromSeconds(recovered.AccessTokenMaxTTL)
                            });
                            await using var recoveredSession = new InfisicalPeriodicTokenSession(recovered, evidence,
                                TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(10), handler, network);
                            await Observe("renew-token", async () =>
                                await recoveredSession.RenewAsync(token) == SecretStatus.Success &&
                                recoveredSession.LastRenewal?.Evidence == InfisicalRenewalEvidence.Applied);
                        }
                        return true;
                    });
            }
            finally { login?.Dispose(); }
        }
    }

    internal static async Task<byte[]> ReadBoundedAsync(Stream stream, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        byte[] block = new byte[4096];
        try
        {
            int count;
            while ((count = await stream.ReadAsync(block, token)) != 0)
            {
                Require(buffer.Length + count <= 131072);
                buffer.Write(block, 0, count);
            }
            return buffer.ToArray();
        }
        finally { Array.Clear(block); }
    }

    private static async Task<byte[]> ReadEnvelopeAsync(TextReader reader, CancellationToken token)
    {
        var text = new System.Text.StringBuilder();
        char[] character = new char[1];
        try
        {
            while (await reader.ReadAsync(character.AsMemory(), token) != 0)
            {
                if (character[0] == '\n') return System.Text.Encoding.UTF8.GetBytes(text.ToString());
                Require(text.Length < 131072);
                text.Append(character[0]);
            }
            throw new InvalidOperationException("local-native-envelope-incomplete");
        }
        finally { Array.Clear(character); text.Clear(); }
    }

    internal static async Task<T> CaptureCreateAsync<T>(LocalNativeReport report, MutationReceipt receipt,
        Func<Task<T>> dispatch, Func<Task> persist)
    {
        try { return await dispatch(); }
        finally
        {
            // A failed witness must not erase an acknowledged resource or authorize
            // speculative cleanup of a possibly dispatched operation.
            report.CreateEffect = receipt.Evidence;
            await persist();
        }
    }

    private static async Task<T> CaptureChangeAsync<T>(LocalNativeReport report, MutationReceipt receipt, bool approval,
        Func<Task<T>> dispatch, Func<Task> persist)
    {
        try { return await dispatch(); }
        finally
        {
            if (approval) report.ApprovalEffect = receipt.Evidence;
            else report.UpdateEffect = receipt.Evidence;
            await persist();
        }
    }

    private static async Task WriteReportAsync(string path, LocalNativeReport report, bool create)
    {
        await using var stream = new FileStream(path, create ? FileMode.CreateNew : FileMode.Truncate,
            FileAccess.Write, FileShare.Read);
        await JsonSerializer.SerializeAsync(stream, report, JsonOptions);
    }
    internal static void Require([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new InvalidOperationException("local-native-contract");
    }
    private static bool Text(string text, int limit) =>
        !string.IsNullOrWhiteSpace(text) && text.Length <= limit && !text.Any(char.IsControl);
    private static bool Hash(string text) => text.Length == 64 &&
        text.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f');
    private static void Unique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty p in element.EnumerateObject()) { Require(names.Add(p.Name)); Unique(p.Value); }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (JsonElement item in element.EnumerateArray()) Unique(item);
    }
}

internal sealed record LocalNativePackage(string Id, string Sha256);
internal sealed record LocalNativeBinding(string Version, string ProfileSha256, string SourceSha256,
    string RecordSha256, LocalNativePackage[] Packages);
internal sealed record LocalNativeWire(int SchemaVersion, string Kind, string ProfileId, string Authority,
    LocalNativeBinding Binding, JsonElement Settings)
{
    public override string ToString() => "[LocalNativeWire]";
}
internal sealed class LocalNativeInput(LocalNativeBinding binding, LocalNativeSettings settings)
{
    [JsonIgnore] public LocalNativeBinding Binding { get; } = binding;
    [JsonIgnore] public LocalNativeSettings Settings { get; } = settings;
    public override string ToString() => "[LocalNativeInput]";
}
internal sealed record LocalNativeSettings(string Origin, bool AllowLoopbackDevelopmentHttp, string Owner,
    string OrganizationId, string ProjectId, string Environment, string Folder, string ReadKey, string WriteKey,
    string? ApprovalKey, int? SelectedVersion, string ServerVersion, string Edition, bool Recreate,
    LocalNativeActor Setup, LocalNativeActor Runtime, LocalNativeActor Denied, LocalNativeActor Writer,
    LocalNativeActor Observer, LocalNativeAuthentication? Authentication)
{
    public LocalNativeIssuance? Issuance { get; init; }
    public override string ToString() => "[LocalNativeSettings]";
}
internal sealed record LocalNativeIssuance(string Kind, string RunId, string RecordSha256, string Owner, string ProjectId,
    string Environment, string Folder, string ForeignProjectId, string ForeignEnvironment, string ForeignFolder,
    string ForeignKey, string ExpectedReadValue, string ForeignValue, string[] TrialIds)
{
    public override string ToString() => "[LocalNativeIssuance]";
}
internal sealed record LocalNativeActor(string Id, string Token)
{
    public override string ToString() => "[LocalNativeActor]";
}
internal sealed record LocalProducerCleanup(string Status, int OutstandingKnown, int Uncertain);
internal sealed record LocalNativeAuthentication(string ActorId, string ClientId, string ClientSecret,
    string PolicyEvidenceSha256, string Lifetime, int? PeriodSeconds, string? RecoveryClientSecret, bool ObserveExpiry)
{
    public override string ToString() => "[LocalNativeAuthentication]";
}
internal sealed record LocalNativeCase(string Id, string Status, string Reason);
internal sealed record LocalNativeReport(int SchemaVersion, string Kind, LocalNativeBinding Binding,
    string DeclaredServerVersion, string ApiVersion, string DeclaredEdition, string Platform, LocalNativeCase[] Cases)
{
    [JsonRequired] public string? ProofRun { get; init; }
    [JsonRequired]
    public LocalNativeCase[] SupplementalCases { get; init; } = NativeLifetimeTrials.Ids
        .Select(id => new LocalNativeCase(id, "unavailable", "not-observed")).ToArray();
    [JsonRequired] public LocalProducerCleanup ProducerCleanup { get; set; } = new("unavailable", 0, 0);
    [JsonConverter(typeof(JsonStringEnumConverter<DispatchEvidence>))]
    public DispatchEvidence CreateEffect { get; set; } = DispatchEvidence.NotDispatched;
    [JsonRequired, JsonConverter(typeof(JsonStringEnumConverter<DispatchEvidence>))]
    public DispatchEvidence UpdateEffect { get; set; } = DispatchEvidence.NotDispatched;
    [JsonRequired, JsonConverter(typeof(JsonStringEnumConverter<DispatchEvidence>))]
    public DispatchEvidence ApprovalEffect { get; set; } = DispatchEvidence.NotDispatched;
    [JsonRequired] public bool ExecutionCompleted { get; set; }
}

internal sealed class LocalNativeTokens : IInfisicalTokenSource, IDisposable
{
    private readonly SecretMaterial material;
    internal LocalNativeTokens(string token) => material = SecretMaterial.FromText(token);
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
    }
    public void Dispose() => material.Dispose();
    public override string ToString() => "[LocalNativeTokens]";
}
