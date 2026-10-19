using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

internal static class AzureKeyVaultClientEffects
{
    internal static bool DeniedMutationMatches(SecretStatus status, int? httpStatus, DispatchEvidence evidence) =>
        httpStatus == 403 && (status == SecretStatus.Denied && evidence == DispatchEvidence.Rejected ||
            status == SecretStatus.Unknown && evidence == DispatchEvidence.PossiblyDispatched);

    internal static bool InventoryMatches(IReadOnlyList<(string Name, string Version)> actual,
        IReadOnlyList<(string Name, string Version)> observed, bool complete)
    {
        var actualSet = actual.ToHashSet();
        var observedSet = observed.ToHashSet();
        return actualSet.Count == actual.Count && observedSet.Count == observed.Count &&
            (complete ? actualSet.SetEquals(observedSet) : actualSet.IsProperSubsetOf(observedSet));
    }

    private const string Prefix = "a.runtime.AzureKeyVaultClient.";

    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        foreach (NativeCaseDefinition definition in expected.Where(d => d.Key.Provider == "AzureKeyVault" &&
            d.Key.Operation is Prefix + "ReadAsync" or Prefix + "SetSecretAsync" or Prefix + "InspectAsync"))
        {
            registry.Add(new(definition, (probe, token) => Execute(environment, definition, probe, token)));
        }
    }

    private static async ValueTask Execute(OwnedAzureEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        string selectedMember = definition.Key.Operation[Prefix.Length..] switch
        {
            "ReadAsync" => "ReadAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            "InspectAsync" => "InspectAsync(SecretKit.Core.SecretInventoryScope,System.Threading.CancellationToken)",
            "SetSecretAsync" => "SetSecretAsync(SecretKit.AzureKeyVault.AzureSetSecretRequest,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            _ => throw new NativeCaseFailureException("missing-registration")
        };
        probe.Contract(definition.Member == "SecretKit.AzureKeyVault.AzureKeyVaultClient." + selectedMember,
            NativeFailure.ContractMismatch);
        JsonElement input = environment.RequireFamilyInput("C08-AR-AzureKeyVaultClient");
        string sandbox = input.GetProperty("namespace").GetString()!;
        probe.Contract(sandbox.Length is >= 3 and <= 40 && sandbox.All(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-'), NativeFailure.MissingInput);
        string name = sandbox + "-" + Guid.NewGuid().ToString("N");
        string initial = Guid.NewGuid().ToString("N");
        string replacement = Guid.NewGuid().ToString("N");
        string written = Guid.NewGuid().ToString("N");
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var wire = new HttpClientTransport(http);
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = wire };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var setup = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Setup), options);
        var observer = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Observer), options);
        var ownedNames = new List<string>();
        try
        {
            var seed = new KeyVaultSecret(name, initial);
            seed.Properties.Enabled = true;
            // Keep ownership before dispatch, including an uncertain setup response.
            ownedNames.Add(name);
            KeyVaultSecret first = (await setup.SetSecretAsync(seed, token)).Value;
            seed = new KeyVaultSecret(name, replacement);
            seed.Properties.Enabled = true;
            if (definition.Key.Variant == "validity.disabled-denied") seed.Properties.Enabled = false;
            DateTimeOffset selectedTime = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (definition.Key.Variant == "validity.not-yet-valid") seed.Properties.NotBefore = selectedTime.AddDays(1);
            if (definition.Key.Variant == "validity.expired") seed.Properties.ExpiresOn = selectedTime.AddDays(-1);
            KeyVaultSecret latest = (await setup.SetSecretAsync(seed, token)).Value;
            if (definition.Key.Operation == Prefix + "InspectAsync" && definition.Key.Variant == "page.page-budget")
            {
                // The SDK requests at most 25 items per page. Own the pagination witness
                // instead of depending on unrelated secrets already in the vault.
                for (int index = 0; index < 25; index++)
                {
                    string additional = sandbox + "-" + Guid.NewGuid().ToString("N");
                    ownedNames.Add(additional);
                    var pageSeed = new KeyVaultSecret(additional, initial);
                    pageSeed.Properties.Enabled = true;
                    await setup.SetSecretAsync(pageSeed, token);
                }
            }
            string[] baseline = await Versions(observer, name, token);
            probe.Contract(baseline.Length == 2 && baseline.Contains(first.Properties.Version) &&
                baseline.Contains(latest.Properties.Version), NativeFailure.MissingPrerequisite);

            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var boundary = new ResponseBoundary(wire, name);
            AzureKeyVaultClient client = environment.CreateClient(definition.Key.Case == "denied-authority"
                ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime, boundary);
            var target = new SecretReference(client.Authority, new AzureSecretAddress(name,
                definition.Key.Variant == "version.exact" ? first.Properties.Version : null));
            bool cancelled = definition.Key.Case == "cancellation-boundary";
            bool lost = definition.Key.Case == "lost-response-no-replay";
            string operation = definition.Key.Operation[Prefix.Length..];
            bool rejected = operation == "SetSecretAsync" && definition.Key.Variant != "precondition.None";
            // Rejected preconditions have no transport boundary: cancellation is tested before dispatch.
            if (cancelled && rejected) cancellation.Cancel();
            boundary.Hold = cancelled && !rejected;
            boundary.Lose = lost && !rejected;
            Task execution = Invoke();
            if (boundary.Hold)
            {
                Task winner = await Task.WhenAny(execution, boundary.Observed.Task).WaitAsync(token);
                if (winner == boundary.Observed.Task)
                {
                    cancellation.Cancel();
                    boundary.Release.TrySetResult();
                }
            }
            try
            {
                await execution;
                probe.Contract(!cancelled, NativeFailure.ContractMismatch);
            }
            catch (OperationCanceledException) when (cancelled && cancellation.IsCancellationRequested)
            {
                probe.Contract(true, NativeFailure.ContractMismatch);
            }

            string[] after = await Versions(observer, name, token);
            bool wrote = operation == "SetSecretAsync" && !rejected && definition.Key.Case != "denied-authority";
            probe.Effect(after.Length == baseline.Length + (wrote ? 1 : 0) &&
                baseline.All(after.Contains) ? NativeObservation.Matched : NativeObservation.Mismatched);
            if (wrote || seed.Properties.Enabled == true && seed.Properties.NotBefore is null &&
                seed.Properties.ExpiresOn is null)
            {
                KeyVaultSecret independentlyRead = (await observer.GetSecretAsync(name,
                    definition.Key.Variant == "version.exact" ? first.Properties.Version : null, token)).Value;
                probe.Effect(independentlyRead.Value == (wrote ? written :
                    definition.Key.Variant == "version.exact" ? initial : replacement)
                    ? NativeObservation.Matched : NativeObservation.Mismatched);
            }
            else
            {
                SecretProperties? independentlyRead = null;
                await foreach (SecretProperties property in observer.GetPropertiesOfSecretVersionsAsync(name, token))
                    if (property.Version == latest.Properties.Version) independentlyRead = property;
                probe.Effect(independentlyRead is not null &&
                    independentlyRead.Enabled == seed.Properties.Enabled &&
                    independentlyRead.NotBefore == seed.Properties.NotBefore &&
                    independentlyRead.ExpiresOn == seed.Properties.ExpiresOn
                    ? NativeObservation.Matched : NativeObservation.Mismatched);
            }

            async Task Invoke()
            {
                switch (operation)
                {
                    case "ReadAsync":
                        SecretOutcome<SecretRead> read = await client.ReadAsync(target, cancellation.Token);
                        if (read.IsSuccess)
                        {
                            using SecretRead owned = read.Value;
                            probe.Contract(definition.Key.Case != "denied-authority" &&
                                owned.Material.Reveal() == (definition.Key.Variant == "version.exact" ? initial : replacement),
                                NativeFailure.ContractMismatch);
                        }
                        else
                        {
                            probe.Contract(definition.Key.Case == "denied-authority" ? read.Status == SecretStatus.Denied :
                                definition.Key.Variant switch
                                {
                                    "validity.disabled-denied" => read.Status == SecretStatus.Denied,
                                    "validity.not-yet-valid" => read.Status is SecretStatus.Invalid or SecretStatus.Denied,
                                    "validity.expired" => read.Status is SecretStatus.Expired or SecretStatus.Denied,
                                    _ => false
                                }, NativeFailure.ContractMismatch);
                        }
                        break;
                    case "SetSecretAsync":
                        using (SecretMaterial material = SecretMaterial.FromText(written))
                        {
                            AzureSetSecretPrecondition condition = definition.Key.Variant switch
                            {
                                "precondition.None" => AzureSetSecretPrecondition.None,
                                "precondition.CreateOnly.rejected" => AzureSetSecretPrecondition.CreateOnly,
                                "precondition.MatchVersion.rejected" => AzureSetSecretPrecondition.MatchVersion,
                                _ => throw new NativeCaseFailureException("missing-input")
                            };
                            var receipt = new MutationReceipt(target);
                            try
                            {
                                SecretOutcome<AzureSetSecretResult> write = await client.SetSecretAsync(new(target, material, condition),
                                    receipt, cancellation.Token);
                                probe.Contract(rejected ? write.Status == SecretStatus.Unsupported &&
                                    receipt.Evidence == DispatchEvidence.NotDispatched :
                                    definition.Key.Case == "denied-authority" ?
                                        DeniedMutationMatches(write.Status, boundary.LastAuthorizedStatus, receipt.Evidence) :
                                    lost ? write.Status == SecretStatus.Unknown &&
                                        receipt.Evidence == DispatchEvidence.PossiblyDispatched :
                                    write.IsSuccess && receipt.Evidence == DispatchEvidence.Applied,
                                    NativeFailure.ContractMismatch);
                            }
                            catch (OperationCanceledException)
                            {
                                probe.Contract(receipt.Evidence == (rejected ? DispatchEvidence.NotDispatched :
                                    DispatchEvidence.PossiblyDispatched), NativeFailure.ContractMismatch);
                                throw;
                            }
                        }
                        break;
                    case "InspectAsync":
                        JsonElement limits = input.GetProperty("inventory");
                        int pages = definition.Key.Variant == "page.page-budget" ? 1 : limits.GetProperty("maximumPages").GetInt32();
                        int items = definition.Key.Variant == "page.item-budget" ? 1 : limits.GetProperty("maximumItems").GetInt32();
                        SecretOutcome<SecretInventory> inventory = await client.InspectAsync(
                            new AzureInventoryScope(client.Authority, pages, items), cancellation.Token);
                        if (definition.Key.Case == "denied-authority")
                            probe.Contract(inventory.Status == SecretStatus.Denied, NativeFailure.ContractMismatch);
                        else
                        {
                            probe.Contract(inventory.IsSuccess, NativeFailure.ContractMismatch);
                            var observed = new List<(string Name, string Version)>();
                            await foreach (SecretProperties property in observer.GetPropertiesOfSecretsAsync(token))
                                observed.Add((property.Name, property.Version));
                            probe.Contract(inventory.Value.Items.All(i => i.Reference.Address is AzureSecretAddress address &&
                                observed.Contains((address.Name, address.Version!))) &&
                                inventory.Value.Items.Count <= items && !inventory.Value.IsPointInTime,
                                NativeFailure.ContractMismatch);
                            probe.Effect(InventoryMatches(inventory.Value.Items.Select(i =>
                                (AzureSecretAddress)i.Reference.Address).Select(a => (a.Name, a.Version!)).ToArray(),
                                observed, inventory.Value.IsComplete) ? NativeObservation.Matched : NativeObservation.Mismatched);
                            if (definition.Key.Variant is "selector.exact" or "page.complete")
                                probe.Contract(inventory.Value.IsComplete, NativeFailure.ContractMismatch);
                            else probe.Contract(!inventory.Value.IsComplete, NativeFailure.MissingPrerequisite);
                        }
                        break;
                    default:
                        throw new NativeCaseFailureException("missing-registration");
                }
            }
        }
        finally
        {
            if (ownedNames.Count > 0)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                bool clean = true;
                foreach (string ownedName in ownedNames)
                {
                    try
                    {
                        try { await setup.StartDeleteSecretAsync(ownedName, cleanup.Token); }
                        catch (RequestFailedException error) when (error.Status == 404) { }
                        try
                        {
                            await observer.GetSecretAsync(ownedName, cancellationToken: cleanup.Token);
                            clean = false;
                        }
                        catch (RequestFailedException error) when (error.Status == 404) { }
                    }
                    catch (Exception)
                    {
                        clean = false;
                    }
                }
                probe.Contract(clean, NativeFailure.CleanupIncomplete);
                environment.ConfirmPrerequisite(definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Matched);
            }
        }
    }

    private static async Task<string[]> Versions(SecretClient observer, string name, CancellationToken token)
    {
        var versions = new List<string>();
        await foreach (SecretProperties property in observer.GetPropertiesOfSecretVersionsAsync(name, token))
            versions.Add(property.Version);
        return versions.ToArray();
    }

    internal sealed class ResponseBoundary(HttpPipelineTransport inner, string name, string? selectedPath = null) : HttpPipelineTransport
    {
        public bool Hold { get; set; }
        public bool Lose { get; set; }
        public int? LastAuthorizedStatus { get; private set; }
        public TaskCompletionSource Observed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-native-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (message.Request.Headers.Contains("Authorization"))
                LastAuthorizedStatus = message.Response.Status;
            if ((Hold || Lose) && message.Request.Headers.Contains("Authorization") &&
                message.Request.Uri.ToUri().AbsolutePath.StartsWith(selectedPath ?? "/secrets/" + name, StringComparison.Ordinal))
            {
                Observed.TrySetResult();
                if (Hold) await Release.Task.WaitAsync(message.CancellationToken);
                if (Lose)
                {
                    message.Response.Dispose();
                    throw new IOException("native-lost-response");
                }
            }
        }
    }
}
