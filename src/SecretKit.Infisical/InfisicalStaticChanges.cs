using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

public enum InfisicalChangeDisposition
{
    Applied,
    SubmittedForApproval
}

public sealed class InfisicalStaticChange
{
    internal InfisicalStaticChange(InfisicalChangeDisposition disposition, string? version, string? approvalId)
    {
        Disposition = disposition;
        Version = version;
        ApprovalId = approvalId;
    }

    public InfisicalChangeDisposition Disposition { get; }
    [JsonIgnore]
    public string? Version { get; }
    [JsonIgnore]
    public string? ApprovalId { get; }
    public override string ToString() => $"[InfisicalStaticChange:{Disposition}]";
}

public sealed partial class InfisicalClient
{
    /// <summary>Creates a selected shared secret; provider policy may submit an approval instead.</summary>
    public ValueTask<SecretOutcome<InfisicalStaticChange>> CreateAsync(SecretReference target,
        SecretMaterial material, MutationReceipt receipt, CancellationToken cancellationToken = default) =>
        ChangeValueAsync(target, material, receipt, HttpMethod.Post, cancellationToken);

    /// <summary>Updates a selected shared secret without pretending to provide compare-and-swap.</summary>
    public ValueTask<SecretOutcome<InfisicalStaticChange>> UpdateValueAsync(SecretReference target,
        SecretMaterial material, MutationReceipt receipt, CancellationToken cancellationToken = default) =>
        ChangeValueAsync(target, material, receipt, HttpMethod.Patch, cancellationToken);

    private async ValueTask<SecretOutcome<InfisicalStaticChange>> ChangeValueAsync(SecretReference target,
        SecretMaterial material, MutationReceipt receipt, HttpMethod method, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();
        if (!target.BelongsTo(Authority) || target.Address is not InfisicalSecretAddress address ||
            !receipt.IsFor(target) || receipt.Evidence != DispatchEvidence.NotDispatched)
        {
            return SecretOutcome<InfisicalStaticChange>.Failure(SecretStatus.Invalid);
        }

        if (address.Version is not null || address.IncludeImports ||
            address.Resolution != InfisicalResolution.Raw)
        {
            return SecretOutcome<InfisicalStaticChange>.Failure(SecretStatus.Unsupported);
        }

        // Copy before awaiting token/network work; the caller continues owning its original.
        using SecretMaterial owned = material.Copy();
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            projectId = address.ProjectId,
            environment = address.Environment,
            secretPath = address.Folder,
            secretValue = owned.Reveal(),
            type = "shared",
            skipMultilineEncoding = true
        });
        if (payload.Length > _responseLimit)
        {
            Array.Clear(payload);
            return SecretOutcome<InfisicalStaticChange>.Failure(SecretStatus.Invalid);
        }

        try
        {
            BeginOperation();
        }
        catch
        {
            Array.Clear(payload);
            throw;
        }

        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
            using var content = new ByteArrayContent(payload);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            using HttpRequestMessage request = method == HttpMethod.Post
                ? await _staticWire.CreateAsync(address.Key, content, linked.Token).ConfigureAwait(false)
                : await _staticWire.UpdateAsync(address.Key, content, linked.Token).ConfigureAwait(false);
            SecretOutcome<JsonDocument> result = await ReadDocumentAsync(request, linked.Token, receipt, target);
            if (!result.IsSuccess)
            {
                SecretStatus status = receipt.Evidence == DispatchEvidence.PossiblyDispatched
                    ? SecretStatus.Unknown : result.Status;
                return SecretOutcome<InfisicalStaticChange>.Failure(status,
                    status == SecretStatus.Throttled ? result.RetryAfter : null);
            }

            using JsonDocument document = result.Value;
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return SecretOutcome<InfisicalStaticChange>.Failure(SecretStatus.Unknown);
            }

            if (root.TryGetProperty("approval", out JsonElement approval) &&
                approval.ValueKind == JsonValueKind.Object)
            {
                if (root.TryGetProperty("secret", out _) ||
                    !approval.TryGetProperty("id", out JsonElement id) || id.ValueKind != JsonValueKind.String ||
                    !Guid.TryParse(id.GetString(), out _) ||
                    (approval.TryGetProperty("hasMerged", out JsonElement merged) &&
                        merged.ValueKind != JsonValueKind.False))
                {
                    return SecretOutcome<InfisicalStaticChange>.Failure(SecretStatus.Unknown);
                }

                receipt.Record(DispatchEvidence.Pending);
                return SecretOutcome<InfisicalStaticChange>.Success(new(
                    InfisicalChangeDisposition.SubmittedForApproval, null, id.GetString()));
            }

            if (!root.TryGetProperty("secret", out JsonElement secret) || secret.ValueKind != JsonValueKind.Object ||
                !secret.TryGetProperty("secretKey", out JsonElement key) || key.ValueKind != JsonValueKind.String ||
                !secret.TryGetProperty("workspace", out JsonElement project) || project.ValueKind != JsonValueKind.String ||
                !secret.TryGetProperty("environment", out JsonElement environment) || environment.ValueKind != JsonValueKind.String)
            {
                return SecretOutcome<InfisicalStaticChange>.Failure(SecretStatus.Unknown);
            }

            if (key.GetString() != address.Key || project.GetString() != address.ProjectId ||
                environment.GetString() != address.Environment ||
                secret.TryGetProperty("secretPath", out JsonElement path) &&
                    (path.ValueKind != JsonValueKind.String || path.GetString() != address.Folder) ||
                secret.TryGetProperty("type", out JsonElement type) &&
                    (type.ValueKind != JsonValueKind.String || type.GetString() != "shared") ||
                secret.TryGetProperty("version", out JsonElement returnedVersion) &&
                    returnedVersion.ValueKind == JsonValueKind.Number &&
                    returnedVersion.TryGetInt32(out int number) && number <= 0)
                return SecretOutcome<InfisicalStaticChange>.Failure(SecretStatus.Invalid);

            if (Version(secret) is not { } version)
                return SecretOutcome<InfisicalStaticChange>.Failure(SecretStatus.Unknown);

            receipt.Record(DispatchEvidence.Applied);
            return SecretOutcome<InfisicalStaticChange>.Success(new(InfisicalChangeDisposition.Applied, version, null));
        }
        finally
        {
            Array.Clear(payload);
            EndOperation();
        }
    }
}
