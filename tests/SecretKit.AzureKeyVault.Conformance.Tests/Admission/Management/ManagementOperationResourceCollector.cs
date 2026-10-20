using System.ClientModel.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.EventGrid;
using Azure.ResourceManager.EventGrid.Models;
using Azure.ResourceManager.KeyVault;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// One independent concrete resource GET. No selected client, handle, operation
// status endpoint, expected result, source URL, action read or mutation is used.
// This source is not an authenticated service or a live qualification.
internal sealed class ManagementOperationResourceCollector
{
    internal const string ArmOrigin = "https://management.azure.com";
    internal enum Failure { None, Boundary, Budget, Denied, Unavailable, Deadline }
    internal sealed record Limits(int MaximumResponseBytes, int MaximumRowBytes, int MaximumNodes,
        int MaximumRows, int MaximumDepth, TimeSpan Timeout);
    internal sealed record Authority([property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential, [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[ManagementResourceAuthority]";
    }

    // No public constructor or mutable registration data. Even reflection-created
    // copies cannot appear in the source's private reference-keyed registry.
    internal sealed class Window
    {
        private Window(Capture.Binding binding, DateTimeOffset armedAt, bool statusPrivateDeleteSelectedProfile)
        {
            Binding = binding;
            ArmedAt = armedAt;
            StatusPrivateDeleteSelectedProfile = statusPrivateDeleteSelectedProfile;
        }
        internal Capture.Binding Binding { get; }
        internal DateTimeOffset ArmedAt { get; }
        internal bool StatusPrivateDeleteSelectedProfile { get; }
        internal Guid Id { get; } = Guid.NewGuid();
        internal static Window Create(Capture.Binding binding, DateTimeOffset armedAt,
            bool statusPrivateDeleteSelectedProfile = false) => new(binding, armedAt, statusPrivateDeleteSelectedProfile);
        public override string ToString() => "[ManagementResourceWindow]";
    }

    internal sealed record Policy([property: JsonIgnore] Guid TenantId,
        [property: JsonIgnore] Guid PrincipalId, [property: JsonIgnore] Guid? ApplicationId,
        [property: JsonIgnore] SecretPermission[] Permissions)
    {
        public override string ToString() => "[ManagementResourcePolicy]";
    }
    internal sealed record VaultConfiguration([property: JsonIgnore] string Location,
        [property: JsonIgnore] Guid TenantId, [property: JsonIgnore] VaultSku Sku,
        [property: JsonIgnore] bool Rbac, [property: JsonIgnore] bool PurgeProtection,
        [property: JsonIgnore] int RetentionDays, [property: JsonIgnore] bool PublicNetworkAccess,
        [property: JsonIgnore] Policy[] Policies, [property: JsonIgnore] string? CreateMode = null)
    {
        public override string ToString() => "[ManagementResourceVaultConfiguration]";
    }
    internal sealed class Attribute : IDisposable
    {
        internal required string Name { get; init; }
        internal required NotificationAttributeKind Kind { get; init; }
        internal required bool IsSecret { get; init; }
        internal required SecretMaterial Value { get; init; }
        public void Dispose() => Value.Dispose();
        public override string ToString() => "[ManagementResourceAttribute]";
    }
    internal sealed class NotificationConfiguration : IDisposable
    {
        internal required SecretMaterial Endpoint { get; init; }
        internal required IReadOnlyList<VaultNotificationEvent> Events { get; init; }
        internal required IReadOnlyList<Attribute> Attributes { get; init; }
        public void Dispose()
        {
            Endpoint.Dispose();
            foreach (var attribute in Attributes) attribute.Dispose();
        }
        public override string ToString() => "[ManagementResourceNotificationConfiguration]";
    }
    internal sealed record DeletedVault([property: JsonIgnore] string OriginalResourceId,
        [property: JsonIgnore] DateTimeOffset? DeletedOn, [property: JsonIgnore] DateTimeOffset? ScheduledPurgeOn,
        [property: JsonIgnore] bool? PurgeProtected)
    {
        public override string ToString() => "[ManagementResourceDeletedVault]";
    }
    internal sealed record RoleAssignment([property: JsonIgnore] string Scope,
        [property: JsonIgnore] string RoleDefinitionId, [property: JsonIgnore] Guid PrincipalId,
        [property: JsonIgnore] string? PrincipalType)
    {
        public override string ToString() => "[ManagementResourceRoleAssignment]";
    }
    internal sealed class Measurement : IDisposable
    {
        internal required Capture.Binding Binding { get; init; }
        internal required Guid WindowId { get; init; }
        internal required DateTimeOffset ArmedAt { get; init; }
        internal required DateTimeOffset StartedAt { get; init; }
        internal required DateTimeOffset FinishedAt { get; init; }
        internal required string Identity { get; init; }
        internal string ApiRevision => Binding.ApiRevision;
        internal required Failure Failure { get; init; }
        // Success means the selected resource exists, not that a requested
        // mutation succeeded. Unknown/unsupported configuration is ineligible.
        internal required SecretStatus ResourceStatus { get; init; }
        internal required int? HttpStatus { get; init; }
        internal required string? NativeRequestId { get; init; }
        internal required string? ResourceId { get; init; }
        internal required string? ResourceName { get; init; }
        internal required string? ResourceType { get; init; }
        internal required string? NativeState { get; init; }
        internal required string? Topic { get; init; }
        internal required IReadOnlyList<string> EventTypes { get; init; }
        internal required VaultConfiguration? VaultConfiguration { get; init; }
        internal required PrivateConnectionState? ConnectionState { get; init; }
        internal string? PrivateEndpointId { get; init; }
        internal required NotificationConfiguration? NotificationConfiguration { get; init; }
        internal required DeletedVault? DeletedVault { get; init; }
        internal required RoleAssignment? RoleAssignment { get; init; }
        internal required bool PersistedStateEligible { get; init; }
        internal bool ResponseComplete => Failure == Failure.None;
        internal bool? ResourceAbsent => ResponseComplete ? ResourceStatus == SecretStatus.Absent : null;
        internal bool AsyncSettlementProven => false;
        internal bool PrincipalQualified => false;
        internal bool EgressQualified => false;
        public void Dispose() => NotificationConfiguration?.Dispose();
        public override string ToString() => "[ManagementResourceMeasurement]";
    }

    private sealed class Registration(long timestamp)
    {
        internal long Timestamp { get; } = timestamp;
        internal bool Consumed;
        internal Task<Measurement>? Task;
        internal StatusPrivateConnectionUpdateReadProof? Proof;
        internal StatusPrivateConnectionUpdateIndependentReadProof? IndependentUpdateProof;
        internal CancellationToken[] PrivateUpdateTokens = [];
        internal StatusPrivateConnectionDeleteReadProof? DeleteProof;
        internal StatusPrivateConnectionDeleteSelectedReadProof? SelectedDeleteProof;
        internal StatusPrivateConnectionDeleteIndependentReadProof? IndependentDeleteProof;
    }

    internal enum StatusPendingPurgeReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusPendingPurgeReadProof(Window window, Capture.Binding binding,
        StatusPendingPurgeReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusPendingPurgeReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusPendingPurgeReadProof]";
    }
    private sealed class StatusPendingPurgeReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusPendingPurgeReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusPendingPurgeReadPhase.ReadyDeletedPresent or
                StatusPendingPurgeReadPhase.BaselineDeletedPresent or StatusPendingPurgeReadPhase.SelectedDeletedPresent);
        internal readonly StatusPendingPurgeReadPhase Phase = phase;
        internal StatusPendingPurgeReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusPendingPurgeReadRegistration> statusPendingReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusPendingPurgeIndependentReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusPendingPurgeIndependentReadProof(Window window, Capture.Binding binding,
        StatusPendingPurgeIndependentReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusPendingPurgeIndependentReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusPendingPurgeIndependentReadProof]";
    }
    private sealed class StatusPendingPurgeIndependentReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusPendingPurgeIndependentReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusPendingPurgeIndependentReadPhase.ReadyDeletedPresent or
                StatusPendingPurgeIndependentReadPhase.BaselineDeletedPresent or
                StatusPendingPurgeIndependentReadPhase.SelectedDeletedPresent);
        internal readonly StatusPendingPurgeIndependentReadPhase Phase = phase;
        internal StatusPendingPurgeIndependentReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusPendingPurgeIndependentReadRegistration> statusPendingIndependentReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusPendingPurgeCancellationReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusPendingPurgeCancellationReadProof(Window window, Capture.Binding binding,
        StatusPendingPurgeCancellationReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusPendingPurgeCancellationReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusPendingPurgeCancellationReadProof]";
    }
    private sealed class StatusPendingPurgeCancellationReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusPendingPurgeCancellationReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusPendingPurgeCancellationReadPhase.ReadyDeletedPresent or
                StatusPendingPurgeCancellationReadPhase.BaselineDeletedPresent or
                StatusPendingPurgeCancellationReadPhase.SelectedDeletedPresent);
        internal readonly StatusPendingPurgeCancellationReadPhase Phase = phase;
        internal StatusPendingPurgeCancellationReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusPendingPurgeCancellationReadRegistration> statusPendingCancellationReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusFailedPurgeReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, CleanupActiveAbsent, CleanupDeletedPresent,
        FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusFailedPurgeReadProof(Window window, Capture.Binding binding,
        StatusFailedPurgeReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusFailedPurgeReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusFailedPurgeReadProof]";
    }
    private sealed class StatusFailedPurgeReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusFailedPurgeReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusFailedPurgeReadPhase.ReadyDeletedPresent or
                StatusFailedPurgeReadPhase.BaselineDeletedPresent or StatusFailedPurgeReadPhase.SelectedDeletedPresent or
                StatusFailedPurgeReadPhase.CleanupDeletedPresent);
        internal readonly StatusFailedPurgeReadPhase Phase = phase;
        internal StatusFailedPurgeReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusFailedPurgeReadRegistration> statusFailedReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusFailedPurgeIndependentReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, CleanupActiveAbsent, CleanupDeletedPresent,
        FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusFailedPurgeIndependentReadProof(Window window, Capture.Binding binding,
        StatusFailedPurgeIndependentReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusFailedPurgeIndependentReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusFailedPurgeIndependentReadProof]";
    }
    private sealed class StatusFailedPurgeIndependentReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusFailedPurgeIndependentReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusFailedPurgeIndependentReadPhase.ReadyDeletedPresent or
                StatusFailedPurgeIndependentReadPhase.BaselineDeletedPresent or
                StatusFailedPurgeIndependentReadPhase.SelectedDeletedPresent or
                StatusFailedPurgeIndependentReadPhase.CleanupDeletedPresent);
        internal readonly StatusFailedPurgeIndependentReadPhase Phase = phase;
        internal StatusFailedPurgeIndependentReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusFailedPurgeIndependentReadRegistration> statusFailedIndependentReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusFailedPurgeCancellationReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, CleanupActiveAbsent, CleanupDeletedPresent,
        FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusFailedPurgeCancellationReadProof(Window window, Capture.Binding binding,
        StatusFailedPurgeCancellationReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusFailedPurgeCancellationReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusFailedPurgeCancellationReadProof]";
    }
    private sealed class StatusFailedPurgeCancellationReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusFailedPurgeCancellationReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusFailedPurgeCancellationReadPhase.ReadyDeletedPresent or
                StatusFailedPurgeCancellationReadPhase.BaselineDeletedPresent or
                StatusFailedPurgeCancellationReadPhase.SelectedDeletedPresent or
                StatusFailedPurgeCancellationReadPhase.CleanupDeletedPresent);
        internal readonly StatusFailedPurgeCancellationReadPhase Phase = phase;
        internal StatusFailedPurgeCancellationReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusFailedPurgeCancellationReadRegistration> statusFailedCancellationReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusCanceledPurgeReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, CleanupActiveAbsent, CleanupDeletedPresent,
        FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusCanceledPurgeReadProof(Window window, Capture.Binding binding,
        StatusCanceledPurgeReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusCanceledPurgeReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusCanceledPurgeReadProof]";
    }
    private sealed class StatusCanceledPurgeReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusCanceledPurgeReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusCanceledPurgeReadPhase.ReadyDeletedPresent or
                StatusCanceledPurgeReadPhase.BaselineDeletedPresent or StatusCanceledPurgeReadPhase.SelectedDeletedPresent or
                StatusCanceledPurgeReadPhase.CleanupDeletedPresent);
        internal readonly StatusCanceledPurgeReadPhase Phase = phase;
        internal StatusCanceledPurgeReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusCanceledPurgeReadRegistration> statusCanceledReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusCanceledPurgeIndependentReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, CleanupActiveAbsent, CleanupDeletedPresent,
        FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusCanceledPurgeIndependentReadProof(Window window, Capture.Binding binding,
        StatusCanceledPurgeIndependentReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusCanceledPurgeIndependentReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusCanceledPurgeIndependentReadProof]";
    }
    private sealed class StatusCanceledPurgeIndependentReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusCanceledPurgeIndependentReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusCanceledPurgeIndependentReadPhase.ReadyDeletedPresent or
                StatusCanceledPurgeIndependentReadPhase.BaselineDeletedPresent or
                StatusCanceledPurgeIndependentReadPhase.SelectedDeletedPresent or
                StatusCanceledPurgeIndependentReadPhase.CleanupDeletedPresent);
        internal readonly StatusCanceledPurgeIndependentReadPhase Phase = phase;
        internal StatusCanceledPurgeIndependentReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusCanceledPurgeIndependentReadRegistration> statusCanceledIndependentReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusCanceledPurgeCancellationReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedPresent, CleanupActiveAbsent, CleanupDeletedPresent,
        FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusCanceledPurgeCancellationReadProof(Window window, Capture.Binding binding,
        StatusCanceledPurgeCancellationReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusCanceledPurgeCancellationReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusCanceledPurgeCancellationReadProof]";
    }
    private sealed class StatusCanceledPurgeCancellationReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusCanceledPurgeCancellationReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusCanceledPurgeCancellationReadPhase.ReadyDeletedPresent or
                StatusCanceledPurgeCancellationReadPhase.BaselineDeletedPresent or
                StatusCanceledPurgeCancellationReadPhase.SelectedDeletedPresent or
                StatusCanceledPurgeCancellationReadPhase.CleanupDeletedPresent);
        internal readonly StatusCanceledPurgeCancellationReadPhase Phase = phase;
        internal StatusCanceledPurgeCancellationReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusCanceledPurgeCancellationReadRegistration> statusCanceledCancellationReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusDeniedVaultRecoverReadPhase
    {
        ReadyActive, ReadyDeletedAbsent, BaselineActiveAbsent, BaselineDeleted,
        SelectedActive, SelectedDeletedAbsent, CleanupActiveRecovered, CleanupActiveAbsent,
        CleanupDeletedPresent, CleanupDeletedAbsent, FinalActiveAbsent, FinalDeletedAbsent
    }

    internal sealed class StatusDeniedVaultRecoverReadProof(
        ManagementOperationResourceCollector source, Window window, Capture.Binding binding,
        StatusDeniedVaultRecoverReadPhase phase, VaultAdministrationEffects.Configuration expected,
        VaultConfiguration? configuration, DeletedVault? deletedVault, Task<Measurement> readTask,
        Task nativeTask, RequestFailedException? nativeError, int httpStatus, int responseBytes,
        string? originalVaultId, string? errorCode, string requestSha256, string responseSha256,
        string nativeRequestId, DateTimeOffset startedAt, DateTimeOffset finishedAt,
        CancellationToken callerToken, CancellationToken originalCallerToken)
    {
        internal ManagementOperationResourceCollector Source { get; } = source;
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusDeniedVaultRecoverReadPhase Phase { get; } = phase;
        internal VaultAdministrationEffects.Configuration ExpectedConfiguration { get; } = expected;
        internal VaultConfiguration? Configuration { get; } = configuration;
        internal DeletedVault? DeletedVault { get; } = deletedVault;
        internal Task<Measurement> ReadTask { get; } = readTask;
        internal Task NativeTask { get; } = nativeTask;
        internal RequestFailedException? NativeError { get; } = nativeError;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string? ErrorCode { get; } = errorCode;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal CancellationToken CallerToken { get; } = callerToken;
        internal CancellationToken OriginalCallerToken { get; } = originalCallerToken;
        public override string ToString() => "[StatusDeniedVaultRecoverReadProof]";
    }

    private sealed class StatusDeniedVaultRecoverReadRegistration(
        VaultAdministrationEffects.Configuration expected, StatusDeniedVaultRecoverReadPhase phase,
        ManagementScope resource)
    {
        internal readonly VaultAdministrationEffects.Configuration Expected = expected;
        internal readonly StatusDeniedVaultRecoverReadPhase Phase = phase;
        internal readonly ManagementScope Resource = resource;
        internal readonly PrivateRead Read = new();
        internal CancellationToken[] Tokens = [];
        internal StatusDeniedVaultRecoverReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusDeniedVaultRecoverReadRegistration> statusDeniedVaultRecoverReads =
        new(ReferenceEqualityComparer.Instance);

    private static bool StatusDeniedVaultRecoverBinding(Capture.Binding binding) =>
        binding.Selector is not null &&
        binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        binding.Selector.Variant == "operation.RecoverVault" &&
        binding.Selector.Case == "denied-authority" &&
        binding.Operation == ManagementMutation.RecoverVault;

    internal Window ArmStatusDeniedVaultRecover(Capture.Binding binding,
        VaultAdministrationEffects.Configuration expected, StatusDeniedVaultRecoverReadPhase phase)
    {
        Require(binding is not null && StatusDeniedVaultRecoverBinding(binding) && Enum.IsDefined(phase));
        ValidateBinding(binding, statusDeniedVaultRecoverRead: true);
        Require(expected is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            expected.TenantId == tenantId && expected.Location == binding.Location);
        _ = expected.Build();
        bool active = phase is StatusDeniedVaultRecoverReadPhase.ReadyActive or
            StatusDeniedVaultRecoverReadPhase.BaselineActiveAbsent or StatusDeniedVaultRecoverReadPhase.SelectedActive or
            StatusDeniedVaultRecoverReadPhase.CleanupActiveRecovered or StatusDeniedVaultRecoverReadPhase.CleanupActiveAbsent or
            StatusDeniedVaultRecoverReadPhase.FinalActiveAbsent;
        Require(active ? binding.Resource is VaultScope :
            binding.Resource is DeletedVaultScope deleted && deleted.Location == binding.Location);
        string name = Path(binding.Resource).Split('/')[^1];
        Require(name.Length == 24 && name.StartsWith("skv", StringComparison.Ordinal) && name[3..].All(char.IsAsciiHexDigit));
        var snapshot = expected with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusDeniedVaultRecoverReads.Add(window, new(snapshot, phase, binding.Resource));
            return window;
        }
    }

    internal bool TryGetStatusDeniedVaultRecoverRead(Window window, Capture.Binding binding,
        StatusDeniedVaultRecoverReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusDeniedVaultRecoverReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusDeniedVaultRecoverReads.TryGetValue(window, out var selected) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(selected.Resource, binding.Resource) ||
                selected.Phase != phase || !ReferenceEquals(registration.Task, task) ||
                !task.IsCompletedSuccessfully) return false;
            if (selected.Tokens.Any(t => t.IsCancellationRequested)) selected.Proof = null;
            if (selected.Proof is null) return false;
            proof = selected.Proof;
            return true;
        }
    }

    internal bool OwnsStatusDeniedVaultRecoverRead(StatusDeniedVaultRecoverReadProof proof, Window window,
        Capture.Binding binding, StatusDeniedVaultRecoverReadPhase phase, Task<Measurement> task) =>
        TryGetStatusDeniedVaultRecoverRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    private async Task<Measurement> CollectStatusDeniedVaultRecoverAsync(Window window, Capture.Binding binding,
        Registration registration, StatusDeniedVaultRecoverReadRegistration selected, Task admission)
    {
        await admission.ConfigureAwait(false);
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        budget.Check();
        var started = budget.ObservedAt;
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource([.. selected.Tokens, deadline.Token]);
        var read = selected.Read;
        Task? nativeTask = null;
        RequestFailedException? nativeError = null;
        int? status = null;
        string? requestId = null, responseHash = null, originalVaultId = null, errorCode = null;
        VaultConfiguration? configuration = null;
        DeletedVault? deletedVault = null;
        Failure failure = Failure.Unavailable;
        SecretStatus outcome = SecretStatus.Unavailable;
        bool valid = false;
        try
        {
            linked.Token.ThrowIfCancellationRequested();
            Require(ReferenceEquals(binding.Resource, selected.Resource));
            var uri = new Uri(ArmOrigin + Path(selected.Resource) + "?api-version=" + binding.ApiRevision);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(ArmOrigin), ArmOrigin),
                Transport = new ReadTransport(authority.Transport, uri, budget, read, limits.MaximumResponseBytes,
                    requireErrorRebuffer: true)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion(Type(selected.Resource), binding.ApiRevision);
            if (selected.Resource is DeletedVaultScope)
                options.SetApiVersion("Microsoft.KeyVault/deletedVaults", binding.ApiRevision);
            var client = new ArmClient(new ObserverCredential(authority.Credential, budget), null, options);
            Response<KeyVaultResource>? activeResponse = null;
            Response<DeletedKeyVaultResource>? deletedResponse = null;
            try
            {
                if (selected.Resource is VaultScope vault)
                {
                    var actual = client.GetKeyVaultResource(new(vault.ExportResourceId())).GetAsync(linked.Token);
                    nativeTask = actual;
                    activeResponse = await actual.ConfigureAwait(false);
                }
                else
                {
                    var actual = client.GetDeletedKeyVaultResource(new(Path(selected.Resource))).GetAsync(linked.Token);
                    nativeTask = actual;
                    deletedResponse = await actual.ConfigureAwait(false);
                }
            }
            catch (RequestFailedException exception) { nativeError = exception; }
            if (read.Send is not null) await read.Send.ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            Require(nativeTask is not null && read.Body is not null && read.Parser is { Complete: true, Invalid: false });
            status = read.Body.Response.Status;
            requestId = read.Body.NativeRequestId;
            responseHash = read.Body.Sha256;
            long? length = ResponseHeaders(read.Body.Response, out var headerRequestId);
            Require(requestId == headerRequestId && (length is null || length == read.Body.Bytes.Length) &&
                read.Body.Bytes.Length <= limits.MaximumRowBytes);
            Shape(read.Body.Bytes.Span);
            using var json = JsonDocument.Parse(read.Body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            bool activePresent = selected.Phase is StatusDeniedVaultRecoverReadPhase.ReadyActive or
                StatusDeniedVaultRecoverReadPhase.SelectedActive or StatusDeniedVaultRecoverReadPhase.CleanupActiveRecovered;
            bool deletedPresent = selected.Phase is StatusDeniedVaultRecoverReadPhase.BaselineDeleted or
                StatusDeniedVaultRecoverReadPhase.CleanupDeletedPresent;
            Require(status == (activePresent || deletedPresent ? 200 : 404));
            if (activePresent)
            {
                Require(selected.Resource is VaultScope && activeResponse is not null && deletedResponse is null &&
                    nativeError is null && nativeTask.IsCompletedSuccessfully && read.Parser.Owns(activeResponse.GetRawResponse()));
                originalVaultId = Path(selected.Resource);
                ValidateStatusSucceededActive(json.RootElement, activeResponse.Value.Data, originalVaultId,
                    binding.Selector.Nonce, selected.Expected, recover: true);
                var p = Object(json.RootElement, "properties");
                Require(OptionalText(p, "createMode") is null or "default" or "recover");
                configuration = new(Text(json.RootElement, "location"), Guid.Parse(Text(p, "tenantId")),
                    activeResponse.Value.Data.Properties.Sku.Name == Azure.ResourceManager.KeyVault.Models.KeyVaultSkuName.Standard
                        ? VaultSku.Standard : VaultSku.Premium,
                    p.GetProperty("enableRbacAuthorization").GetBoolean(), p.GetProperty("enablePurgeProtection").GetBoolean(),
                    p.GetProperty("softDeleteRetentionInDays").GetInt32(), Text(p, "publicNetworkAccess") == "Enabled",
                    [], OptionalText(p, "createMode"));
                outcome = SecretStatus.Success;
            }
            else if (deletedPresent)
            {
                Require(selected.Resource is DeletedVaultScope && deletedResponse is not null && activeResponse is null &&
                    nativeError is null && nativeTask.IsCompletedSuccessfully && read.Parser.Owns(deletedResponse.GetRawResponse()));
                originalVaultId = Text(Object(json.RootElement, "properties"), "vaultId");
                var coordinate = (DeletedVaultScope)selected.Resource;
                string[] parts = originalVaultId.Split('/');
                Require(parts.Length == 9 && parts[1] == "subscriptions" &&
                    parts[2] == coordinate.Subscription.SubscriptionId.ToString("D") &&
                    parts[3] == "resourceGroups" && Segment(parts[4], 90) && parts[5] == "providers" &&
                    parts[6] == "Microsoft.KeyVault" && parts[7] == "vaults" && parts[8] == coordinate.VaultName);
                ValidateStatusSucceededDeleted(json.RootElement, deletedResponse.Value.Data, Path(selected.Resource),
                    originalVaultId, binding.Selector.Nonce, selected.Expected);
                var p = deletedResponse.Value.Data.Properties;
                deletedVault = new(originalVaultId, p.DeletedOn, p.ScheduledPurgeOn, p.PurgeProtectionEnabled);
                outcome = SecretStatus.Success;
            }
            else
            {
                Require(nativeError is { Status: 404 } && nativeTask.IsFaulted &&
                    activeResponse is null && deletedResponse is null &&
                    Only(json.RootElement, "error") && json.RootElement.EnumerateObject().Count() == 1);
                var error = Object(json.RootElement, "error");
                errorCode = Text(error, "code");
                Require(Only(error, "code", "message") &&
                    errorCode is "NotFound" or "ResourceNotFound" or "VaultNotFound" &&
                    nativeError.ErrorCode == errorCode);
                if (error.TryGetProperty("message", out var message))
                    Require(message.ValueKind == JsonValueKind.String && message.GetString()!.Length <= 4096 &&
                        !message.GetString()!.Any(char.IsControl));
                outcome = SecretStatus.Absent;
            }
            valid = true;
        }
        catch (Exception exception)
        {
            failure = deadline.IsCancellationRequested ? Failure.Deadline :
                exception is Boundary boundary ? boundary.Reason : Failure.Unavailable;
        }
        finally
        {
            if (nativeTask is not null) try { await nativeTask.ConfigureAwait(false); } catch (Exception) { }
            if (read.Send is not null) try { await read.Send.ConfigureAwait(false); } catch (Exception) { }
            try { read.Storage.Dispose(); }
            catch (Exception) { valid = false; failure = Failure.Unavailable; }
        }
        lock (gate)
        {
            if (selected.Tokens.Any(t => t.IsCancellationRequested))
                throw new OperationCanceledException(selected.Tokens.First(t => t.IsCancellationRequested));
            try
            {
                budget.Check();
                linked.Token.ThrowIfCancellationRequested();
                Require(valid && read.Parser is { Complete: true, Invalid: false } && nativeTask is { IsCompleted: true } &&
                    read.Send is { IsCompletedSuccessfully: true } && ReferenceEquals(binding.Resource, selected.Resource) &&
                    ReferenceEquals(statusDeniedVaultRecoverReads[window], selected) && selected.Proof is null &&
                    registration.Task is not null && read.RequestSha256 is not null && read.Body is not null &&
                    responseHash is not null && requestId is not null && started >= window.ArmedAt && budget.ObservedAt >= started);
                selected.Proof = new(this, window, binding, selected.Phase, selected.Expected, configuration, deletedVault,
                    registration.Task, nativeTask, nativeError, status!.Value, read.Body.Bytes.Length, originalVaultId, errorCode,
                    read.RequestSha256, responseHash, requestId, started, budget.ObservedAt, selected.Tokens[0], selected.Tokens[1]);
                failure = Failure.None;
            }
            catch (Exception exception)
            {
                failure = deadline.IsCancellationRequested ? Failure.Deadline :
                    exception is Boundary boundary ? boundary.Reason : Failure.Unavailable;
                outcome = SecretStatus.Unavailable;
            }
        }
        bool exists = failure == Failure.None && outcome == SecretStatus.Success;
        return new()
        {
            Binding = binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = budget.ObservedAt,
            Identity = authority.Label,
            Failure = failure,
            ResourceStatus = failure == Failure.None ? outcome : SecretStatus.Unavailable,
            HttpStatus = status ?? read.ObservedStatus,
            NativeRequestId = requestId,
            ResourceId = exists ? Path(selected.Resource) : null,
            ResourceName = exists ? Path(selected.Resource).Split('/')[^1] : null,
            ResourceType = exists ? Type(selected.Resource) : null,
            NativeState = exists && configuration is not null ? "Succeeded" : null,
            Topic = null,
            EventTypes = [],
            VaultConfiguration = exists ? configuration : null,
            ConnectionState = null,
            NotificationConfiguration = null,
            DeletedVault = exists ? deletedVault : null,
            RoleAssignment = null,
            PersistedStateEligible = exists
        };
    }

    internal enum StatusDeniedVaultUpdateReadPhase
    {
        ReadyActive, ReadyDeletedAbsent, BaselineActive, BaselineDeletedAbsent,
        SelectedActive, SelectedDeletedAbsent, CleanupActive, CleanupDeletedAbsent,
        FinalActiveAbsent, FinalDeletedAbsent
    }

    internal sealed class StatusDeniedVaultUpdateReadProof(
        ManagementOperationResourceCollector source, Window window, Capture.Binding binding,
        StatusDeniedVaultUpdateReadPhase phase, VaultAdministrationEffects.Configuration expected,
        VaultConfiguration? configuration, Task<Measurement> readTask, Task nativeTask,
        RequestFailedException? nativeError, int httpStatus, string? originalVaultId,
        string? errorCode, string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt,
        CancellationToken callerToken, CancellationToken originalCallerToken)
    {
        internal ManagementOperationResourceCollector Source { get; } = source;
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusDeniedVaultUpdateReadPhase Phase { get; } = phase;
        internal VaultAdministrationEffects.Configuration ExpectedConfiguration { get; } = expected;
        internal VaultConfiguration? Configuration { get; } = configuration;
        internal Task<Measurement> ReadTask { get; } = readTask;
        internal Task NativeTask { get; } = nativeTask;
        internal RequestFailedException? NativeError { get; } = nativeError;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string? ErrorCode { get; } = errorCode;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal CancellationToken CallerToken { get; } = callerToken;
        internal CancellationToken OriginalCallerToken { get; } = originalCallerToken;
        public override string ToString() => "[StatusDeniedVaultUpdateReadProof]";
    }

    private sealed class StatusDeniedVaultUpdateReadRegistration(
        VaultAdministrationEffects.Configuration expected, StatusDeniedVaultUpdateReadPhase phase)
    {
        internal readonly VaultAdministrationEffects.Configuration Expected = expected;
        internal readonly StatusDeniedVaultUpdateReadPhase Phase = phase;
        internal CancellationToken[] Tokens = [];
        internal StatusDeniedVaultUpdateReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusDeniedVaultUpdateReadRegistration> statusDeniedVaultUpdateReads =
        new(ReferenceEqualityComparer.Instance);

    private static bool StatusDeniedVaultUpdateBinding(Capture.Binding binding) =>
        binding.Selector is not null &&
        binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        binding.Selector.Variant == "operation.CreateOrUpdateVault" &&
        binding.Selector.Case == "denied-authority" &&
        binding.Operation == ManagementMutation.CreateOrUpdateVault;

    internal Window ArmStatusDeniedVaultUpdate(Capture.Binding binding,
        VaultAdministrationEffects.Configuration expected, StatusDeniedVaultUpdateReadPhase phase)
    {
        Require(binding is not null && StatusDeniedVaultUpdateBinding(binding) && Enum.IsDefined(phase));
        // Deleted counterpart admission is local to this enrollment, not a
        // broader generic CreateOrUpdateVault read contract.
        ValidateBinding(binding, statusDeniedVaultUpdateRead: true);
        Require(expected is { Rbac: true, PurgeProtection: false, Policies.Length: 0 } &&
            expected.TenantId == tenantId && expected.Location == binding.Location);
        _ = expected.Build();
        bool active = phase is StatusDeniedVaultUpdateReadPhase.ReadyActive or
            StatusDeniedVaultUpdateReadPhase.BaselineActive or StatusDeniedVaultUpdateReadPhase.SelectedActive or
            StatusDeniedVaultUpdateReadPhase.CleanupActive or StatusDeniedVaultUpdateReadPhase.FinalActiveAbsent;
        Require(active ? binding.Resource is VaultScope :
            binding.Resource is DeletedVaultScope deleted && deleted.Location == binding.Location);
        Require(phase switch
        {
            StatusDeniedVaultUpdateReadPhase.ReadyActive or StatusDeniedVaultUpdateReadPhase.ReadyDeletedAbsent or
                StatusDeniedVaultUpdateReadPhase.BaselineActive or StatusDeniedVaultUpdateReadPhase.BaselineDeletedAbsent =>
                !expected.PublicNetworkAccess,
            StatusDeniedVaultUpdateReadPhase.SelectedActive or StatusDeniedVaultUpdateReadPhase.SelectedDeletedAbsent =>
                expected.PublicNetworkAccess,
            _ => true
        });
        string name = Path(binding.Resource).Split('/')[^1];
        Require(name.Length == 24 && name.StartsWith("skv", StringComparison.Ordinal) && name[3..].All(char.IsAsciiHexDigit));
        var snapshot = expected with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusDeniedVaultUpdateReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal bool TryGetStatusDeniedVaultUpdateRead(Window window, Capture.Binding binding,
        StatusDeniedVaultUpdateReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusDeniedVaultUpdateReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusDeniedVaultUpdateReads.TryGetValue(window, out var selected) ||
                !ReferenceEquals(window.Binding, binding) || selected.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (selected.Tokens.Any(t => t.IsCancellationRequested)) selected.Proof = null;
            if (selected.Proof is null) return false;
            proof = selected.Proof;
            return true;
        }
    }

    internal bool OwnsStatusDeniedVaultUpdateRead(StatusDeniedVaultUpdateReadProof proof, Window window,
        Capture.Binding binding, StatusDeniedVaultUpdateReadPhase phase, Task<Measurement> task) =>
        TryGetStatusDeniedVaultUpdateRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    private async Task<Measurement> CollectStatusDeniedVaultUpdateAsync(Window window, Capture.Binding binding,
        Registration registration, StatusDeniedVaultUpdateReadRegistration selected, Task admission)
    {
        await admission.ConfigureAwait(false);
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        budget.Check();
        var started = budget.ObservedAt;
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource([.. selected.Tokens, deadline.Token]);
        var read = new PrivateRead();
        Task? nativeTask = null;
        RequestFailedException? nativeError = null;
        int? status = null;
        string? requestId = null, responseHash = null, originalVaultId = null, errorCode = null;
        VaultConfiguration? configuration = null;
        Failure failure = Failure.Unavailable;
        SecretStatus outcome = SecretStatus.Unavailable;
        bool valid = false;
        try
        {
            linked.Token.ThrowIfCancellationRequested();
            var uri = new Uri(ArmOrigin + Path(binding.Resource) + "?api-version=" + binding.ApiRevision);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(ArmOrigin), ArmOrigin),
                Transport = new ReadTransport(authority.Transport, uri, budget, read, limits.MaximumResponseBytes,
                    requireErrorRebuffer: true)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion(Type(binding.Resource), binding.ApiRevision);
            if (binding.Resource is DeletedVaultScope)
                options.SetApiVersion("Microsoft.KeyVault/deletedVaults", binding.ApiRevision);
            var client = new ArmClient(new ObserverCredential(authority.Credential, budget), null, options);
            Response<KeyVaultResource>? activeResponse = null;
            Response<DeletedKeyVaultResource>? deletedResponse = null;
            try
            {
                if (binding.Resource is VaultScope vault)
                {
                    var actual = client.GetKeyVaultResource(new(vault.ExportResourceId())).GetAsync(linked.Token);
                    nativeTask = actual;
                    activeResponse = await actual.ConfigureAwait(false);
                }
                else
                {
                    var actual = client.GetDeletedKeyVaultResource(new(Path(binding.Resource))).GetAsync(linked.Token);
                    nativeTask = actual;
                    deletedResponse = await actual.ConfigureAwait(false);
                }
            }
            catch (RequestFailedException exception) { nativeError = exception; }
            if (read.Send is not null) await read.Send.ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            Require(nativeTask is not null && read.Body is not null && read.Parser is { Complete: true, Invalid: false });
            status = read.Body.Response.Status;
            requestId = read.Body.NativeRequestId;
            responseHash = read.Body.Sha256;
            long? length = ResponseHeaders(read.Body.Response, out var headerRequestId);
            Require(requestId == headerRequestId && (length is null || length == read.Body.Bytes.Length) &&
                read.Body.Bytes.Length <= limits.MaximumRowBytes);
            Shape(read.Body.Bytes.Span);
            using var json = JsonDocument.Parse(read.Body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            bool present = selected.Phase is StatusDeniedVaultUpdateReadPhase.ReadyActive or
                StatusDeniedVaultUpdateReadPhase.BaselineActive or StatusDeniedVaultUpdateReadPhase.SelectedActive or
                StatusDeniedVaultUpdateReadPhase.CleanupActive;
            Require(status == (present ? 200 : 404));
            if (present)
            {
                Require(binding.Resource is VaultScope && activeResponse is not null && deletedResponse is null &&
                    nativeError is null && nativeTask.IsCompletedSuccessfully && read.Parser.Owns(activeResponse.GetRawResponse()));
                originalVaultId = Path(binding.Resource);
                // This validator requires every raw configuration field, both
                // empty arrays and ownership, then joins the installed model.
                ValidateStatusSucceededActive(json.RootElement, activeResponse.Value.Data, originalVaultId,
                    binding.Selector.Nonce, selected.Expected);
                var properties = Object(json.RootElement, "properties");
                Require(OptionalText(properties, "createMode") is null or "default");
                configuration = new(selected.Expected.Location, selected.Expected.TenantId, selected.Expected.Sku,
                    selected.Expected.Rbac, selected.Expected.PurgeProtection, selected.Expected.RetentionDays,
                    selected.Expected.PublicNetworkAccess, [], OptionalText(properties, "createMode"));
                outcome = SecretStatus.Success;
            }
            else
            {
                Require(nativeError is { Status: 404 } && nativeTask.IsFaulted &&
                    activeResponse is null && deletedResponse is null &&
                    Only(json.RootElement, "error") && json.RootElement.EnumerateObject().Count() == 1);
                var error = Object(json.RootElement, "error");
                errorCode = Text(error, "code");
                Require(Only(error, "code", "message") &&
                    errorCode is "NotFound" or "ResourceNotFound" or "VaultNotFound" &&
                    nativeError.ErrorCode == errorCode);
                if (error.TryGetProperty("message", out var message))
                    Require(message.ValueKind == JsonValueKind.String && message.GetString()!.Length <= 4096 &&
                        !message.GetString()!.Any(char.IsControl));
                outcome = SecretStatus.Absent;
            }
            valid = true;
        }
        catch (Exception exception)
        {
            failure = deadline.IsCancellationRequested ? Failure.Deadline :
                exception is Boundary boundary ? boundary.Reason : Failure.Unavailable;
        }
        finally
        {
            // No proof until real credential/send/native/parser/storage owners
            // have ended. Cancellation cannot detach a borrower or fake drain.
            if (nativeTask is not null) try { await nativeTask.ConfigureAwait(false); } catch (Exception) { }
            if (read.Send is not null) try { await read.Send.ConfigureAwait(false); } catch (Exception) { }
            try { read.Storage.Dispose(); }
            catch (Exception) { valid = false; failure = Failure.Unavailable; }
        }
        lock (gate)
        {
            if (selected.Tokens.Any(t => t.IsCancellationRequested))
                throw new OperationCanceledException(selected.Tokens.First(t => t.IsCancellationRequested));
            try
            {
                budget.Check();
                linked.Token.ThrowIfCancellationRequested();
                Require(valid && read.Parser is { Complete: true, Invalid: false } && nativeTask is { IsCompleted: true } &&
                    read.Send is { IsCompletedSuccessfully: true } &&
                    ReferenceEquals(statusDeniedVaultUpdateReads[window], selected) && selected.Proof is null &&
                    registration.Task is not null && read.RequestSha256 is not null &&
                    responseHash is not null && requestId is not null);
                selected.Proof = new(this, window, binding, selected.Phase, selected.Expected, configuration,
                    registration.Task, nativeTask, nativeError, status!.Value, originalVaultId, errorCode,
                    read.RequestSha256, responseHash, requestId, started, budget.ObservedAt,
                    selected.Tokens[0], selected.Tokens[1]);
                failure = Failure.None;
            }
            catch (Exception exception)
            {
                failure = deadline.IsCancellationRequested ? Failure.Deadline :
                    exception is Boundary boundary ? boundary.Reason : Failure.Unavailable;
                outcome = SecretStatus.Unavailable;
            }
        }
        bool exists = failure == Failure.None && outcome == SecretStatus.Success;
        return new()
        {
            Binding = binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = budget.ObservedAt,
            Identity = authority.Label,
            Failure = failure,
            ResourceStatus = failure == Failure.None ? outcome : SecretStatus.Unavailable,
            HttpStatus = status ?? read.ObservedStatus,
            NativeRequestId = requestId,
            ResourceId = exists ? originalVaultId : null,
            ResourceName = exists ? Path(binding.Resource).Split('/')[^1] : null,
            ResourceType = exists ? Type(binding.Resource) : null,
            NativeState = exists ? "Succeeded" : null,
            Topic = null,
            EventTypes = [],
            VaultConfiguration = exists ? configuration : null,
            ConnectionState = null,
            NotificationConfiguration = null,
            DeletedVault = null,
            RoleAssignment = null,
            PersistedStateEligible = exists
        };
    }

    internal enum StatusDeniedPurgeReadPhase
    {
        ReadyActiveAbsent, ReadyDeletedPresent, BaselineActiveAbsent, BaselineDeletedPresent,
        SelectedActiveAbsent, SelectedDeletedAbsent, FinalActiveAbsent, FinalDeletedAbsent
    }
    internal sealed class StatusDeniedPurgeReadProof(Window window, Capture.Binding binding,
        StatusDeniedPurgeReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusDeniedPurgeReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusDeniedPurgeReadProof]";
    }
    private sealed class StatusDeniedPurgeReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusDeniedPurgeReadPhase phase)
    {
        internal readonly PurgeReadRun Run = new(baseline,
            phase is StatusDeniedPurgeReadPhase.ReadyDeletedPresent or
                StatusDeniedPurgeReadPhase.BaselineDeletedPresent);
        internal readonly StatusDeniedPurgeReadPhase Phase = phase;
        internal StatusDeniedPurgeReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusDeniedPurgeReadRegistration> statusDeniedReads =
        new(ReferenceEqualityComparer.Instance);

    internal Window ArmStatusDeniedPurge(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusDeniedPurgeReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant is "operation.PurgeDeletedVault" or "status.Succeeded" or
                "status.Pending" or "status.Failed" or "status.Canceled" or "status.Unknown" &&
            binding.Selector.Case == "denied-authority" && Enum.IsDefined(phase));
        bool active = phase is StatusDeniedPurgeReadPhase.ReadyActiveAbsent or
            StatusDeniedPurgeReadPhase.BaselineActiveAbsent or StatusDeniedPurgeReadPhase.SelectedActiveAbsent or
            StatusDeniedPurgeReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusDeniedReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal bool TryGetStatusDeniedPurgeRead(Window window, Capture.Binding binding,
        StatusDeniedPurgeReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusDeniedPurgeReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusDeniedReads.TryGetValue(window, out var denied) ||
                !ReferenceEquals(window.Binding, binding) || denied.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (denied.Run.Tokens.Any(t => t.IsCancellationRequested)) denied.Proof = null;
            if (denied.Proof is null) return false;
            proof = denied.Proof;
            return true;
        }
    }

    internal bool OwnsStatusDeniedPurgeRead(StatusDeniedPurgeReadProof proof, Window window,
        Capture.Binding binding, StatusDeniedPurgeReadPhase phase, Task<Measurement> task) =>
        TryGetStatusDeniedPurgeRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    // Shared native read state contains no profile proof authority. Only the
    // distinct reference registries can publish their corresponding proof.
    private sealed class PurgeReadRun(VaultAdministrationEffects.Configuration baseline, bool present)
    {
        internal readonly VaultAdministrationEffects.Configuration Baseline = baseline;
        internal readonly bool Present = present;
        internal CancellationToken[] Tokens = [];
    }

    internal Window ArmStatusPendingPurge(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusPendingPurgeReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Pending" && binding.Selector.Case == "selected-contract" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusPendingPurgeReadPhase.ReadyActiveAbsent or
            StatusPendingPurgeReadPhase.BaselineActiveAbsent or StatusPendingPurgeReadPhase.SelectedActiveAbsent or
            StatusPendingPurgeReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusPendingReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal Window ArmStatusPendingPurgeIndependent(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusPendingPurgeIndependentReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Pending" && binding.Selector.Case == "independent-effect" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusPendingPurgeIndependentReadPhase.ReadyActiveAbsent or
            StatusPendingPurgeIndependentReadPhase.BaselineActiveAbsent or StatusPendingPurgeIndependentReadPhase.SelectedActiveAbsent or
            StatusPendingPurgeIndependentReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusPendingIndependentReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal Window ArmStatusPendingPurgeCancellation(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusPendingPurgeCancellationReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Pending" && binding.Selector.Case == "cancellation-boundary" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusPendingPurgeCancellationReadPhase.ReadyActiveAbsent or
            StatusPendingPurgeCancellationReadPhase.BaselineActiveAbsent or StatusPendingPurgeCancellationReadPhase.SelectedActiveAbsent or
            StatusPendingPurgeCancellationReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusPendingCancellationReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal Window ArmStatusFailedPurge(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusFailedPurgeReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Failed" && binding.Selector.Case == "selected-contract" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusFailedPurgeReadPhase.ReadyActiveAbsent or
            StatusFailedPurgeReadPhase.BaselineActiveAbsent or StatusFailedPurgeReadPhase.SelectedActiveAbsent or
            StatusFailedPurgeReadPhase.CleanupActiveAbsent or StatusFailedPurgeReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusFailedReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal Window ArmStatusFailedPurgeIndependent(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusFailedPurgeIndependentReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Failed" && binding.Selector.Case == "independent-effect" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusFailedPurgeIndependentReadPhase.ReadyActiveAbsent or
            StatusFailedPurgeIndependentReadPhase.BaselineActiveAbsent or StatusFailedPurgeIndependentReadPhase.SelectedActiveAbsent or
            StatusFailedPurgeIndependentReadPhase.CleanupActiveAbsent or StatusFailedPurgeIndependentReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusFailedIndependentReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal Window ArmStatusFailedPurgeCancellation(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusFailedPurgeCancellationReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Failed" && binding.Selector.Case == "cancellation-boundary" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusFailedPurgeCancellationReadPhase.ReadyActiveAbsent or
            StatusFailedPurgeCancellationReadPhase.BaselineActiveAbsent or StatusFailedPurgeCancellationReadPhase.SelectedActiveAbsent or
            StatusFailedPurgeCancellationReadPhase.CleanupActiveAbsent or StatusFailedPurgeCancellationReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusFailedCancellationReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal Window ArmStatusCanceledPurge(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusCanceledPurgeReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Canceled" && binding.Selector.Case == "selected-contract" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusCanceledPurgeReadPhase.ReadyActiveAbsent or
            StatusCanceledPurgeReadPhase.BaselineActiveAbsent or StatusCanceledPurgeReadPhase.SelectedActiveAbsent or
            StatusCanceledPurgeReadPhase.CleanupActiveAbsent or StatusCanceledPurgeReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusCanceledReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal Window ArmStatusCanceledPurgeIndependent(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusCanceledPurgeIndependentReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Canceled" && binding.Selector.Case == "independent-effect" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusCanceledPurgeIndependentReadPhase.ReadyActiveAbsent or
            StatusCanceledPurgeIndependentReadPhase.BaselineActiveAbsent or StatusCanceledPurgeIndependentReadPhase.SelectedActiveAbsent or
            StatusCanceledPurgeIndependentReadPhase.CleanupActiveAbsent or StatusCanceledPurgeIndependentReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusCanceledIndependentReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal Window ArmStatusCanceledPurgeCancellation(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusCanceledPurgeCancellationReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "status.Canceled" && binding.Selector.Case == "cancellation-boundary" &&
            Enum.IsDefined(phase));
        bool active = phase is StatusCanceledPurgeCancellationReadPhase.ReadyActiveAbsent or
            StatusCanceledPurgeCancellationReadPhase.BaselineActiveAbsent or StatusCanceledPurgeCancellationReadPhase.SelectedActiveAbsent or
            StatusCanceledPurgeCancellationReadPhase.CleanupActiveAbsent or StatusCanceledPurgeCancellationReadPhase.FinalActiveAbsent;
        ValidatePurgeReadBinding(binding, baseline, active);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            var window = ArmPurgeReadWindow(binding, armed, stamp);
            statusCanceledCancellationReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    private void ValidatePurgeReadBinding(Capture.Binding binding,
        VaultAdministrationEffects.Configuration baseline, bool active)
    {
        Require(binding.Operation == ManagementMutation.PurgeDeletedVault && binding.ApiRevision == "2026-02-01" &&
            binding.LeaseId != Guid.Empty && binding.Selector.Nonce != Guid.Empty &&
            new[] { binding.Selector.Operation, binding.Selector.Scope, binding.Selector.Variant, binding.Selector.Case }
                .All(s => TextValue(s, 512)) && Segment(binding.Location, 50) &&
            baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true } &&
            baseline.Policies is { Length: 0 } && baseline.TenantId == tenantId && baseline.Location == binding.Location);
        _ = baseline.Build();
        Require(active ? binding.Resource is VaultScope :
            binding.Resource is DeletedVaultScope d && d.Location == binding.Location);
        string name = Path(binding.Resource).Split('/')[^1];
        Require(name.Length == 24 && name.StartsWith("skv", StringComparison.Ordinal) && name[3..].All(char.IsAsciiHexDigit));
    }

    private Window ArmPurgeReadWindow(Capture.Binding binding, DateTimeOffset armed, long stamp)
    {
        // Called under gate. Each phase has its own collector, not a rearmed
        // generic window; the caller registers its own exact profile.
        Require(windows.Count == 0 && !nonces.Contains(binding.Selector.Nonce) && !leases.Contains(binding.LeaseId));
        var window = Window.Create(binding, armed);
        windows.Add(window, new(stamp));
        nonces.Add(binding.Selector.Nonce);
        leases.Add(binding.LeaseId);
        return window;
    }

    internal bool TryGetStatusPendingPurgeRead(Window window, Capture.Binding binding, StatusPendingPurgeReadPhase phase,
        Task<Measurement> task, [NotNullWhen(true)] out StatusPendingPurgeReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusPendingReads.TryGetValue(window, out var selected) ||
                !ReferenceEquals(window.Binding, binding) || selected.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (selected.Run.Tokens.Any(t => t.IsCancellationRequested)) selected.Proof = null;
            if (selected.Proof is null) return false;
            proof = selected.Proof;
            return true;
        }
    }

    internal bool OwnsStatusPendingPurgeRead(StatusPendingPurgeReadProof proof, Window window, Capture.Binding binding,
        StatusPendingPurgeReadPhase phase, Task<Measurement> task) =>
        TryGetStatusPendingPurgeRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    internal bool TryGetStatusPendingPurgeIndependentRead(Window window, Capture.Binding binding,
        StatusPendingPurgeIndependentReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusPendingPurgeIndependentReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusPendingIndependentReads.TryGetValue(window, out var independent) ||
                !ReferenceEquals(window.Binding, binding) || independent.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (independent.Run.Tokens.Any(t => t.IsCancellationRequested)) independent.Proof = null;
            if (independent.Proof is null) return false;
            proof = independent.Proof;
            return true;
        }
    }

    internal bool OwnsStatusPendingPurgeIndependentRead(StatusPendingPurgeIndependentReadProof proof, Window window,
        Capture.Binding binding, StatusPendingPurgeIndependentReadPhase phase, Task<Measurement> task) =>
        TryGetStatusPendingPurgeIndependentRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    internal bool TryGetStatusPendingPurgeCancellationRead(Window window, Capture.Binding binding,
        StatusPendingPurgeCancellationReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusPendingPurgeCancellationReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusPendingCancellationReads.TryGetValue(window, out var cancellation) ||
                !ReferenceEquals(window.Binding, binding) || cancellation.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (cancellation.Run.Tokens.Any(t => t.IsCancellationRequested)) cancellation.Proof = null;
            if (cancellation.Proof is null) return false;
            proof = cancellation.Proof;
            return true;
        }
    }

    internal bool OwnsStatusPendingPurgeCancellationRead(StatusPendingPurgeCancellationReadProof proof, Window window,
        Capture.Binding binding, StatusPendingPurgeCancellationReadPhase phase, Task<Measurement> task) =>
        TryGetStatusPendingPurgeCancellationRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    internal bool TryGetStatusFailedPurgeRead(Window window, Capture.Binding binding,
        StatusFailedPurgeReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusFailedPurgeReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusFailedReads.TryGetValue(window, out var failed) ||
                !ReferenceEquals(window.Binding, binding) || failed.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (failed.Run.Tokens.Any(t => t.IsCancellationRequested)) failed.Proof = null;
            if (failed.Proof is null) return false;
            proof = failed.Proof;
            return true;
        }
    }

    internal bool OwnsStatusFailedPurgeRead(StatusFailedPurgeReadProof proof, Window window,
        Capture.Binding binding, StatusFailedPurgeReadPhase phase, Task<Measurement> task) =>
        TryGetStatusFailedPurgeRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    internal bool TryGetStatusFailedPurgeIndependentRead(Window window, Capture.Binding binding,
        StatusFailedPurgeIndependentReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusFailedPurgeIndependentReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusFailedIndependentReads.TryGetValue(window, out var independent) ||
                !ReferenceEquals(window.Binding, binding) || independent.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (independent.Run.Tokens.Any(t => t.IsCancellationRequested)) independent.Proof = null;
            if (independent.Proof is null) return false;
            proof = independent.Proof;
            return true;
        }
    }

    internal bool OwnsStatusFailedPurgeIndependentRead(StatusFailedPurgeIndependentReadProof proof, Window window,
        Capture.Binding binding, StatusFailedPurgeIndependentReadPhase phase, Task<Measurement> task) =>
        TryGetStatusFailedPurgeIndependentRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    internal bool TryGetStatusFailedPurgeCancellationRead(Window window, Capture.Binding binding,
        StatusFailedPurgeCancellationReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusFailedPurgeCancellationReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusFailedCancellationReads.TryGetValue(window, out var cancellation) ||
                !ReferenceEquals(window.Binding, binding) || cancellation.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (cancellation.Run.Tokens.Any(t => t.IsCancellationRequested)) cancellation.Proof = null;
            if (cancellation.Proof is null) return false;
            proof = cancellation.Proof;
            return true;
        }
    }

    internal bool OwnsStatusFailedPurgeCancellationRead(StatusFailedPurgeCancellationReadProof proof, Window window,
        Capture.Binding binding, StatusFailedPurgeCancellationReadPhase phase, Task<Measurement> task) =>
        TryGetStatusFailedPurgeCancellationRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    internal bool TryGetStatusCanceledPurgeRead(Window window, Capture.Binding binding,
        StatusCanceledPurgeReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusCanceledPurgeReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusCanceledReads.TryGetValue(window, out var canceled) ||
                !ReferenceEquals(window.Binding, binding) || canceled.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (canceled.Run.Tokens.Any(t => t.IsCancellationRequested)) canceled.Proof = null;
            if (canceled.Proof is null) return false;
            proof = canceled.Proof;
            return true;
        }
    }

    internal bool OwnsStatusCanceledPurgeRead(StatusCanceledPurgeReadProof proof, Window window,
        Capture.Binding binding, StatusCanceledPurgeReadPhase phase, Task<Measurement> task) =>
        TryGetStatusCanceledPurgeRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    internal bool TryGetStatusCanceledPurgeIndependentRead(Window window, Capture.Binding binding,
        StatusCanceledPurgeIndependentReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusCanceledPurgeIndependentReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusCanceledIndependentReads.TryGetValue(window, out var independent) ||
                !ReferenceEquals(window.Binding, binding) || independent.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (independent.Run.Tokens.Any(t => t.IsCancellationRequested)) independent.Proof = null;
            if (independent.Proof is null) return false;
            proof = independent.Proof;
            return true;
        }
    }

    internal bool OwnsStatusCanceledPurgeIndependentRead(StatusCanceledPurgeIndependentReadProof proof, Window window,
        Capture.Binding binding, StatusCanceledPurgeIndependentReadPhase phase, Task<Measurement> task) =>
        TryGetStatusCanceledPurgeIndependentRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    internal bool TryGetStatusCanceledPurgeCancellationRead(Window window, Capture.Binding binding,
        StatusCanceledPurgeCancellationReadPhase phase, Task<Measurement> task,
        [NotNullWhen(true)] out StatusCanceledPurgeCancellationReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var registration) ||
                !statusCanceledCancellationReads.TryGetValue(window, out var cancellation) ||
                !ReferenceEquals(window.Binding, binding) || cancellation.Phase != phase ||
                !ReferenceEquals(registration.Task, task) || !task.IsCompletedSuccessfully) return false;
            if (cancellation.Run.Tokens.Any(t => t.IsCancellationRequested)) cancellation.Proof = null;
            if (cancellation.Proof is null) return false;
            proof = cancellation.Proof;
            return true;
        }
    }

    internal bool OwnsStatusCanceledPurgeCancellationRead(StatusCanceledPurgeCancellationReadProof proof, Window window,
        Capture.Binding binding, StatusCanceledPurgeCancellationReadPhase phase, Task<Measurement> task) =>
        TryGetStatusCanceledPurgeCancellationRead(window, binding, phase, task, out var issued) && ReferenceEquals(issued, proof);

    private async Task<Measurement> CollectPurgeReadAsync(Window window, Capture.Binding binding,
        Registration registration, PurgeReadRun run, Task admission)
    {
        await admission.ConfigureAwait(false);
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        budget.Check();
        var started = budget.ObservedAt;
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource([.. run.Tokens, deadline.Token]);
        var read = new PrivateRead();
        Task? nativeTask = null;
        int? status = null;
        string? requestId = null, originalVaultId = null, responseHash = null;
        DeletedVault? deleted = null;
        Failure failure = Failure.Unavailable;
        SecretStatus outcome = SecretStatus.Unavailable;
        bool valid = false;
        try
        {
            linked.Token.ThrowIfCancellationRequested();
            var uri = new Uri(ArmOrigin + Path(binding.Resource) + "?api-version=" + binding.ApiRevision);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(ArmOrigin), ArmOrigin),
                Transport = new ReadTransport(authority.Transport, uri, budget, read, limits.MaximumResponseBytes,
                    requireErrorRebuffer: true)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion(Type(binding.Resource), binding.ApiRevision);
            if (binding.Resource is DeletedVaultScope)
                options.SetApiVersion("Microsoft.KeyVault/deletedVaults", binding.ApiRevision);
            var client = new ArmClient(new ObserverCredential(authority.Credential, budget), null, options);
            Response<KeyVaultResource>? activeResponse = null;
            Response<DeletedKeyVaultResource>? deletedResponse = null;
            RequestFailedException? error = null;
            try
            {
                if (binding.Resource is VaultScope vault)
                {
                    var actual = client.GetKeyVaultResource(new(vault.ExportResourceId())).GetAsync(linked.Token);
                    nativeTask = actual;
                    activeResponse = await actual.ConfigureAwait(false);
                }
                else
                {
                    var actual = client.GetDeletedKeyVaultResource(new(Path(binding.Resource))).GetAsync(linked.Token);
                    nativeTask = actual;
                    deletedResponse = await actual.ConfigureAwait(false);
                }
            }
            catch (RequestFailedException exception) { error = exception; }
            if (read.Send is not null) await read.Send.ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            Require(nativeTask is not null && read.Body is not null && read.Parser is { Complete: true, Invalid: false });
            status = read.Body.Response.Status;
            requestId = read.Body.NativeRequestId;
            responseHash = read.Body.Sha256;
            long? length = ResponseHeaders(read.Body.Response, out var headerRequestId);
            Require(requestId == headerRequestId && (length is null || length == read.Body.Bytes.Length) &&
                read.Body.Bytes.Length <= limits.MaximumRowBytes);
            Shape(read.Body.Bytes.Span);
            using var json = JsonDocument.Parse(read.Body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            bool present = run.Present;
            Require(status == (present ? 200 : 404));
            if (!present)
            {
                Require(error is { Status: 404, ErrorCode: "ResourceNotFound" } && nativeTask.IsFaulted &&
                    activeResponse is null && deletedResponse is null);
                ValidateStatusSucceededAbsence(json.RootElement);
                outcome = SecretStatus.Absent;
            }
            else
            {
                Require(activeResponse is null && deletedResponse is not null && error is null &&
                    nativeTask.IsCompletedSuccessfully && read.Parser.Owns(deletedResponse.GetRawResponse()));
                originalVaultId = Text(Object(json.RootElement, "properties"), "vaultId");
                var coordinate = (DeletedVaultScope)binding.Resource;
                string[] parts = originalVaultId.Split('/');
                Require(parts.Length == 9 && parts[0].Length == 0 && parts[1] == "subscriptions" &&
                    parts[2] == coordinate.Subscription.SubscriptionId.ToString("D") &&
                    parts[3] == "resourceGroups" && Segment(parts[4], 90) && parts[5] == "providers" &&
                    parts[6] == "Microsoft.KeyVault" && parts[7] == "vaults" && parts[8] == coordinate.VaultName);
                ValidatePurgeDeleted(json.RootElement, deletedResponse.Value.Data, Path(binding.Resource),
                    originalVaultId, binding.Selector.Nonce, run.Baseline);
                var properties = deletedResponse.Value.Data.Properties;
                deleted = new(originalVaultId, properties.DeletedOn, properties.ScheduledPurgeOn, properties.PurgeProtectionEnabled);
                outcome = SecretStatus.Success;
            }
            valid = true;
        }
        catch (Exception exception)
        {
            failure = deadline.IsCancellationRequested ? Failure.Deadline :
                exception is Boundary b ? b.Reason : Failure.Unavailable;
        }
        finally
        {
            // Publication follows the actual native, credential, transport,
            // parser and host finalizers, including ignored cancellation.
            if (nativeTask is not null) try { await nativeTask.ConfigureAwait(false); } catch (Exception) { }
            if (read.Send is not null) try { await read.Send.ConfigureAwait(false); } catch (Exception) { }
            try { read.Storage.Dispose(); }
            catch (Exception) { valid = false; failure = Failure.Unavailable; }
        }
        lock (gate)
        {
            if (run.Tokens.Any(t => t.IsCancellationRequested))
                throw new OperationCanceledException(run.Tokens.First(t => t.IsCancellationRequested));
            try
            {
                budget.Check();
                linked.Token.ThrowIfCancellationRequested();
                Require(valid && read.Parser is { Complete: true, Invalid: false } &&
                    nativeTask is not null && nativeTask.IsCompleted && read.Send is { IsCompletedSuccessfully: true });
                if (statusDeniedReads.TryGetValue(window, out var denied))
                {
                    Require(ReferenceEquals(denied.Run, run) && denied.Proof is null);
                    denied.Proof = new(window, binding, denied.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else if (statusPendingReads.TryGetValue(window, out var selected))
                {
                    Require(ReferenceEquals(selected.Run, run) && selected.Proof is null);
                    selected.Proof = new(window, binding, selected.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else if (statusPendingIndependentReads.TryGetValue(window, out var independent))
                {
                    Require(ReferenceEquals(independent.Run, run) && independent.Proof is null);
                    independent.Proof = new(window, binding, independent.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else if (statusPendingCancellationReads.TryGetValue(window, out var cancellation))
                {
                    Require(ReferenceEquals(cancellation.Run, run) && cancellation.Proof is null);
                    cancellation.Proof = new(window, binding, cancellation.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else if (statusFailedReads.TryGetValue(window, out var failed))
                {
                    Require(ReferenceEquals(failed.Run, run) && failed.Proof is null);
                    failed.Proof = new(window, binding, failed.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else if (statusFailedIndependentReads.TryGetValue(window, out var failedIndependent))
                {
                    Require(ReferenceEquals(failedIndependent.Run, run) && failedIndependent.Proof is null);
                    failedIndependent.Proof = new(window, binding, failedIndependent.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else if (statusCanceledReads.TryGetValue(window, out var canceled))
                {
                    Require(ReferenceEquals(canceled.Run, run) && canceled.Proof is null);
                    canceled.Proof = new(window, binding, canceled.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else if (statusCanceledIndependentReads.TryGetValue(window, out var canceledIndependent))
                {
                    Require(ReferenceEquals(canceledIndependent.Run, run) && canceledIndependent.Proof is null);
                    canceledIndependent.Proof = new(window, binding, canceledIndependent.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else if (statusCanceledCancellationReads.TryGetValue(window, out var canceledCancellation))
                {
                    Require(ReferenceEquals(canceledCancellation.Run, run) && canceledCancellation.Proof is null);
                    canceledCancellation.Proof = new(window, binding, canceledCancellation.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                else
                {
                    Require(statusFailedCancellationReads.TryGetValue(window, out var failedCancellation) &&
                        ReferenceEquals(failedCancellation.Run, run) && failedCancellation.Proof is null);
                    failedCancellation.Proof = new(window, binding, failedCancellation.Phase, nativeTask, status!.Value, originalVaultId,
                        read.RequestSha256!, responseHash!, requestId!, started, budget.ObservedAt);
                }
                failure = Failure.None;
            }
            catch (Exception exception)
            {
                failure = deadline.IsCancellationRequested ? Failure.Deadline :
                    exception is Boundary b ? b.Reason : Failure.Unavailable;
                outcome = SecretStatus.Unavailable;
                deleted = null;
            }
        }
        bool exists = failure == Failure.None && outcome == SecretStatus.Success;
        return new()
        {
            Binding = binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = budget.ObservedAt,
            Identity = authority.Label,
            Failure = failure,
            ResourceStatus = outcome,
            // A positive response revokes old absence even when native parsing
            // fails. Typed proof publication still requires all checks above.
            HttpStatus = status ?? read.ObservedStatus,
            NativeRequestId = requestId,
            ResourceId = exists ? Path(binding.Resource) : null,
            ResourceName = exists ? Path(binding.Resource).Split('/')[^1] : null,
            ResourceType = exists ? "Microsoft.KeyVault/deletedVaults" : null,
            NativeState = null,
            Topic = null,
            EventTypes = [],
            VaultConfiguration = null,
            ConnectionState = null,
            NotificationConfiguration = null,
            DeletedVault = exists ? deleted : null,
            RoleAssignment = null,
            PersistedStateEligible = exists
        };
    }

    private static void ValidatePurgeDeleted(JsonElement root, DeletedKeyVaultData native, string deletedId,
        string vaultId, Guid nonce, VaultAdministrationEffects.Configuration baseline)
    {
        Require(Only(root, "id", "name", "type", "properties") && Text(root, "id") == deletedId &&
            Text(root, "name") == vaultId.Split('/')[^1] && Text(root, "type") == "Microsoft.KeyVault/deletedVaults");
        var p = Object(root, "properties");
        Require(Only(p, "vaultId", "location", "tags", "purgeProtectionEnabled", "deletionDate", "scheduledPurgeDate") &&
            Text(p, "vaultId") == vaultId && Text(p, "location") == baseline.Location &&
            Object(p, "tags").EnumerateObject().Count() == 1 && Text(Object(p, "tags"), "secretkit-fixture") == nonce.ToString("N") &&
            Boolean(p, "purgeProtectionEnabled") == false && Date(p, "deletionDate") is { } deleted &&
            Date(p, "scheduledPurgeDate") is { } purge && purge - deleted == TimeSpan.FromDays(baseline.RetentionDays));
        Require(native.Id?.ToString() == deletedId && native.Name == Text(root, "name") &&
            native.ResourceType.ToString() == Text(root, "type") && native.Properties.VaultId == vaultId &&
            native.Properties.Location == baseline.Location && native.Properties.Tags.Count == 1 &&
            native.Properties.Tags.TryGetValue("secretkit-fixture", out var tag) && tag == nonce.ToString("N") &&
            native.Properties.PurgeProtectionEnabled == false && native.Properties.DeletedOn == Date(p, "deletionDate") &&
            native.Properties.ScheduledPurgeOn == Date(p, "scheduledPurgeDate"));
    }

    internal enum StatusSucceededDeleteVaultReadPhase { BaselineActive, BaselineDeleted, SelectedActive, SelectedDeleted }
    internal sealed class StatusSucceededDeleteVaultReadProof(Window window, Capture.Binding binding,
        StatusSucceededDeleteVaultReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusSucceededDeleteVaultReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusSucceededDeleteVaultReadProof]";
    }
    private sealed class StatusSucceededDeleteVaultReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusSucceededDeleteVaultReadPhase phase)
    {
        internal readonly VaultAdministrationEffects.Configuration Baseline = baseline;
        internal readonly StatusSucceededDeleteVaultReadPhase Phase = phase;
        internal StatusSucceededDeleteVaultReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusSucceededDeleteVaultReadRegistration> statusSucceededReads =
        new(ReferenceEqualityComparer.Instance);

    internal Window ArmStatusSucceededDeleteVault(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusSucceededDeleteVaultReadPhase phase)
    {
        Require(binding is not null && VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.DeleteVault && binding.ApiRevision == "2026-02-01" &&
            binding.LeaseId != Guid.Empty && binding.Selector.Nonce != Guid.Empty &&
            new[] { binding.Selector.Operation, binding.Selector.Scope, binding.Selector.Variant, binding.Selector.Case }
                .All(s => TextValue(s, 512)) && Segment(binding.Location, 50) &&
            Enum.IsDefined(phase) && baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true } &&
            baseline.Policies is { Length: 0 } && baseline.TenantId == tenantId && baseline.Location == binding.Location);
        _ = baseline.Build();
        bool deleted = phase is StatusSucceededDeleteVaultReadPhase.BaselineDeleted or StatusSucceededDeleteVaultReadPhase.SelectedDeleted;
        Require(deleted ? binding.Resource is DeletedVaultScope d && d.Location == binding.Location :
            binding.Resource is VaultScope);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            Require(windows.Count < 32 && !nonces.Contains(binding.Selector.Nonce) && !leases.Contains(binding.LeaseId));
            var window = Window.Create(binding, armed);
            windows.Add(window, new(stamp));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            statusSucceededReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultRead(Window window, Capture.Binding binding, Task<Measurement> readTask,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!windows.TryGetValue(window, out var r) || !statusSucceededReads.TryGetValue(window, out var selected) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Task, readTask) ||
                !readTask.IsCompletedSuccessfully || selected.Proof is null) return false;
            proof = selected.Proof;
            return true;
        }
    }

    private async Task<Measurement> CollectStatusSucceededDeleteVaultAsync(Window window, Capture.Binding binding,
        Registration registration, StatusSucceededDeleteVaultReadRegistration selected, Task admission, CancellationToken token)
    {
        await admission.ConfigureAwait(false);
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        budget.Check();
        var started = budget.ObservedAt;
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        var read = new PrivateRead();
        Task? nativeTask = null;
        int? status = null;
        string? requestId = null, originalVaultId = null;
        Failure failure = Failure.Unavailable;
        SecretStatus outcome = SecretStatus.Unavailable;
        VaultConfiguration? configuration = null;
        DeletedVault? deleted = null;
        bool disposed = false;
        try
        {
            var uri = new Uri(ArmOrigin + Path(binding.Resource) + "?api-version=" + binding.ApiRevision);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(ArmOrigin), ArmOrigin),
                Transport = new ReadTransport(authority.Transport, uri, budget, read, limits.MaximumResponseBytes)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion(Type(binding.Resource), binding.ApiRevision);
            if (binding.Resource is DeletedVaultScope)
                options.SetApiVersion("Microsoft.KeyVault/deletedVaults", binding.ApiRevision);
            var client = new ArmClient(new ObserverCredential(authority.Credential, budget), null, options);
            Response<KeyVaultResource>? activeResponse = null;
            Response<DeletedKeyVaultResource>? deletedResponse = null;
            RequestFailedException? error = null;
            try
            {
                if (binding.Resource is VaultScope vault)
                {
                    var actual = client.GetKeyVaultResource(new(vault.ExportResourceId())).GetAsync(linked.Token);
                    nativeTask = actual;
                    activeResponse = await actual.ConfigureAwait(false);
                }
                else
                {
                    var actual = client.GetDeletedKeyVaultResource(new(Path(binding.Resource))).GetAsync(linked.Token);
                    nativeTask = actual;
                    deletedResponse = await actual.ConfigureAwait(false);
                }
            }
            catch (RequestFailedException exception) { error = exception; }
            if (read.Send is not null) await read.Send.ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            Require(nativeTask is not null && read.Body is not null && read.Parser is { Complete: true, Invalid: false });
            status = read.Body.Response.Status;
            requestId = read.Body.NativeRequestId;
            _ = ResponseHeaders(read.Body.Response, out _);
            Require(read.Body.Bytes.Length <= limits.MaximumRowBytes);
            Shape(read.Body.Bytes.Span);
            using var json = JsonDocument.Parse(read.Body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            bool expectAbsent = selected.Phase is StatusSucceededDeleteVaultReadPhase.BaselineDeleted or
                StatusSucceededDeleteVaultReadPhase.SelectedActive;
            Require(status == (expectAbsent ? 404 : 200));
            if (expectAbsent)
            {
                Require(error is { Status: 404, ErrorCode: "ResourceNotFound" } && nativeTask.IsFaulted &&
                    activeResponse is null && deletedResponse is null);
                ValidateStatusSucceededAbsence(json.RootElement);
                outcome = SecretStatus.Absent;
            }
            else if (activeResponse is not null)
            {
                Require(error is null && nativeTask.IsCompletedSuccessfully && read.Parser.Owns(activeResponse.GetRawResponse()));
                originalVaultId = Path(binding.Resource);
                ValidateStatusSucceededActive(json.RootElement, activeResponse.Value.Data, originalVaultId,
                    binding.Selector.Nonce, selected.Baseline);
                configuration = new(selected.Baseline.Location, selected.Baseline.TenantId, selected.Baseline.Sku,
                    true, false, selected.Baseline.RetentionDays, true, [],
                    OptionalText(Object(json.RootElement, "properties"), "createMode"));
                outcome = SecretStatus.Success;
            }
            else
            {
                Require(deletedResponse is not null && error is null && nativeTask.IsCompletedSuccessfully &&
                    read.Parser.Owns(deletedResponse.GetRawResponse()));
                originalVaultId = Text(Object(json.RootElement, "properties"), "vaultId");
                var coordinate = (DeletedVaultScope)binding.Resource;
                string[] parts = originalVaultId.Split('/');
                Require(parts.Length == 9 && parts[1] == "subscriptions" &&
                    parts[2] == coordinate.Subscription.SubscriptionId.ToString("D") &&
                    parts[3] == "resourceGroups" && Segment(parts[4], 90) && parts[5] == "providers" &&
                    parts[6] == "Microsoft.KeyVault" && parts[7] == "vaults" && parts[8] == coordinate.VaultName);
                ValidateStatusSucceededDeleted(json.RootElement, deletedResponse.Value.Data, Path(binding.Resource),
                    originalVaultId, binding.Selector.Nonce, selected.Baseline);
                var p = deletedResponse.Value.Data.Properties;
                deleted = new(originalVaultId, p.DeletedOn, p.ScheduledPurgeOn, p.PurgeProtectionEnabled);
                outcome = SecretStatus.Success;
            }
            read.Storage.Dispose();
            disposed = true;
            Require(read.Parser is { Complete: true, Invalid: false });
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            lock (gate) selected.Proof = new(window, binding, selected.Phase, nativeTask, status.Value,
                originalVaultId, read.RequestSha256!, read.Body.Sha256, requestId, started, budget.ObservedAt);
            failure = Failure.None;
        }
        catch (Exception exception)
        {
            lock (gate) selected.Proof = null;
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
            failure = deadline.IsCancellationRequested ? Failure.Deadline : exception is Boundary b ? b.Reason : Failure.Unavailable;
            outcome = SecretStatus.Unavailable;
        }
        finally
        {
            if (nativeTask is not null) try { await nativeTask.ConfigureAwait(false); } catch (Exception) { }
            if (read.Send is not null) try { await read.Send.ConfigureAwait(false); } catch (Exception) { }
            if (!disposed)
                try { read.Storage.Dispose(); }
                catch { lock (gate) selected.Proof = null; failure = Failure.Unavailable; outcome = SecretStatus.Unavailable; }
        }
        bool present = failure == Failure.None && outcome == SecretStatus.Success;
        return new()
        {
            Binding = binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = budget.ObservedAt,
            Identity = authority.Label,
            Failure = failure,
            ResourceStatus = outcome,
            HttpStatus = status,
            NativeRequestId = requestId,
            ResourceId = present ? Path(binding.Resource) : null,
            ResourceName = present ? Path(binding.Resource).Split('/')[^1] : null,
            ResourceType = present ? Type(binding.Resource) : null,
            NativeState = present && configuration is not null ? "Succeeded" : null,
            Topic = null,
            EventTypes = [],
            VaultConfiguration = present ? configuration : null,
            ConnectionState = null,
            NotificationConfiguration = null,
            DeletedVault = present ? deleted : null,
            RoleAssignment = null,
            PersistedStateEligible = present
        };
    }

    internal enum StatusSucceededDeleteVaultIndependentReadPhase { BaselineActive, BaselineDeleted, SelectedActive, SelectedDeleted }
    internal sealed class StatusSucceededDeleteVaultIndependentReadProof(Window window, Capture.Binding binding,
        StatusSucceededDeleteVaultIndependentReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusSucceededDeleteVaultIndependentReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusSucceededDeleteVaultIndependentReadProof]";
    }
    private sealed class StatusSucceededDeleteVaultIndependentReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusSucceededDeleteVaultIndependentReadPhase phase)
    {
        internal readonly VaultAdministrationEffects.Configuration Baseline = baseline;
        internal readonly StatusSucceededDeleteVaultIndependentReadPhase Phase = phase;
        internal StatusSucceededDeleteVaultIndependentReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusSucceededDeleteVaultIndependentReadRegistration> statusSucceededIndependentReads =
        new(ReferenceEqualityComparer.Instance);

    internal Window ArmStatusSucceededDeleteVaultIndependent(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusSucceededDeleteVaultIndependentReadPhase phase)
    {
        Require(binding is not null && VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.DeleteVault && binding.ApiRevision == "2026-02-01" &&
            binding.LeaseId != Guid.Empty && binding.Selector.Nonce != Guid.Empty &&
            new[] { binding.Selector.Operation, binding.Selector.Scope, binding.Selector.Variant, binding.Selector.Case }
                .All(s => TextValue(s, 512)) && Segment(binding.Location, 50) &&
            Enum.IsDefined(phase) && baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true } &&
            baseline.Policies is { Length: 0 } && baseline.TenantId == tenantId && baseline.Location == binding.Location);
        _ = baseline.Build();
        bool deleted = phase is StatusSucceededDeleteVaultIndependentReadPhase.BaselineDeleted or StatusSucceededDeleteVaultIndependentReadPhase.SelectedDeleted;
        Require(deleted ? binding.Resource is DeletedVaultScope d && d.Location == binding.Location :
            binding.Resource is VaultScope);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            Require(windows.Count < 32 && !nonces.Contains(binding.Selector.Nonce) && !leases.Contains(binding.LeaseId));
            var window = Window.Create(binding, armed);
            windows.Add(window, new(stamp));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            statusSucceededIndependentReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultIndependentRead(Window window, Capture.Binding binding, Task<Measurement> readTask,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultIndependentReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!windows.TryGetValue(window, out var r) || !statusSucceededIndependentReads.TryGetValue(window, out var selected) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Task, readTask) ||
                !readTask.IsCompletedSuccessfully || selected.Proof is null) return false;
            proof = selected.Proof;
            return true;
        }
    }

    private async Task<Measurement> CollectStatusSucceededDeleteVaultIndependentAsync(Window window, Capture.Binding binding,
        Registration registration, StatusSucceededDeleteVaultIndependentReadRegistration selected, Task admission, CancellationToken token)
    {
        await admission.ConfigureAwait(false);
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        budget.Check();
        var started = budget.ObservedAt;
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        var read = new PrivateRead();
        Task? nativeTask = null;
        int? status = null;
        string? requestId = null, originalVaultId = null;
        Failure failure = Failure.Unavailable;
        SecretStatus outcome = SecretStatus.Unavailable;
        VaultConfiguration? configuration = null;
        DeletedVault? deleted = null;
        bool disposed = false;
        try
        {
            var uri = new Uri(ArmOrigin + Path(binding.Resource) + "?api-version=" + binding.ApiRevision);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(ArmOrigin), ArmOrigin),
                Transport = new ReadTransport(authority.Transport, uri, budget, read, limits.MaximumResponseBytes)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion(Type(binding.Resource), binding.ApiRevision);
            if (binding.Resource is DeletedVaultScope)
                options.SetApiVersion("Microsoft.KeyVault/deletedVaults", binding.ApiRevision);
            var client = new ArmClient(new ObserverCredential(authority.Credential, budget), null, options);
            Response<KeyVaultResource>? activeResponse = null;
            Response<DeletedKeyVaultResource>? deletedResponse = null;
            RequestFailedException? error = null;
            try
            {
                if (binding.Resource is VaultScope vault)
                {
                    var actual = client.GetKeyVaultResource(new(vault.ExportResourceId())).GetAsync(linked.Token);
                    nativeTask = actual;
                    activeResponse = await actual.ConfigureAwait(false);
                }
                else
                {
                    var actual = client.GetDeletedKeyVaultResource(new(Path(binding.Resource))).GetAsync(linked.Token);
                    nativeTask = actual;
                    deletedResponse = await actual.ConfigureAwait(false);
                }
            }
            catch (RequestFailedException exception) { error = exception; }
            if (read.Send is not null) await read.Send.ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            Require(nativeTask is not null && read.Body is not null && read.Parser is { Complete: true, Invalid: false });
            status = read.Body.Response.Status;
            requestId = read.Body.NativeRequestId;
            _ = ResponseHeaders(read.Body.Response, out _);
            Require(read.Body.Bytes.Length <= limits.MaximumRowBytes);
            Shape(read.Body.Bytes.Span);
            using var json = JsonDocument.Parse(read.Body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            bool expectAbsent = selected.Phase is StatusSucceededDeleteVaultIndependentReadPhase.BaselineDeleted or
                StatusSucceededDeleteVaultIndependentReadPhase.SelectedActive;
            Require(status == (expectAbsent ? 404 : 200));
            if (expectAbsent)
            {
                Require(error is { Status: 404, ErrorCode: "ResourceNotFound" } && nativeTask.IsFaulted &&
                    activeResponse is null && deletedResponse is null);
                ValidateStatusSucceededAbsence(json.RootElement);
                outcome = SecretStatus.Absent;
            }
            else if (activeResponse is not null)
            {
                Require(error is null && nativeTask.IsCompletedSuccessfully && read.Parser.Owns(activeResponse.GetRawResponse()));
                originalVaultId = Path(binding.Resource);
                ValidateStatusSucceededActive(json.RootElement, activeResponse.Value.Data, originalVaultId,
                    binding.Selector.Nonce, selected.Baseline);
                configuration = new(selected.Baseline.Location, selected.Baseline.TenantId, selected.Baseline.Sku,
                    true, false, selected.Baseline.RetentionDays, true, [],
                    OptionalText(Object(json.RootElement, "properties"), "createMode"));
                outcome = SecretStatus.Success;
            }
            else
            {
                Require(deletedResponse is not null && error is null && nativeTask.IsCompletedSuccessfully &&
                    read.Parser.Owns(deletedResponse.GetRawResponse()));
                originalVaultId = Text(Object(json.RootElement, "properties"), "vaultId");
                var coordinate = (DeletedVaultScope)binding.Resource;
                string[] parts = originalVaultId.Split('/');
                Require(parts.Length == 9 && parts[1] == "subscriptions" &&
                    parts[2] == coordinate.Subscription.SubscriptionId.ToString("D") &&
                    parts[3] == "resourceGroups" && Segment(parts[4], 90) && parts[5] == "providers" &&
                    parts[6] == "Microsoft.KeyVault" && parts[7] == "vaults" && parts[8] == coordinate.VaultName);
                ValidateStatusSucceededDeleted(json.RootElement, deletedResponse.Value.Data, Path(binding.Resource),
                    originalVaultId, binding.Selector.Nonce, selected.Baseline);
                var p = deletedResponse.Value.Data.Properties;
                deleted = new(originalVaultId, p.DeletedOn, p.ScheduledPurgeOn, p.PurgeProtectionEnabled);
                outcome = SecretStatus.Success;
            }
            read.Storage.Dispose();
            disposed = true;
            Require(read.Parser is { Complete: true, Invalid: false });
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            lock (gate) selected.Proof = new(window, binding, selected.Phase, nativeTask, status.Value,
                originalVaultId, read.RequestSha256!, read.Body.Sha256, requestId, started, budget.ObservedAt);
            failure = Failure.None;
        }
        catch (Exception exception)
        {
            lock (gate) selected.Proof = null;
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
            failure = deadline.IsCancellationRequested ? Failure.Deadline : exception is Boundary b ? b.Reason : Failure.Unavailable;
            outcome = SecretStatus.Unavailable;
        }
        finally
        {
            if (nativeTask is not null) try { await nativeTask.ConfigureAwait(false); } catch (Exception) { }
            if (read.Send is not null) try { await read.Send.ConfigureAwait(false); } catch (Exception) { }
            if (!disposed)
                try { read.Storage.Dispose(); }
                catch { lock (gate) selected.Proof = null; failure = Failure.Unavailable; outcome = SecretStatus.Unavailable; }
        }
        bool present = failure == Failure.None && outcome == SecretStatus.Success;
        return new()
        {
            Binding = binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = budget.ObservedAt,
            Identity = authority.Label,
            Failure = failure,
            ResourceStatus = outcome,
            HttpStatus = status,
            NativeRequestId = requestId,
            ResourceId = present ? Path(binding.Resource) : null,
            ResourceName = present ? Path(binding.Resource).Split('/')[^1] : null,
            ResourceType = present ? Type(binding.Resource) : null,
            NativeState = present && configuration is not null ? "Succeeded" : null,
            Topic = null,
            EventTypes = [],
            VaultConfiguration = present ? configuration : null,
            ConnectionState = null,
            NotificationConfiguration = null,
            DeletedVault = present ? deleted : null,
            RoleAssignment = null,
            PersistedStateEligible = present
        };
    }

    internal enum StatusSucceededDeleteVaultCancellationReadPhase { BaselineActive, BaselineDeleted, SelectedActive, SelectedDeleted }
    internal sealed class StatusSucceededDeleteVaultCancellationReadProof(Window window, Capture.Binding binding,
        StatusSucceededDeleteVaultCancellationReadPhase phase, Task nativeTask, int httpStatus, string? originalVaultId,
        string requestSha256, string responseSha256, string nativeRequestId, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal StatusSucceededDeleteVaultCancellationReadPhase Phase { get; } = phase;
        internal Task NativeTask { get; } = nativeTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string? OriginalVaultId { get; } = originalVaultId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationReadProof]";
    }
    private sealed class StatusSucceededDeleteVaultCancellationReadRegistration(VaultAdministrationEffects.Configuration baseline,
        StatusSucceededDeleteVaultCancellationReadPhase phase)
    {
        internal readonly VaultAdministrationEffects.Configuration Baseline = baseline;
        internal readonly StatusSucceededDeleteVaultCancellationReadPhase Phase = phase;
        internal StatusSucceededDeleteVaultCancellationReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusSucceededDeleteVaultCancellationReadRegistration> statusSucceededCancellationReads =
        new(ReferenceEqualityComparer.Instance);

    internal Window ArmStatusSucceededDeleteVaultCancellation(Capture.Binding binding, VaultAdministrationEffects.Configuration baseline,
        StatusSucceededDeleteVaultCancellationReadPhase phase)
    {
        Require(binding is not null && VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.DeleteVault && binding.ApiRevision == "2026-02-01" &&
            binding.LeaseId != Guid.Empty && binding.Selector.Nonce != Guid.Empty &&
            new[] { binding.Selector.Operation, binding.Selector.Scope, binding.Selector.Variant, binding.Selector.Case }
                .All(s => TextValue(s, 512)) && Segment(binding.Location, 50) &&
            Enum.IsDefined(phase) && baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true } &&
            baseline.Policies is { Length: 0 } && baseline.TenantId == tenantId && baseline.Location == binding.Location);
        _ = baseline.Build();
        bool deleted = phase is StatusSucceededDeleteVaultCancellationReadPhase.BaselineDeleted or StatusSucceededDeleteVaultCancellationReadPhase.SelectedDeleted;
        Require(deleted ? binding.Resource is DeletedVaultScope d && d.Location == binding.Location :
            binding.Resource is VaultScope);
        var snapshot = baseline with { Policies = [] };
        var armed = time.GetUtcNow();
        var stamp = time.GetTimestamp();
        lock (gate)
        {
            Require(windows.Count < 32 && !nonces.Contains(binding.Selector.Nonce) && !leases.Contains(binding.LeaseId));
            var window = Window.Create(binding, armed);
            windows.Add(window, new(stamp));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            statusSucceededCancellationReads.Add(window, new(snapshot, phase));
            return window;
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultCancellationRead(Window window, Capture.Binding binding, Task<Measurement> readTask,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultCancellationReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!windows.TryGetValue(window, out var r) || !statusSucceededCancellationReads.TryGetValue(window, out var selected) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Task, readTask) ||
                !readTask.IsCompletedSuccessfully || selected.Proof is null) return false;
            proof = selected.Proof;
            return true;
        }
    }

    private async Task<Measurement> CollectStatusSucceededDeleteVaultCancellationAsync(Window window, Capture.Binding binding,
        Registration registration, StatusSucceededDeleteVaultCancellationReadRegistration selected, Task admission, CancellationToken token)
    {
        await admission.ConfigureAwait(false);
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        budget.Check();
        var started = budget.ObservedAt;
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        var read = new PrivateRead();
        Task? nativeTask = null;
        int? status = null;
        string? requestId = null, originalVaultId = null;
        Failure failure = Failure.Unavailable;
        SecretStatus outcome = SecretStatus.Unavailable;
        VaultConfiguration? configuration = null;
        DeletedVault? deleted = null;
        bool disposed = false;
        try
        {
            var uri = new Uri(ArmOrigin + Path(binding.Resource) + "?api-version=" + binding.ApiRevision);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(ArmOrigin), ArmOrigin),
                Transport = new ReadTransport(authority.Transport, uri, budget, read, limits.MaximumResponseBytes)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion(Type(binding.Resource), binding.ApiRevision);
            if (binding.Resource is DeletedVaultScope)
                options.SetApiVersion("Microsoft.KeyVault/deletedVaults", binding.ApiRevision);
            var client = new ArmClient(new ObserverCredential(authority.Credential, budget), null, options);
            Response<KeyVaultResource>? activeResponse = null;
            Response<DeletedKeyVaultResource>? deletedResponse = null;
            RequestFailedException? error = null;
            try
            {
                if (binding.Resource is VaultScope vault)
                {
                    var actual = client.GetKeyVaultResource(new(vault.ExportResourceId())).GetAsync(linked.Token);
                    nativeTask = actual;
                    activeResponse = await actual.ConfigureAwait(false);
                }
                else
                {
                    var actual = client.GetDeletedKeyVaultResource(new(Path(binding.Resource))).GetAsync(linked.Token);
                    nativeTask = actual;
                    deletedResponse = await actual.ConfigureAwait(false);
                }
            }
            catch (RequestFailedException exception) { error = exception; }
            if (read.Send is not null) await read.Send.ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            Require(nativeTask is not null && read.Body is not null && read.Parser is { Complete: true, Invalid: false });
            status = read.Body.Response.Status;
            requestId = read.Body.NativeRequestId;
            _ = ResponseHeaders(read.Body.Response, out _);
            Require(read.Body.Bytes.Length <= limits.MaximumRowBytes);
            Shape(read.Body.Bytes.Span);
            using var json = JsonDocument.Parse(read.Body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            bool expectAbsent = selected.Phase is StatusSucceededDeleteVaultCancellationReadPhase.BaselineDeleted or
                StatusSucceededDeleteVaultCancellationReadPhase.SelectedActive;
            Require(status == (expectAbsent ? 404 : 200));
            if (expectAbsent)
            {
                Require(error is { Status: 404, ErrorCode: "ResourceNotFound" } && nativeTask.IsFaulted &&
                    activeResponse is null && deletedResponse is null);
                ValidateStatusSucceededAbsence(json.RootElement);
                outcome = SecretStatus.Absent;
            }
            else if (activeResponse is not null)
            {
                Require(error is null && nativeTask.IsCompletedSuccessfully && read.Parser.Owns(activeResponse.GetRawResponse()));
                originalVaultId = Path(binding.Resource);
                ValidateStatusSucceededActive(json.RootElement, activeResponse.Value.Data, originalVaultId,
                    binding.Selector.Nonce, selected.Baseline);
                configuration = new(selected.Baseline.Location, selected.Baseline.TenantId, selected.Baseline.Sku,
                    true, false, selected.Baseline.RetentionDays, true, [],
                    OptionalText(Object(json.RootElement, "properties"), "createMode"));
                outcome = SecretStatus.Success;
            }
            else
            {
                Require(deletedResponse is not null && error is null && nativeTask.IsCompletedSuccessfully &&
                    read.Parser.Owns(deletedResponse.GetRawResponse()));
                originalVaultId = Text(Object(json.RootElement, "properties"), "vaultId");
                var coordinate = (DeletedVaultScope)binding.Resource;
                string[] parts = originalVaultId.Split('/');
                Require(parts.Length == 9 && parts[1] == "subscriptions" &&
                    parts[2] == coordinate.Subscription.SubscriptionId.ToString("D") &&
                    parts[3] == "resourceGroups" && Segment(parts[4], 90) && parts[5] == "providers" &&
                    parts[6] == "Microsoft.KeyVault" && parts[7] == "vaults" && parts[8] == coordinate.VaultName);
                ValidateStatusSucceededDeleted(json.RootElement, deletedResponse.Value.Data, Path(binding.Resource),
                    originalVaultId, binding.Selector.Nonce, selected.Baseline);
                var p = deletedResponse.Value.Data.Properties;
                deleted = new(originalVaultId, p.DeletedOn, p.ScheduledPurgeOn, p.PurgeProtectionEnabled);
                outcome = SecretStatus.Success;
            }
            read.Storage.Dispose();
            disposed = true;
            Require(read.Parser is { Complete: true, Invalid: false });
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            lock (gate) selected.Proof = new(window, binding, selected.Phase, nativeTask, status.Value,
                originalVaultId, read.RequestSha256!, read.Body.Sha256, requestId, started, budget.ObservedAt);
            failure = Failure.None;
        }
        catch (Exception exception)
        {
            lock (gate) selected.Proof = null;
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
            failure = deadline.IsCancellationRequested ? Failure.Deadline : exception is Boundary b ? b.Reason : Failure.Unavailable;
            outcome = SecretStatus.Unavailable;
        }
        finally
        {
            if (nativeTask is not null) try { await nativeTask.ConfigureAwait(false); } catch (Exception) { }
            if (read.Send is not null) try { await read.Send.ConfigureAwait(false); } catch (Exception) { }
            if (!disposed)
                try { read.Storage.Dispose(); }
                catch { lock (gate) selected.Proof = null; failure = Failure.Unavailable; outcome = SecretStatus.Unavailable; }
        }
        bool present = failure == Failure.None && outcome == SecretStatus.Success;
        return new()
        {
            Binding = binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = budget.ObservedAt,
            Identity = authority.Label,
            Failure = failure,
            ResourceStatus = outcome,
            HttpStatus = status,
            NativeRequestId = requestId,
            ResourceId = present ? Path(binding.Resource) : null,
            ResourceName = present ? Path(binding.Resource).Split('/')[^1] : null,
            ResourceType = present ? Type(binding.Resource) : null,
            NativeState = present && configuration is not null ? "Succeeded" : null,
            Topic = null,
            EventTypes = [],
            VaultConfiguration = present ? configuration : null,
            ConnectionState = null,
            NotificationConfiguration = null,
            DeletedVault = present ? deleted : null,
            RoleAssignment = null,
            PersistedStateEligible = present
        };
    }

    internal static void ValidateStatusSucceededAbsence(JsonElement root)
    {
        Require(Only(root, "error") && root.EnumerateObject().Count() == 1);
        var error = Object(root, "error");
        Require(Only(error, "code", "message") && Text(error, "code") == "ResourceNotFound");
        if (error.TryGetProperty("message", out var message))
            Require(message.ValueKind == JsonValueKind.String && message.GetString()!.Length <= 4096 &&
                !message.GetString()!.Any(char.IsControl));
    }

    internal static void ValidateStatusSucceededActive(JsonElement root, KeyVaultData native, string vaultId, Guid nonce,
        VaultAdministrationEffects.Configuration baseline, bool recover = false)
    {
        _ = VaultFixtureProvisioner.ParseOwnedVaultResource(vaultId, nonce, root, baseline, "Succeeded", recover: recover);
        Require(Only(root, "id", "name", "type", "location", "tags", "properties", "systemData"));
        var p = Object(root, "properties");
        Require(Only(p, "tenantId", "sku", "vaultUri", "provisioningState", "enableRbacAuthorization",
            "enablePurgeProtection", "enableSoftDelete", "softDeleteRetentionInDays", "publicNetworkAccess",
            "accessPolicies", "privateEndpointConnections", "createMode", "enabledForDeployment",
            "enabledForDiskEncryption", "enabledForTemplateDeployment", "networkAcls"));
        Require(Only(Object(p, "sku"), "family", "name"));
        Require(native.Id?.ToString() == vaultId && native.Name == Text(root, "name") &&
            native.ResourceType.ToString() == Text(root, "type") && native.Location.Name == baseline.Location &&
            native.Tags.Count == 1 && native.Tags.TryGetValue("secretkit-fixture", out var tag) && tag == nonce.ToString("N") &&
            native.Properties.TenantId == baseline.TenantId && native.Properties.Sku.Family.ToString() == "A" &&
            native.Properties.Sku.Name.ToString().Equals(baseline.Sku.ToString(), StringComparison.OrdinalIgnoreCase) &&
            native.Properties.VaultUri == new Uri(Text(p, "vaultUri")) && native.Properties.ProvisioningState?.ToString() == "Succeeded" &&
            native.Properties.EnableRbacAuthorization == true && native.Properties.EnableSoftDelete == true &&
            native.Properties.EnablePurgeProtection == false && native.Properties.SoftDeleteRetentionInDays == baseline.RetentionDays &&
            native.Properties.PublicNetworkAccess == (baseline.PublicNetworkAccess ? "Enabled" : "Disabled") &&
            native.Properties.AccessPolicies.Count == 0 &&
            Same(native.Properties.CreateMode?.ToString(), OptionalText(p, "createMode")));
        using var serialized = JsonDocument.Parse(ModelReaderWriter.Write(native).ToMemory());
        var model = Object(serialized.RootElement, "properties");
        Require(model.TryGetProperty("privateEndpointConnections", out var children) &&
            children.ValueKind == JsonValueKind.Array && children.GetArrayLength() == 0);
        foreach (string field in new[] { "enabledForDeployment", "enabledForDiskEncryption", "enabledForTemplateDeployment", "networkAcls" })
            JoinOptional(p, model, field);
        if (root.TryGetProperty("systemData", out var system) && system.ValueKind != JsonValueKind.Null)
        {
            Require(Only(system, "createdBy", "createdByType", "createdAt", "lastModifiedBy", "lastModifiedByType", "lastModifiedAt") &&
                native.SystemData is not null &&
                native.SystemData.CreatedBy == OptionalText(system, "createdBy") &&
                native.SystemData.CreatedByType?.ToString() == OptionalText(system, "createdByType") &&
                native.SystemData.CreatedOn == Date(system, "createdAt") &&
                native.SystemData.LastModifiedBy == OptionalText(system, "lastModifiedBy") &&
                native.SystemData.LastModifiedByType?.ToString() == OptionalText(system, "lastModifiedByType") &&
                native.SystemData.LastModifiedOn == Date(system, "lastModifiedAt"));
        }
        else Require(native.SystemData is null);
    }

    private static void JoinOptional(JsonElement raw, JsonElement model, string field)
    {
        bool supplied = raw.TryGetProperty(field, out var value), projected = model.TryGetProperty(field, out var native);
        Require(supplied ? projected && System.Text.Json.Nodes.JsonNode.DeepEquals(
            System.Text.Json.Nodes.JsonNode.Parse(value.GetRawText()), System.Text.Json.Nodes.JsonNode.Parse(native.GetRawText()))
            : !projected || native.ValueKind == JsonValueKind.Null);
    }

    internal static void ValidateStatusSucceededDeleted(JsonElement root, DeletedKeyVaultData native, string deletedId,
        string vaultId, Guid nonce, VaultAdministrationEffects.Configuration baseline)
    {
        Require(Only(root, "id", "name", "type", "properties") && Text(root, "id") == deletedId &&
            Text(root, "name") == vaultId.Split('/')[^1] && Text(root, "type") == "Microsoft.KeyVault/locations/deletedVaults");
        var p = Object(root, "properties");
        Require(Only(p, "vaultId", "location", "tags", "purgeProtectionEnabled", "deletionDate", "scheduledPurgeDate") &&
            Text(p, "vaultId") == vaultId && Text(p, "location") == baseline.Location &&
            Object(p, "tags").EnumerateObject().Count() == 1 && Text(Object(p, "tags"), "secretkit-fixture") == nonce.ToString("N") &&
            Boolean(p, "purgeProtectionEnabled") == false && Date(p, "deletionDate") is { } deleted &&
            Date(p, "scheduledPurgeDate") is { } purge && purge - deleted == TimeSpan.FromDays(baseline.RetentionDays));
        Require(native.Id?.ToString() == deletedId && native.Name == Text(root, "name") &&
            native.ResourceType.ToString() == Text(root, "type") && native.Properties.VaultId == vaultId &&
            native.Properties.Location == baseline.Location && native.Properties.Tags.Count == 1 &&
            native.Properties.Tags.TryGetValue("secretkit-fixture", out var tag) && tag == nonce.ToString("N") &&
            native.Properties.PurgeProtectionEnabled == false && native.Properties.DeletedOn == Date(p, "deletionDate") &&
            native.Properties.ScheduledPurgeOn == Date(p, "scheduledPurgeDate"));
    }

    // Raw presence is retained separately from the installed model's nullable
    // projections. A missing property is not silently promoted to JSON null.
    internal sealed record PrivateConnectionOptional(string Presence, [property: JsonIgnore] string? Value)
    {
        public override string ToString() => "[PrivateConnectionOptional]";
    }
    internal sealed record StatusPrivateConnectionFacts([property: JsonIgnore] string Id,
        [property: JsonIgnore] string Name, [property: JsonIgnore] string Type,
        [property: JsonIgnore] string EndpointId, string State, string Provisioning,
        [property: JsonIgnore] PrivateConnectionOptional Location,
        [property: JsonIgnore] PrivateConnectionOptional ETag,
        [property: JsonIgnore] PrivateConnectionOptional Description,
        [property: JsonIgnore] PrivateConnectionOptional ActionsRequired, string TagsPresence,
        [property: JsonIgnore] IReadOnlyDictionary<string, string> Tags, string SystemDataPresence,
        [property: JsonIgnore] IReadOnlyDictionary<string, PrivateConnectionOptional> SystemData)
    {
        public override string ToString() => "[StatusPrivateConnectionFacts]";
    }
    internal sealed class StatusPrivateConnectionUpdateReadProof(Window window, Capture.Binding binding,
        Task<Response<KeyVaultPrivateEndpointConnectionResource>> nativeTask, StatusPrivateConnectionFacts? facts,
        int httpStatus, string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal Task<Response<KeyVaultPrivateEndpointConnectionResource>> NativeTask { get; } = nativeTask;
        internal StatusPrivateConnectionFacts? Facts { get; } = facts;
        internal int HttpStatus { get; } = httpStatus;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal string Phase => HttpStatus == 404 ? "cleanup" : Facts?.State == "Pending" ? "baseline" : "selected-state";
        public override string ToString() => "[StatusPrivateConnectionUpdateReadProof]";
    }

    private sealed class PrivateRead
    {
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal int? ObservedStatus;
        internal OwnedArmResponse.Body? Body;
        internal OwnedArmResponse.ParserCustody? Parser;
        internal Task<Response<KeyVaultPrivateEndpointConnectionResource>>? NativeTask;
        internal Task? Send;
        internal string? RequestSha256;
    }

    internal sealed class StatusPrivateConnectionDeleteReadProof(Window window, Capture.Binding binding,
        Task<Response<KeyVaultPrivateEndpointConnectionResource>> nativeTask, StatusPrivateConnectionFacts? facts,
        int httpStatus, string? errorCode, string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt, PrivateConnectionOptional? errorMessage)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal Task<Response<KeyVaultPrivateEndpointConnectionResource>> NativeTask { get; } = nativeTask;
        internal StatusPrivateConnectionFacts? Facts { get; } = facts;
        internal int HttpStatus { get; } = httpStatus;
        internal string? ErrorCode { get; } = errorCode;
        internal PrivateConnectionOptional? ErrorMessage { get; } = errorMessage;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal string Phase => HttpStatus == 404 ? "selected-state" : "baseline";
        public override string ToString() => "[StatusPrivateConnectionDeleteReadProof]";
    }
    internal sealed class StatusPrivateConnectionDeleteSelectedReadProof(Window window, Capture.Binding binding,
        Task<Response<KeyVaultPrivateEndpointConnectionResource>> nativeTask, StatusPrivateConnectionFacts? facts,
        int httpStatus, string? errorCode, string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt, PrivateConnectionOptional? errorMessage)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal Task<Response<KeyVaultPrivateEndpointConnectionResource>> NativeTask { get; } = nativeTask;
        internal StatusPrivateConnectionFacts? Facts { get; } = facts;
        internal int HttpStatus { get; } = httpStatus;
        internal string? ErrorCode { get; } = errorCode;
        internal PrivateConnectionOptional? ErrorMessage { get; } = errorMessage;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal string Phase => HttpStatus == 404 ? "selected-state" : "baseline";
        public override string ToString() => "[StatusPrivateConnectionDeleteSelectedReadProof]";
    }
    internal enum StatusPrivateConnectionDeleteIndependentReadPhase { Baseline, SelectedState, Cleanup }

    internal sealed class StatusPrivateConnectionDeleteIndependentReadProof(Window window, Capture.Binding binding,
        Task<Response<KeyVaultPrivateEndpointConnectionResource>> nativeTask, StatusPrivateConnectionFacts? facts,
        int httpStatus, string? errorCode, string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt, PrivateConnectionOptional? errorMessage,
        StatusPrivateConnectionDeleteIndependentReadPhase phase)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal Task<Response<KeyVaultPrivateEndpointConnectionResource>> NativeTask { get; } = nativeTask;
        internal StatusPrivateConnectionFacts? Facts { get; } = facts;
        internal int HttpStatus { get; } = httpStatus;
        internal string? ErrorCode { get; } = errorCode;
        internal PrivateConnectionOptional? ErrorMessage { get; } = errorMessage;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal StatusPrivateConnectionDeleteIndependentReadPhase Phase { get; } = phase;
        public override string ToString() => "[StatusPrivateConnectionDeleteIndependentReadProof]";
    }
    private readonly Dictionary<Window, StatusPrivateConnectionDeleteIndependentReadPhase> statusPrivateDeleteIndependentReads =
        new(ReferenceEqualityComparer.Instance);

    internal enum StatusDeniedPrivateConnectionDeleteReadPhase { Discovery, Baseline, SelectedState, Cleanup }

    internal sealed class StatusDeniedPrivateConnectionDeleteReadProof(Window window, Capture.Binding binding,
        Task<Response<KeyVaultPrivateEndpointConnectionResource>> nativeTask, StatusPrivateConnectionFacts? facts,
        int httpStatus, string? errorCode, string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt, PrivateConnectionOptional? errorMessage,
        StatusDeniedPrivateConnectionDeleteReadPhase phase)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal Task<Response<KeyVaultPrivateEndpointConnectionResource>> NativeTask { get; } = nativeTask;
        internal StatusPrivateConnectionFacts? Facts { get; } = facts;
        internal int HttpStatus { get; } = httpStatus;
        internal string? ErrorCode { get; } = errorCode;
        internal PrivateConnectionOptional? ErrorMessage { get; } = errorMessage;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal StatusDeniedPrivateConnectionDeleteReadPhase Phase { get; } = phase;
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteReadProof]";
    }
    private sealed class StatusDeniedPrivateConnectionDeleteReadRegistration(StatusDeniedPrivateConnectionDeleteReadPhase phase)
    {
        internal readonly StatusDeniedPrivateConnectionDeleteReadPhase Phase = phase;
        internal CancellationToken[] Tokens = [];
        internal StatusDeniedPrivateConnectionDeleteReadProof? Proof;
    }
    private readonly Dictionary<Window, StatusDeniedPrivateConnectionDeleteReadRegistration> statusDeniedPrivateDeleteReads =
        new(ReferenceEqualityComparer.Instance);

    internal Window ArmStatusDeniedPrivateConnectionDelete(Capture.Binding binding,
        StatusDeniedPrivateConnectionDeleteReadPhase phase)
    {
        Require(binding is not null && binding.Selector is not null &&
            binding.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
            binding.Selector.Variant == "operation.DeletePrivateConnection" &&
            binding.Selector.Case == "denied-authority" &&
            binding.Operation == ManagementMutation.DeletePrivateConnection && binding.Resource is PrivateConnectionScope &&
            binding.ApiRevision == "2026-02-01" && Enum.IsDefined(phase));
        return ArmPrivateRead(binding, false, null, deniedPrivateDeletePhase: phase);
    }

    internal bool TryGetStatusDeniedPrivateConnectionDeleteRead(Window window, Capture.Binding binding,
        Task<Measurement> readTask, [NotNullWhen(true)] out StatusDeniedPrivateConnectionDeleteReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusDeniedPrivateDeleteReads.TryGetValue(window, out var selected) ||
                !windows.TryGetValue(window, out var registration) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(registration.Task, readTask) ||
                !readTask.IsCompletedSuccessfully) return false;
            if (selected.Tokens.Any(t => t.IsCancellationRequested)) selected.Proof = null;
            if (selected.Proof is null || selected.Proof.Phase != selected.Phase) return false;
            proof = selected.Proof;
            return true;
        }
    }

    internal bool OwnsStatusDeniedPrivateConnectionDeleteRead(StatusDeniedPrivateConnectionDeleteReadProof proof,
        Window window, Capture.Binding binding, Task<Measurement> readTask) =>
        TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, readTask, out var issued) &&
        ReferenceEquals(issued, proof);

    internal enum StatusPrivateConnectionUpdateIndependentReadPhase { Discovery, Baseline, SelectedState, BeforeEndpointDelete, Cleanup }

    internal sealed class StatusPrivateConnectionUpdateIndependentReadProof(Window window, Capture.Binding binding,
        Task<Response<KeyVaultPrivateEndpointConnectionResource>> nativeTask, StatusPrivateConnectionFacts? facts,
        int httpStatus, string? errorCode, string requestSha256, string responseSha256, string nativeRequestId,
        DateTimeOffset startedAt, DateTimeOffset finishedAt, PrivateConnectionOptional? errorMessage,
        StatusPrivateConnectionUpdateIndependentReadPhase phase)
    {
        internal Window Window { get; } = window;
        internal Capture.Binding Binding { get; } = binding;
        internal Task<Response<KeyVaultPrivateEndpointConnectionResource>> NativeTask { get; } = nativeTask;
        internal StatusPrivateConnectionFacts? Facts { get; } = facts;
        internal int HttpStatus { get; } = httpStatus;
        internal string? ErrorCode { get; } = errorCode;
        internal PrivateConnectionOptional? ErrorMessage { get; } = errorMessage;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        internal StatusPrivateConnectionUpdateIndependentReadPhase Phase { get; } = phase;
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentReadProof]";
    }
    private readonly Dictionary<Window, StatusPrivateConnectionUpdateIndependentReadPhase> statusPrivateUpdateIndependentReads =
        new(ReferenceEqualityComparer.Instance);


    internal Window ArmStatusPrivateConnectionUpdateIndependent(Capture.Binding binding, StatusPrivateConnectionUpdateIndependentReadPhase phase)
    {
        Require(binding is not null && VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.UpdatePrivateConnection && binding.Resource is PrivateConnectionScope &&
            binding.ApiRevision == "2026-02-01" && Enum.IsDefined(phase));
        return ArmPrivateRead(binding, false, null, phase);
    }

    internal bool TryGetStatusPrivateConnectionUpdateIndependentRead(Window window, Capture.Binding binding,
        Task<Measurement> readTask, [NotNullWhen(true)] out StatusPrivateConnectionUpdateIndependentReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusPrivateUpdateIndependentReads.TryGetValue(window, out var phase) ||
                !windows.TryGetValue(window, out var r) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Task, readTask) ||
                !readTask.IsCompletedSuccessfully || r.IndependentUpdateProof is null || r.PrivateUpdateTokens.Any(t => t.IsCancellationRequested) || r.IndependentUpdateProof.Phase != phase) return false;
            proof = r.IndependentUpdateProof;
            return true;
        }
    }

    internal bool OwnsStatusPrivateConnectionUpdateIndependentRead(StatusPrivateConnectionUpdateIndependentReadProof proof,
        Window window, Capture.Binding binding, Task<Measurement> readTask) =>
        TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, readTask, out var issued) &&
        ReferenceEquals(issued, proof);
    private readonly Authority authority;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly Guid tenantId;
    private readonly object gate = new();
    private readonly Dictionary<Window, Registration> windows = [];
    private readonly HashSet<Guid> nonces = [], leases = [];

    // The expected tenant is host-selected, not inferred from a label, token or
    // selected client's success. Credential and transport remain borrowed.
    internal ManagementOperationResourceCollector(Authority authority, Limits limits, TimeProvider time, Guid tenantId)
    {
        if (authority is null || authority.Credential is null || authority.Transport is null ||
            !TextValue(authority.Label, 128) || limits is null || time is null || tenantId == Guid.Empty ||
            limits.MaximumResponseBytes is < 1024 or > 1024 * 1024 ||
            limits.MaximumRowBytes < 256 || limits.MaximumRowBytes > limits.MaximumResponseBytes ||
            limits.MaximumNodes is < 8 or > 65536 || limits.MaximumRows is < 1 or > 4096 ||
            limits.MaximumDepth is < 2 or > 32 ||
            limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("management-resource-input");
        this.authority = authority;
        this.limits = limits;
        this.time = time;
        this.tenantId = tenantId;
    }

    internal Window Arm(Capture.Binding binding, bool statusPrivateDeleteSelectedProfile = false) =>
        ArmPrivateRead(binding, statusPrivateDeleteSelectedProfile, null);

    internal Window ArmStatusPrivateConnectionDeleteIndependent(Capture.Binding binding,
        StatusPrivateConnectionDeleteIndependentReadPhase phase)
    {
        Require(binding is not null && VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.DeletePrivateConnection && binding.Resource is PrivateConnectionScope &&
            binding.ApiRevision == "2026-02-01" && Enum.IsDefined(phase));
        return ArmPrivateRead(binding, false, phase);
    }

    private Window ArmPrivateRead(Capture.Binding binding, bool statusPrivateDeleteSelectedProfile,
        StatusPrivateConnectionDeleteIndependentReadPhase? independentPhase,
        StatusPrivateConnectionUpdateIndependentReadPhase? independentUpdatePhase = null,
        StatusDeniedPrivateConnectionDeleteReadPhase? deniedPrivateDeletePhase = null)
    {
        try { ValidateBinding(binding); }
        catch (Exception) { throw new ArgumentException("management-resource-binding"); }
        Require(!statusPrivateDeleteSelectedProfile ||
            VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(binding.Selector));
        bool privateCancellation = VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(binding.Selector) ||
            VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(binding.Selector) ||
            statusPrivateDeleteSelectedProfile || independentPhase is not null || independentUpdatePhase is not null ||
            deniedPrivateDeletePhase is not null;
        DateTimeOffset armedAt = privateCancellation ? time.GetUtcNow() : default;
        long timestamp = privateCancellation ? time.GetTimestamp() : 0;
        lock (gate)
        {
            if (windows.Count >= 32 || nonces.Contains(binding.Selector.Nonce) || leases.Contains(binding.LeaseId))
                throw new InvalidOperationException("management-resource-window");
            var window = Window.Create(binding, privateCancellation ? armedAt : time.GetUtcNow(),
                statusPrivateDeleteSelectedProfile);
            windows.Add(window, new(privateCancellation ? timestamp : time.GetTimestamp()));
            if (independentPhase is { } phase) statusPrivateDeleteIndependentReads.Add(window, phase);
            if (independentUpdatePhase is { } updatePhase) statusPrivateUpdateIndependentReads.Add(window, updatePhase);
            if (deniedPrivateDeletePhase is { } deniedPhase) statusDeniedPrivateDeleteReads.Add(window, new(deniedPhase));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            return window;
        }
    }

    internal ValueTask<Measurement> CollectAsync(Window window, Capture.Binding binding,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null)
    {
        TaskCompletionSource? admitted = null;
        Task<Measurement>? selectedTask = null;
        lock (gate)
        {
            if (statusDeniedVaultRecoverReads.TryGetValue(window, out var vaultRecover))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding) &&
                    ReferenceEquals(vaultRecover.Resource, binding.Resource));
                registration.Consumed = true;
                vaultRecover.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectStatusDeniedVaultRecoverAsync(window, binding,
                    registration, vaultRecover, admitted.Task);
            }
            else if (statusDeniedVaultUpdateReads.TryGetValue(window, out var vaultUpdate))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                vaultUpdate.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectStatusDeniedVaultUpdateAsync(window, binding,
                    registration, vaultUpdate, admitted.Task);
            }
            else if (statusDeniedReads.TryGetValue(window, out var denied))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                denied.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, denied.Run, admitted.Task);
            }
            else if (statusPendingReads.TryGetValue(window, out var pending))
            {
                // Foreign preflight never consumes the registered phase.
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                pending.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, pending.Run, admitted.Task);
            }
            else if (statusPendingIndependentReads.TryGetValue(window, out var pendingIndependent))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                pendingIndependent.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, pendingIndependent.Run, admitted.Task);
            }
            else if (statusPendingCancellationReads.TryGetValue(window, out var pendingCancellation))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                pendingCancellation.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, pendingCancellation.Run, admitted.Task);
            }
            else if (statusFailedReads.TryGetValue(window, out var failed))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                failed.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, failed.Run, admitted.Task);
            }
            else if (statusFailedIndependentReads.TryGetValue(window, out var failedIndependent))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                failedIndependent.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, failedIndependent.Run, admitted.Task);
            }
            else if (statusFailedCancellationReads.TryGetValue(window, out var failedCancellation))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                failedCancellation.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, failedCancellation.Run, admitted.Task);
            }
            else if (statusCanceledReads.TryGetValue(window, out var canceled))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                canceled.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, canceled.Run, admitted.Task);
            }
            else if (statusCanceledIndependentReads.TryGetValue(window, out var canceledIndependent))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                canceledIndependent.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, canceledIndependent.Run, admitted.Task);
            }
            else if (statusCanceledCancellationReads.TryGetValue(window, out var canceledCancellation))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                canceledCancellation.Run.Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectPurgeReadAsync(window, binding,
                    registration, canceledCancellation.Run, admitted.Task);
            }
            else if (statusSucceededReads.TryGetValue(window, out var selected))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectStatusSucceededDeleteVaultAsync(window, binding,
                    registration, selected, admitted.Task, cancellationToken);
            }
            else if (statusSucceededIndependentReads.TryGetValue(window, out var independentSelected))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectStatusSucceededDeleteVaultIndependentAsync(window, binding,
                    registration, independentSelected, admitted.Task, cancellationToken);
            }
            else if (statusSucceededCancellationReads.TryGetValue(window, out var cancellationSelected))
            {
                Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                    registration.Task is null && ReferenceEquals(window.Binding, binding));
                registration.Consumed = true;
                admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
                selectedTask = registration.Task = CollectStatusSucceededDeleteVaultCancellationAsync(window, binding,
                    registration, cancellationSelected, admitted.Task, cancellationToken);
            }
        }
        if (admitted is not null) { admitted.SetResult(); return new(selectedTask!); }
        bool independentPrivateDelete, independentPrivateUpdate, deniedPrivateDelete;
        lock (gate)
        {
            independentPrivateDelete = statusPrivateDeleteIndependentReads.ContainsKey(window);
            independentPrivateUpdate = statusPrivateUpdateIndependentReads.ContainsKey(window);
            deniedPrivateDelete = statusDeniedPrivateDeleteReads.ContainsKey(window);
        }
        if (!independentPrivateDelete && !independentPrivateUpdate && !deniedPrivateDelete &&
            !VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(binding.Selector) &&
            !VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(binding.Selector) &&
            !window.StatusPrivateDeleteSelectedProfile)
            return CollectCoreAsync(window, binding, cancellationToken);
        TaskCompletionSource start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<Measurement> task;
        lock (gate)
        {
            Require(windows.TryGetValue(window, out var registration) && !registration.Consumed &&
                registration.Task is null && ReferenceEquals(window.Binding, binding));
            registration.Consumed = true;
            if (independentPrivateUpdate) registration.PrivateUpdateTokens = [cancellationToken, originalCallerToken ?? cancellationToken];
            if (deniedPrivateDelete)
                statusDeniedPrivateDeleteReads[window].Tokens = [cancellationToken, originalCallerToken ?? cancellationToken];
            task = registration.Task = CollectPrivateReadAsync(window, binding, registration, start.Task, cancellationToken);
        }
        start.SetResult();
        return new(task);
    }

    internal bool TryGetStatusPrivateConnectionUpdateRead(Window window, Capture.Binding binding,
        Task<Measurement> readTask, [NotNullWhen(true)] out StatusPrivateConnectionUpdateReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!windows.TryGetValue(window, out var r) || !ReferenceEquals(window.Binding, binding) ||
                !ReferenceEquals(r.Task, readTask) || !readTask.IsCompletedSuccessfully || r.Proof is null) return false;
            proof = r.Proof;
            return true;
        }
    }

    internal bool OwnsStatusPrivateConnectionUpdateRead(StatusPrivateConnectionUpdateReadProof proof,
        Window window, Capture.Binding binding, Task<Measurement> readTask) =>
        TryGetStatusPrivateConnectionUpdateRead(window, binding, readTask, out var issued) &&
        ReferenceEquals(issued, proof);

    internal bool TryGetStatusPrivateConnectionDeleteRead(Window window, Capture.Binding binding,
        Task<Measurement> readTask, [NotNullWhen(true)] out StatusPrivateConnectionDeleteReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var r) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Task, readTask) ||
                !readTask.IsCompletedSuccessfully || r.DeleteProof is null) return false;
            proof = r.DeleteProof;
            return true;
        }
    }

    internal bool OwnsStatusPrivateConnectionDeleteRead(StatusPrivateConnectionDeleteReadProof proof,
        Window window, Capture.Binding binding, Task<Measurement> readTask) =>
        TryGetStatusPrivateConnectionDeleteRead(window, binding, readTask, out var issued) &&
        ReferenceEquals(issued, proof);

    internal bool TryGetStatusPrivateConnectionDeleteSelectedRead(Window window, Capture.Binding binding,
        Task<Measurement> readTask, [NotNullWhen(true)] out StatusPrivateConnectionDeleteSelectedReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !windows.TryGetValue(window, out var r) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Task, readTask) ||
                !readTask.IsCompletedSuccessfully || r.SelectedDeleteProof is null) return false;
            proof = r.SelectedDeleteProof;
            return true;
        }
    }

    internal bool OwnsStatusPrivateConnectionDeleteSelectedRead(StatusPrivateConnectionDeleteSelectedReadProof proof,
        Window window, Capture.Binding binding, Task<Measurement> readTask) =>
        TryGetStatusPrivateConnectionDeleteSelectedRead(window, binding, readTask, out var issued) &&
        ReferenceEquals(issued, proof);

    internal bool TryGetStatusPrivateConnectionDeleteIndependentRead(Window window, Capture.Binding binding,
        Task<Measurement> readTask, [NotNullWhen(true)] out StatusPrivateConnectionDeleteIndependentReadProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusPrivateDeleteIndependentReads.TryGetValue(window, out var phase) ||
                !windows.TryGetValue(window, out var r) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Task, readTask) ||
                !readTask.IsCompletedSuccessfully || r.IndependentDeleteProof is null || r.IndependentDeleteProof.Phase != phase) return false;
            proof = r.IndependentDeleteProof;
            return true;
        }
    }

    internal bool OwnsStatusPrivateConnectionDeleteIndependentRead(StatusPrivateConnectionDeleteIndependentReadProof proof,
        Window window, Capture.Binding binding, Task<Measurement> readTask) =>
        TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, readTask, out var issued) &&
        ReferenceEquals(issued, proof);

    private async Task<Measurement> CollectPrivateReadAsync(Window window, Capture.Binding binding,
        Registration registration, Task start, CancellationToken token)
    {
        await start.ConfigureAwait(false);
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        budget.Check();
        DateTimeOffset started = budget.ObservedAt;
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        var read = new PrivateRead();
        bool independentDelete, independentUpdate;
        StatusPrivateConnectionDeleteIndependentReadPhase independentPhase;
        StatusPrivateConnectionUpdateIndependentReadPhase updatePhase;
        StatusDeniedPrivateConnectionDeleteReadRegistration? deniedPrivateDelete;
        lock (gate)
        {
            independentDelete = statusPrivateDeleteIndependentReads.TryGetValue(window, out independentPhase);
            independentUpdate = statusPrivateUpdateIndependentReads.TryGetValue(window, out updatePhase);
            statusDeniedPrivateDeleteReads.TryGetValue(window, out deniedPrivateDelete);
        }
        bool selectedDelete = window.StatusPrivateDeleteSelectedProfile;
        bool delete = deniedPrivateDelete is not null || independentDelete || selectedDelete ||
            VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(binding.Selector);
        StatusPrivateConnectionFacts? facts = null;
        Failure failure = Failure.Unavailable;
        SecretStatus outcome = SecretStatus.Unavailable;
        int? status = null;
        string? requestId = null, responseHash = null, errorCode = null;
        PrivateConnectionOptional? errorMessage = null;
        bool disposed = false;
        try
        {
            Require(binding.Resource is PrivateConnectionScope && registration.PrivateUpdateTokens.All(t => !t.IsCancellationRequested));
            Require(deniedPrivateDelete is null || deniedPrivateDelete.Tokens.All(t => !t.IsCancellationRequested));
            var uri = new Uri(ArmOrigin + Path(binding.Resource) + "?api-version=" + binding.ApiRevision);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(ArmOrigin), ArmOrigin),
                Transport = new ReadTransport(authority.Transport, uri, budget, read, limits.MaximumResponseBytes)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion("Microsoft.KeyVault/vaults/privateEndpointConnections", binding.ApiRevision);
            var client = new ArmClient(new ObserverCredential(authority.Credential, budget), null, options);
            read.NativeTask = client.GetKeyVaultPrivateEndpointConnectionResource(new ResourceIdentifier(Path(binding.Resource)))
                .GetAsync(cancellationToken: linked.Token);
            Response<KeyVaultPrivateEndpointConnectionResource>? native = null;
            RequestFailedException? error = null;
            try { native = await read.NativeTask.ConfigureAwait(false); }
            catch (RequestFailedException exception) { error = exception; }
            if (read.Send is not null) await read.Send.ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            Require(read.Body is not null && read.Parser is { Complete: true, Invalid: false });
            status = read.Body.Response.Status;
            requestId = read.Body.NativeRequestId;
            responseHash = read.Body.Sha256;
            _ = ResponseHeaders(read.Body.Response, out _);
            Require(read.Body.Bytes.Length <= limits.MaximumRowBytes);
            Shape(read.Body.Bytes.Span);
            using var json = JsonDocument.Parse(read.Body.Bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            if (status == 200)
            {
                Require(native is not null && error is null && read.Parser.Owns(native.GetRawResponse()));
                facts = ValidateStatusPrivateConnectionResource(json.RootElement, native.Value.Data,
                    (PrivateConnectionScope)binding.Resource, binding.Location, allowLocation: true);
                Require(delete ? facts.State == "Pending" : facts.State is "Pending" or "Approved");
                outcome = SecretStatus.Success;
            }
            else
            {
                var root = json.RootElement;
                Require(status == 404 && native is null && error is { Status: 404 } &&
                    Only(root, "error") && root.EnumerateObject().Count() == 1);
                var fault = Object(root, "error");
                errorCode = Text(fault, "code");
                Require(Only(fault, "code", "message") && error.ErrorCode == errorCode &&
                    (delete ? errorCode is "NotFound" or "ResourceNotFound" : errorCode == "NotFound"));
                if (delete && fault.TryGetProperty("message", out var message))
                    Require(message.ValueKind == JsonValueKind.String);
                errorMessage = PrivateOptional(fault, "message");
                outcome = SecretStatus.Absent;
            }
            read.Storage.Dispose();
            disposed = true;
            Require(read.Parser is { Complete: true, Invalid: false });
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            Require(!independentDelete || (independentPhase == StatusPrivateConnectionDeleteIndependentReadPhase.Baseline
                ? status == 200 && facts is { State: "Pending", Provisioning: "Succeeded" }
                : status == 404 && facts is null && errorCode is "NotFound" or "ResourceNotFound"));
            Require(registration.PrivateUpdateTokens.All(t => !t.IsCancellationRequested));
            Require(deniedPrivateDelete is null || deniedPrivateDelete.Tokens.All(t => !t.IsCancellationRequested) &&
                (deniedPrivateDelete.Phase switch
                {
                    StatusDeniedPrivateConnectionDeleteReadPhase.Discovery or StatusDeniedPrivateConnectionDeleteReadPhase.Baseline =>
                        status == 200 && facts is { State: "Pending", Provisioning: "Succeeded" } &&
                        read.NativeTask.IsCompletedSuccessfully,
                    StatusDeniedPrivateConnectionDeleteReadPhase.SelectedState or StatusDeniedPrivateConnectionDeleteReadPhase.Cleanup =>
                        status == 404 && facts is null && errorCode is "NotFound" or "ResourceNotFound" &&
                        read.NativeTask.IsFaulted,
                    _ => false
                }));
            Require(!independentUpdate || (updatePhase switch
            {
                StatusPrivateConnectionUpdateIndependentReadPhase.Discovery or StatusPrivateConnectionUpdateIndependentReadPhase.Baseline =>
                    status == 200 && facts is { State: "Pending", Provisioning: "Succeeded" },
                StatusPrivateConnectionUpdateIndependentReadPhase.SelectedState =>
                    status == 200 && facts is { State: "Approved", Provisioning: "Succeeded" },
                StatusPrivateConnectionUpdateIndependentReadPhase.BeforeEndpointDelete =>
                    status == 200 && facts is { State: "Pending" or "Approved", Provisioning: "Succeeded" },
                StatusPrivateConnectionUpdateIndependentReadPhase.Cleanup => status == 404 && facts is null && errorCode == "NotFound",
                _ => false
            }));
            failure = Failure.None;
            if (deniedPrivateDelete is not null)
            {
                var proof = new StatusDeniedPrivateConnectionDeleteReadProof(window, binding, read.NativeTask, facts,
                    status.Value, errorCode, read.RequestSha256!, responseHash, requestId, started, budget.ObservedAt,
                    errorMessage, deniedPrivateDelete.Phase);
                lock (gate)
                {
                    Require(deniedPrivateDelete.Proof is null &&
                        deniedPrivateDelete.Tokens.All(t => !t.IsCancellationRequested));
                    deniedPrivateDelete.Proof = proof;
                }
            }
            else if (independentUpdate)
            {
                var proof = new StatusPrivateConnectionUpdateIndependentReadProof(window, binding, read.NativeTask, facts,
                    status.Value, errorCode, read.RequestSha256!, responseHash, requestId, started, budget.ObservedAt,
                    errorMessage, updatePhase);
                lock (gate) registration.IndependentUpdateProof = proof;
            }
            else if (independentDelete)
            {
                var proof = new StatusPrivateConnectionDeleteIndependentReadProof(window, binding, read.NativeTask, facts,
                    status.Value, errorCode, read.RequestSha256!, responseHash, requestId, started, budget.ObservedAt,
                    errorMessage, independentPhase);
                lock (gate) registration.IndependentDeleteProof = proof;
            }
            else if (selectedDelete)
            {
                var proof = new StatusPrivateConnectionDeleteSelectedReadProof(window, binding, read.NativeTask, facts,
                    status.Value, errorCode, read.RequestSha256!, responseHash, requestId, started, budget.ObservedAt,
                    errorMessage);
                lock (gate) registration.SelectedDeleteProof = proof;
            }
            else if (delete)
            {
                var proof = new StatusPrivateConnectionDeleteReadProof(window, binding, read.NativeTask, facts,
                    status.Value, errorCode, read.RequestSha256!, responseHash, requestId, started, budget.ObservedAt,
                    errorMessage);
                lock (gate) registration.DeleteProof = proof;
            }
            else
            {
                var proof = new StatusPrivateConnectionUpdateReadProof(window, binding, read.NativeTask, facts,
                    status.Value, read.RequestSha256!, responseHash, requestId, started, budget.ObservedAt);
                lock (gate) registration.Proof = proof;
            }
        }
        catch (Exception exception)
        {
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
            failure = deadline.IsCancellationRequested ? Failure.Deadline :
                exception is Boundary b ? b.Reason : Failure.Unavailable;
            outcome = SecretStatus.Unavailable;
            facts = null;
        }
        finally
        {
            // Actual native and transport work has ended before any host
            // response, parser stream, or captured storage is released.
            if (read.NativeTask is not null)
                try { await read.NativeTask.ConfigureAwait(false); } catch (Exception) { }
            if (read.Send is not null)
                try { await read.Send.ConfigureAwait(false); } catch (Exception) { }
            if (!disposed)
                try { read.Storage.Dispose(); }
                catch (Exception)
                {
                    failure = Failure.Unavailable;
                    outcome = SecretStatus.Unavailable;
                    facts = null;
                    lock (gate)
                    {
                        registration.Proof = null;
                        registration.DeleteProof = null;
                        registration.SelectedDeleteProof = null;
                        registration.IndependentDeleteProof = null;
                        registration.IndependentUpdateProof = null;
                        if (deniedPrivateDelete is not null) deniedPrivateDelete.Proof = null;
                    }
                }
        }
        return new()
        {
            Binding = binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = budget.ObservedAt,
            Identity = authority.Label,
            Failure = failure,
            ResourceStatus = outcome,
            HttpStatus = status,
            NativeRequestId = requestId,
            ResourceId = facts?.Id,
            ResourceName = facts?.Name,
            ResourceType = facts?.Type,
            NativeState = facts?.Provisioning,
            PrivateEndpointId = facts?.EndpointId,
            ConnectionState = facts is null ? null : Enum.Parse<PrivateConnectionState>(facts.State),
            Topic = null,
            EventTypes = [],
            VaultConfiguration = null,
            NotificationConfiguration = null,
            DeletedVault = null,
            RoleAssignment = null,
            PersistedStateEligible = facts is not null
        };
    }

    internal static StatusPrivateConnectionFacts ValidateStatusPrivateConnectionResource(JsonElement root,
        KeyVaultPrivateEndpointConnectionData native, PrivateConnectionScope scope, string location, bool allowLocation)
    {
        Require(Only(root, allowLocation
            ? ["id", "name", "type", "location", "tags", "etag", "systemData", "properties"]
            : ["id", "name", "type", "etag", "systemData", "properties"]));
        string id = Text(root, "id"), name = Text(root, "name"), type = Text(root, "type");
        Require(id == Path(scope) && name == scope.ConnectionName && type == Type(scope) &&
            native.Id?.ToString() == id && native.Name == name && native.ResourceType.ToString() == type);
        var properties = Object(root, "properties");
        Require(Only(properties, "provisioningState", "privateEndpoint", "privateLinkServiceConnectionState"));
        string provisioning = Text(properties, "provisioningState");
        var endpoint = Object(properties, "privateEndpoint");
        Require(Only(endpoint, "id"));
        string endpointId = Text(endpoint, "id");
        string[] parts = endpointId.Split('/');
        Require(parts.Length == 9 && parts[0].Length == 0 && Same(parts[1], "subscriptions") &&
            Guid.TryParseExact(parts[2], "D", out var subscription) && subscription != Guid.Empty &&
            Same(parts[3], "resourceGroups") && Segment(parts[4], 90) && Same(parts[5], "providers") &&
            Same(parts[6], "Microsoft.Network") && Same(parts[7], "privateEndpoints") && Segment(parts[8], 256));
        var connection = Object(properties, "privateLinkServiceConnectionState");
        Require(Only(connection, "status", "description", "actionsRequired"));
        string state = Text(connection, "status");
        var description = PrivateOptional(connection, "description");
        var actions = PrivateOptional(connection, "actionsRequired");
        var region = PrivateOptional(root, "location");
        var etag = PrivateOptional(root, "etag");
        Require(provisioning == "Succeeded" && native.ProvisioningState?.ToString() == provisioning &&
            native.PrivateEndpointId?.ToString() == endpointId && native.ConnectionState?.Status?.ToString() == state &&
            native.ConnectionState.Description == description.Value &&
            native.ConnectionState.ActionsRequired?.ToString() == actions.Value &&
            native.ETag?.ToString() == etag.Value &&
            (region.Value is null ? string.IsNullOrEmpty(native.Location?.Name) :
                Same(region.Value, location) && native.Location?.Name == region.Value));
        string tagsPresence = root.TryGetProperty("tags", out var tags) ? tags.ValueKind == JsonValueKind.Null ? "null" : "value" : "missing";
        var frozenTags = new Dictionary<string, string>(StringComparer.Ordinal);
        if (tagsPresence == "value")
        {
            Require(tags.ValueKind == JsonValueKind.Object && tags.EnumerateObject().Count() <= 64);
            foreach (var tag in tags.EnumerateObject())
            {
                Require(TextValue(tag.Name, 512) && tag.Value.ValueKind == JsonValueKind.String);
                string value = tag.Value.GetString()!;
                Require(value.Length <= 4096 && !value.Any(char.IsControl) && frozenTags.TryAdd(tag.Name, value));
            }
        }
        Require(native.Tags.Count == frozenTags.Count &&
            frozenTags.All(t => native.Tags.TryGetValue(t.Key, out var value) && value == t.Value));
        string systemPresence = root.TryGetProperty("systemData", out var system)
            ? system.ValueKind == JsonValueKind.Null ? "null" : "value" : "missing";
        string[] fields = ["createdBy", "createdByType", "createdAt", "lastModifiedBy", "lastModifiedByType", "lastModifiedAt"];
        var frozenSystem = new Dictionary<string, PrivateConnectionOptional>(StringComparer.Ordinal);
        if (systemPresence == "value")
        {
            Require(Only(system, fields) && native.SystemData is not null);
            foreach (string field in fields) frozenSystem.Add(field, PrivateOptional(system, field));
            Require(native.SystemData.CreatedBy == frozenSystem["createdBy"].Value &&
                native.SystemData.LastModifiedBy == frozenSystem["lastModifiedBy"].Value &&
                native.SystemData.CreatedByType?.ToString() == frozenSystem["createdByType"].Value &&
                native.SystemData.LastModifiedByType?.ToString() == frozenSystem["lastModifiedByType"].Value);
            foreach (string field in new[] { "createdByType", "lastModifiedByType" })
                Require(frozenSystem[field].Value is null or "User" or "Application" or "ManagedIdentity" or "Key");
            Require(native.SystemData.CreatedOn == PrivateDate(frozenSystem["createdAt"]) &&
                native.SystemData.LastModifiedOn == PrivateDate(frozenSystem["lastModifiedAt"]));
        }
        else Require(native.SystemData is null);
        return new(id, name, type, endpointId, state, provisioning, region, etag, description, actions,
            tagsPresence, new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(frozenTags),
            systemPresence, new System.Collections.ObjectModel.ReadOnlyDictionary<string, PrivateConnectionOptional>(frozenSystem));
    }

    private static PrivateConnectionOptional PrivateOptional(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value)) return new("missing", null);
        if (value.ValueKind == JsonValueKind.Null) return new("null", null);
        Require(value.ValueKind == JsonValueKind.String);
        string text = value.GetString()!;
        Require(text.Length <= 4096 && !text.Any(char.IsControl));
        return new("value", text);
    }

    private static DateTimeOffset? PrivateDate(PrivateConnectionOptional value)
    {
        if (value.Value is null) return null;
        Require(DateTimeOffset.TryParse(value.Value, CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out var date));
        return date;
    }

    private async ValueTask<Measurement> CollectCoreAsync(Window window, Capture.Binding binding,
        CancellationToken cancellationToken = default)
    {
        Registration registration;
        lock (gate)
        {
            if (window is null || !windows.TryGetValue(window, out var found) || found.Consumed || window.Binding != binding)
                throw new InvalidOperationException("management-resource-window");
            registration = found;
            registration.Consumed = true;
        }
        cancellationToken.ThrowIfCancellationRequested();
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        DateTimeOffset started = window.ArmedAt;
        int? status = null;
        string? requestId = null, id = null, name = null, type = null, nativeState = null, topic = null, privateEndpoint = null;
        string[] events = [];
        VaultConfiguration? vault = null;
        NotificationConfiguration? notification = null;
        PrivateConnectionState? connection = null;
        DeletedVault? deleted = null;
        RoleAssignment? assignment = null;
        bool eligible = false;
        try { budget.Check(); started = budget.ObservedAt; }
        catch (Boundary b) { return Finish(b.Reason, SecretStatus.Unavailable); }
        using var deadline = new CancellationTokenSource(budget.Remaining, time);
        budget.Deadline = deadline;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        byte[] storage = new byte[limits.MaximumResponseBytes + 1];
        bool updateCancellation = VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(binding.Selector);
        try
        {
            var uri = new Uri(ArmOrigin + Path(binding.Resource) + "?api-version=" + binding.ApiRevision);
            var options = new ArmClientOptions { Transport = new ReadTransport(authority.Transport, uri, budget) };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            var pipeline = HttpPipelineBuilder.Build(options,
                new BearerTokenAuthenticationPolicy(new ObserverCredential(authority.Credential, budget), ArmOrigin + "/.default"));
            using var message = pipeline.CreateMessage();
            message.BufferResponse = false;
            message.Request.Method = RequestMethod.Get;
            message.Request.Uri.Reset(uri);
            await pipeline.SendAsync(message, linked.Token).ConfigureAwait(false);
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            var response = message.Response;
            var originalRequest = message.Request;
            var originalHeaders = updateCancellation ? response.Headers.ToArray() : [];
            var originalRequestHeaders = updateCancellation ? message.Request.Headers.ToArray() : [];
            status = response.Status;
            long? length = ResponseHeaders(response, out requestId);
            if (length > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
            int count = 0;
            var input = response.ContentStream;
            if (input is not null)
                while (true)
                {
                    budget.Check();
                    int read = await input.ReadAsync(storage.AsMemory(count), linked.Token).ConfigureAwait(false);
                    budget.Check();
                    linked.Token.ThrowIfCancellationRequested();
                    if (read == 0) break;
                    count += read;
                    if (count > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
                }
            if (updateCancellation)
                Require(ReferenceEquals(message.Response, response) && ReferenceEquals(response.ContentStream, input) &&
                    ReferenceEquals(message.Request, originalRequest) && response.Status == status &&
                    originalHeaders.SequenceEqual(response.Headers) &&
                    originalRequestHeaders.SequenceEqual(message.Request.Headers) &&
                    message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                    message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri);
            Require(count > 0 && (length is null || length == count));
            if (count > limits.MaximumRowBytes) throw new Boundary(Failure.Budget);
            Shape(storage.AsSpan(0, count));
            using var document = JsonDocument.Parse(storage.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            var root = document.RootElement;
            Require(root.ValueKind == JsonValueKind.Object);
            if (status != 200)
            {
                Require(status >= 400 && root.EnumerateObject().Count() == 1 && root.TryGetProperty("error", out _));
                Error(root.GetProperty("error"));
                if (status is 401 or 403) return Finish(Failure.Denied, SecretStatus.Denied);
                if (status == 404)
                {
                    if (binding.Resource is PrivateConnectionScope)
                        Require(Text(root.GetProperty("error"), "code") is "ResourceNotFound" or "NotFound");
                    if (updateCancellation || VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(binding.Selector))
                        RecoveryAbsence(root.GetProperty("error"));
                    return Finish(Failure.None, SecretStatus.Absent);
                }
                return Finish(Failure.Unavailable, SecretStatus.Unavailable);
            }
            Require(!root.TryGetProperty("error", out _) && !root.TryGetProperty("errors", out _) &&
                !root.TryGetProperty("partial", out _) && !root.TryGetProperty("nextLink", out _) &&
                !root.TryGetProperty("value", out _) && !root.TryGetProperty("status", out _));
            var properties = Object(root, "properties");
            Require(!properties.TryGetProperty("error", out _) && !properties.TryGetProperty("errors", out _) &&
                !properties.TryGetProperty("status", out _) && !properties.TryGetProperty("partial", out _));
            id = Text(root, "id");
            name = Text(root, "name");
            type = Text(root, "type");
            Require(Same(id, Path(binding.Resource)) && Same(name, id.Split('/')[^1]) &&
                Same(type, Type(binding.Resource)));
            // Exact typed identity, structural and byte bounds precede every
            // installed native model reader. No SecretKit resource projection.
            var bytes = new BinaryData(storage.AsMemory(0, count));
            switch (binding.Resource)
            {
                case VaultScope selected:
                    {
                        Require(Same(Text(root, "location"), binding.Location) &&
                            Identifier(properties, "tenantId") == tenantId);
                        if (properties.TryGetProperty("vaultUri", out var endpoint) && endpoint.ValueKind != JsonValueKind.Null)
                            Require(Uri.TryCreate(String(endpoint), UriKind.Absolute, out var vaultEndpoint) &&
                                vaultEndpoint.IsWellFormedOriginalString() &&
                                Same(vaultEndpoint.AbsoluteUri, "https://" + selected.VaultName + ".vault.azure.net/"));
                        ValidateVault(properties);
                        var native = Native<KeyVaultData>(bytes);
                        Require(Same(native.Id?.ToString(), id) && Same(native.Name, name) &&
                            Same(native.ResourceType.ToString(), type) && Same(native.Location.Name, binding.Location) &&
                            native.Properties.TenantId == tenantId &&
                            native.Properties.EnableRbacAuthorization == Boolean(properties, "enableRbacAuthorization") &&
                            native.Properties.EnablePurgeProtection == Boolean(properties, "enablePurgeProtection") &&
                            native.Properties.EnableSoftDelete == Boolean(properties, "enableSoftDelete") &&
                            Same(native.Properties.CreateMode?.ToString(), OptionalText(properties, "createMode")) &&
                            Same(native.Properties.Sku.Name.ToString(), Text(properties.GetProperty("sku"), "name")) &&
                            Same(native.Properties.Sku.Family.ToString(), Text(properties.GetProperty("sku"), "family")) &&
                            native.Properties.SoftDeleteRetentionInDays ==
                                (properties.TryGetProperty("softDeleteRetentionInDays", out var retention) &&
                                    retention.ValueKind != JsonValueKind.Null ? retention.GetInt32() : (int?)null) &&
                            Same(native.Properties.PublicNetworkAccess, OptionalText(properties, "publicNetworkAccess")));
                        nativeState = OptionalText(properties, "provisioningState");
                        Require(Same(native.Properties.ProvisioningState?.ToString(), nativeState));
                        bool recoveryCancellation = VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(binding.Selector);
                        vault = Vault(properties, binding.Location, recoveryCancellation || updateCancellation);
                        if (recoveryCancellation || updateCancellation)
                        {
                            Require(native.Properties.AccessPolicies.Count == 0 &&
                                properties.GetProperty("accessPolicies").GetArrayLength() == 0 && vault is not null &&
                                native.Tags.Count == 1 && native.Tags.TryGetValue("secretkit-fixture", out var nonce) &&
                                nonce == binding.Selector.Nonce.ToString("N") &&
                                native.Properties.VaultUri == new Uri("https://" + selected.VaultName + ".vault.azure.net"));
                            _ = VaultFixtureProvisioner.ParseOwnedVaultResource(selected.ExportResourceId(),
                                binding.Selector.Nonce, root, new(vault.Location, vault.TenantId, vault.Sku,
                                    vault.Rbac, vault.PurgeProtection, vault.RetentionDays, vault.PublicNetworkAccess, []),
                                "Succeeded", recover: recoveryCancellation);
                            if (updateCancellation)
                            {
                                using var serialized = JsonDocument.Parse(ModelReaderWriter.Write(native).ToMemory());
                                Require(serialized.RootElement.GetProperty("properties")
                                    .GetProperty("privateEndpointConnections") is { ValueKind: JsonValueKind.Array } children &&
                                    children.GetArrayLength() == 0 && vault.CreateMode is null or "default");
                            }
                        }
                        eligible = SettledResource(nativeState) && vault is not null;
                        break;
                    }
                case DeletedVaultScope selected:
                    {
                        Require(Same(Text(properties, "location"), binding.Location));
                        string original = Text(properties, "vaultId");
                        string[] parts = original.Split('/');
                        Require(parts.Length == 9 && parts[0].Length == 0 && Same(parts[1], "subscriptions") &&
                            Same(parts[2], selected.Subscription.SubscriptionId.ToString("D")) && Same(parts[3], "resourceGroups") &&
                            Segment(parts[4], 90) && Same(parts[5], "providers") && Same(parts[6], "Microsoft.KeyVault") &&
                            Same(parts[7], "vaults") && Same(parts[8], selected.VaultName));
                        var deletedOn = Date(properties, "deletionDate");
                        var purgeOn = Date(properties, "scheduledPurgeDate");
                        var purgeProtected = Boolean(properties, "purgeProtectionEnabled");
                        var native = Native<DeletedKeyVaultData>(bytes);
                        Require(Same(native.Id?.ToString(), id) && Same(native.Name, name) &&
                            Same(native.ResourceType.ToString(), type) && native.Properties.DeletedOn == deletedOn &&
                            native.Properties.ScheduledPurgeOn == purgeOn && native.Properties.PurgeProtectionEnabled == purgeProtected);
                        if (updateCancellation || VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(binding.Selector))
                        {
                            var tags = Object(properties, "tags");
                            Require(tags.EnumerateObject().Count() == 1 &&
                                Text(tags, "secretkit-fixture") == binding.Selector.Nonce.ToString("N") &&
                                native.Properties.Tags.Count == 1 &&
                                native.Properties.Tags.TryGetValue("secretkit-fixture", out var nonce) &&
                                nonce == binding.Selector.Nonce.ToString("N") &&
                                native.Properties.VaultId == original && native.Properties.Location == binding.Location &&
                                deletedOn is not null && purgeOn is not null && purgeOn > deletedOn &&
                                purgeProtected == false);
                        }
                        deleted = new(original, deletedOn, purgeOn, purgeProtected);
                        eligible = true;
                        break;
                    }
                case PrivateConnectionScope:
                    {
                        if (properties.TryGetProperty("privateEndpoint", out var endpoint) && endpoint.ValueKind != JsonValueKind.Null)
                        {
                            privateEndpoint = Text(Object(properties, "privateEndpoint"), "id");
                            string[] parts = privateEndpoint.Split('/');
                            Require(parts.Length == 9 && parts[0].Length == 0 && Same(parts[1], "subscriptions") &&
                                Guid.TryParseExact(parts[2], "D", out var subscription) && subscription != Guid.Empty &&
                                Same(parts[3], "resourceGroups") && Segment(parts[4], 90) &&
                                Same(parts[5], "providers") && Same(parts[6], "Microsoft.Network") &&
                                Same(parts[7], "privateEndpoints") && Segment(parts[8], 256));
                        }
                        nativeState = OptionalText(properties, "provisioningState");
                        string? state = null;
                        if (properties.TryGetProperty("privateLinkServiceConnectionState", out var link) && link.ValueKind != JsonValueKind.Null)
                            state = OptionalText(Object(properties, "privateLinkServiceConnectionState"), "status");
                        if (state is "Pending" or "Approved" or "Rejected" or "Disconnected")
                            connection = Enum.Parse<PrivateConnectionState>(state);
                        var native = Native<KeyVaultPrivateEndpointConnectionData>(bytes);
                        Require(Same(native.Id?.ToString(), id) && Same(native.Name, name) &&
                            Same(native.ResourceType.ToString(), type) && Same(native.ConnectionState?.Status?.ToString(), state) &&
                            Same(native.ProvisioningState?.ToString(), nativeState) &&
                            Same(native.PrivateEndpointId?.ToString(), privateEndpoint));
                        eligible = SettledResource(nativeState) && connection is not null;
                        break;
                    }
                case RoleAssignmentScope selected:
                    {
                        string parent = Parent(selected.Parent);
                        Require(Same(Text(properties, "scope"), parent));
                        Guid principal = Identifier(properties, "principalId");
                        string definition = Text(properties, "roleDefinitionId");
                        string subscription = Path(selected).Split('/')[2];
                        string prefix = "/subscriptions/" + subscription + "/providers/Microsoft.Authorization/roleDefinitions/";
                        Require(definition.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                            Guid.TryParseExact(definition[prefix.Length..], "D", out var definitionId) && definitionId != Guid.Empty);
                        string? principalType = OptionalText(properties, "principalType");
                        var native = Native<RoleAssignmentData>(bytes);
                        Require(Same(native.Id?.ToString(), id) && Same(native.Name, name) &&
                            Same(native.ResourceType.ToString(), type) && Same(native.Scope, parent) &&
                            native.PrincipalId == principal && Same(native.RoleDefinitionId?.ToString(), definition) &&
                            Same(native.PrincipalType?.ToString(), principalType));
                        assignment = new(parent, definition, principal, principalType);
                        eligible = true;
                        break;
                    }
                case NotificationScope selected:
                    {
                        topic = Text(properties, "topic");
                        Require(Same(topic, selected.Vault.ExportResourceId()));
                        nativeState = OptionalText(properties, "provisioningState");
                        if (properties.TryGetProperty("filter", out var filter) && filter.ValueKind != JsonValueKind.Null)
                        {
                            Require(filter.ValueKind == JsonValueKind.Object);
                            if (filter.TryGetProperty("includedEventTypes", out var included) && included.ValueKind != JsonValueKind.Null)
                                events = Strings(included);
                        }
                        var native = Native<EventGridSubscriptionData>(bytes);
                        Require(Same(native.Id?.ToString(), id) && Same(native.Name, name) &&
                            Same(native.ResourceType.ToString(), type) && Same(native.Topic, topic) &&
                            Same(native.ProvisioningState?.ToString(), nativeState) &&
                            (events.Length == 0 || native.Filter is not null && native.Filter.IncludedEventTypes.SequenceEqual(events)));
                        notification = Notification(properties, native);
                        eligible = SettledResource(nativeState) && notification is not null;
                        break;
                    }
                default: throw new Boundary();
            }
            budget.Check();
            linked.Token.ThrowIfCancellationRequested();
            return Finish(Failure.None, SecretStatus.Success);
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                notification?.Dispose();
                throw new OperationCanceledException(cancellationToken);
            }
            return Finish(deadline.IsCancellationRequested ? Failure.Deadline :
                exception is Boundary b ? b.Reason : Failure.Unavailable, SecretStatus.Unavailable);
        }
        finally
        {
            // Only after ACTUAL credential, send, body and native reader work.
            // No WaitAsync/cancellation callback detaches work or clears live
            // storage. Immutable native/JSON strings are ordinary managed strings.
            CryptographicOperations.ZeroMemory(storage);
        }

        Measurement Finish(Failure failure, SecretStatus resourceStatus)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                notification?.Dispose();
                throw new OperationCanceledException(cancellationToken);
            }
            try { budget.Check(); }
            catch (Boundary b) { failure = b.Reason; resourceStatus = SecretStatus.Unavailable; }
            if (failure != Failure.None || resourceStatus != SecretStatus.Success)
            {
                notification?.Dispose();
                notification = null;
                vault = null;
                connection = null;
                deleted = null;
                assignment = null;
                privateEndpoint = null;
                id = name = type = nativeState = topic = null;
                events = [];
                eligible = false;
            }
            return new()
            {
                Binding = binding,
                WindowId = window.Id,
                ArmedAt = window.ArmedAt,
                StartedAt = started,
                FinishedAt = budget.ObservedAt,
                Identity = authority.Label,
                Failure = failure,
                ResourceStatus = resourceStatus,
                HttpStatus = status,
                NativeRequestId = requestId,
                ResourceId = id,
                ResourceName = name,
                ResourceType = type,
                NativeState = nativeState,
                Topic = topic,
                EventTypes = Array.AsReadOnly(events),
                VaultConfiguration = vault,
                ConnectionState = connection,
                PrivateEndpointId = privateEndpoint,
                NotificationConfiguration = notification,
                DeletedVault = deleted,
                RoleAssignment = assignment,
                PersistedStateEligible = eligible
            };
        }
    }

    private void ValidateVault(JsonElement p)
    {
        var sku = Object(p, "sku");
        _ = Text(sku, "name");
        _ = Text(sku, "family");
        foreach (string field in new[] { "enableRbacAuthorization", "enablePurgeProtection", "enableSoftDelete" })
            _ = Boolean(p, field);
        if (p.TryGetProperty("softDeleteRetentionInDays", out var retention) && retention.ValueKind != JsonValueKind.Null)
            Require(retention.TryGetInt32(out _));
        _ = OptionalText(p, "publicNetworkAccess");
        _ = OptionalText(p, "createMode");
        if (p.TryGetProperty("accessPolicies", out var policies) && policies.ValueKind != JsonValueKind.Null)
        {
            Require(policies.ValueKind == JsonValueKind.Array && policies.GetArrayLength() <= 16);
            var unique = new HashSet<(Guid, Guid, Guid?)>();
            foreach (var policy in policies.EnumerateArray())
            {
                Guid tenant = Identifier(policy, "tenantId"), principal = Identifier(policy, "objectId");
                Guid? application = policy.TryGetProperty("applicationId", out var app) && app.ValueKind != JsonValueKind.Null
                    ? Identifier(policy, "applicationId") : null;
                Require(tenant == tenantId && unique.Add((tenant, principal, application)));
                var permissions = Object(policy, "permissions");
                foreach (string kind in new[] { "secrets", "keys", "certificates", "storage" })
                    if (permissions.TryGetProperty(kind, out var values)) _ = Strings(values);
            }
        }
    }

    private VaultConfiguration? Vault(JsonElement p, string location, bool recoveryCancellation = false)
    {
        var sku = p.GetProperty("sku");
        bool? rbac = Boolean(p, "enableRbacAuthorization"), purge = Boolean(p, "enablePurgeProtection");
        string? network = OptionalText(p, "publicNetworkAccess");
        string? mode = OptionalText(p, "createMode");
        string[] fields = ["tenantId", "sku", "vaultUri", "provisioningState", "enableRbacAuthorization", "enablePurgeProtection",
            "enableSoftDelete", "softDeleteRetentionInDays", "publicNetworkAccess", "accessPolicies", "createMode"];
        if (!Only(p, recoveryCancellation ? [.. fields, "privateEndpointConnections"] : fields) ||
            !Only(sku, "name", "family") || Text(sku, "family") != "A" ||
            Text(sku, "name") is not ("standard" or "premium") || Boolean(p, "enableSoftDelete") != true ||
            rbac is null || purge is null || network is not ("Enabled" or "Disabled") ||
            mode is not (null or "default" or "recover") ||
            !p.TryGetProperty("softDeleteRetentionInDays", out var retention) || !retention.TryGetInt32(out int days) ||
            days is < 7 or > 90 || !p.TryGetProperty("accessPolicies", out var rows) || rows.ValueKind != JsonValueKind.Array)
            return null;
        if (recoveryCancellation && p.TryGetProperty("privateEndpointConnections", out var connections))
            Require(connections.ValueKind == JsonValueKind.Array && connections.GetArrayLength() == 0);
        var policies = new List<Policy>();
        foreach (var row in rows.EnumerateArray())
        {
            var permissions = row.GetProperty("permissions");
            if (!Only(row, "tenantId", "objectId", "applicationId", "permissions") ||
                !Only(permissions, "secrets", "keys", "certificates", "storage") ||
                !permissions.TryGetProperty("secrets", out var secrets)) return null;
            foreach (string kind in new[] { "keys", "certificates", "storage" })
                if (permissions.TryGetProperty(kind, out var values) && values.GetArrayLength() != 0) return null;
            var named = new List<SecretPermission>();
            foreach (string text in Strings(secrets))
            {
                if (!Enum.TryParse<SecretPermission>(text, true, out var permission) || !Enum.IsDefined(permission) ||
                    !permission.ToString().Equals(text, StringComparison.OrdinalIgnoreCase)) return null;
                named.Add(permission);
            }
            policies.Add(new(Identifier(row, "tenantId"), Identifier(row, "objectId"),
                row.TryGetProperty("applicationId", out var application) && application.ValueKind != JsonValueKind.Null
                    ? Identifier(row, "applicationId") : null, named.ToArray()));
        }
        return new(location, tenantId, Text(sku, "name") == "premium" ? VaultSku.Premium : VaultSku.Standard,
            rbac.Value, purge.Value, days, network == "Enabled", policies.ToArray(), mode);
    }

    private NotificationConfiguration? Notification(JsonElement p, EventGridSubscriptionData native)
    {
        // Missing, masked, hidden, filtered or extra configuration is not a
        // representable configuration. Never join getFullUrl/delivery actions.
        if (!Only(p, "topic", "provisioningState", "destination", "filter") ||
            !p.TryGetProperty("filter", out var filter) || filter.ValueKind != JsonValueKind.Object ||
            !Only(filter, "includedEventTypes", "advancedFilters") ||
            !filter.TryGetProperty("includedEventTypes", out var included) || included.ValueKind != JsonValueKind.Array ||
            !p.TryGetProperty("destination", out var destination) || destination.ValueKind != JsonValueKind.Object ||
            !Only(destination, "endpointType", "properties") || Text(destination, "endpointType") != "WebHook" ||
            native.Destination is not WebHookEventSubscriptionDestination webhook) return null;
        if (filter.TryGetProperty("advancedFilters", out var advanced) &&
            (advanced.ValueKind != JsonValueKind.Array || advanced.GetArrayLength() != 0)) return null;
        string[] texts = Strings(included);
        var events = new List<VaultNotificationEvent>();
        foreach (string text in texts)
        {
            VaultNotificationEvent? value = text switch
            {
                "Microsoft.KeyVault.SecretNewVersionCreated" => VaultNotificationEvent.SecretNewVersionCreated,
                "Microsoft.KeyVault.SecretNearExpiry" => VaultNotificationEvent.SecretNearExpiry,
                "Microsoft.KeyVault.SecretExpired" => VaultNotificationEvent.SecretExpired,
                _ => null
            };
            if (value is null) return null;
            events.Add(value.Value);
        }
        if (events.Count is < 1 or > 3) return null;
        var settings = Object(destination, "properties");
        if (!Only(settings, "endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings") ||
            !settings.TryGetProperty("endpointUrl", out var endpoint) || endpoint.ValueKind != JsonValueKind.String ||
            !Endpoint(endpoint.GetString()!) ||
            !settings.TryGetProperty("deliveryAttributeMappings", out var mappings) || mappings.ValueKind != JsonValueKind.Array ||
            mappings.GetArrayLength() > 10) return null;
        string url = endpoint.GetString()!;
        if (settings.TryGetProperty("endpointBaseUrl", out var baseUrl) && baseUrl.ValueKind != JsonValueKind.Null &&
            (!Endpoint(String(baseUrl)) || !Same(new Uri(url).GetLeftPart(UriPartial.Path), String(baseUrl)))) return null;
        // The native reader must agree with the same complete metadata response.
        if (webhook.Endpoint?.OriginalString != url || native.Filter is null ||
            !native.Filter.IncludedEventTypes.SequenceEqual(texts)) return null;
        var attributes = new List<Attribute>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        SecretMaterial? material = null;
        bool transferred = false;
        try
        {
            foreach (var row in mappings.EnumerateArray())
            {
                if (!Only(row, "name", "type", "properties")) return null;
                string name = Text(row, "name"), kind = Text(row, "type");
                if (name.Length is < 1 or > 64 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') ||
                    !names.Add(name) || kind is not ("Static" or "Dynamic")) return null;
                var properties = Object(row, "properties");
                string field = kind == "Static" ? "value" : "sourceField";
                if (!(kind == "Static" ? Only(properties, "value", "isSecret") : Only(properties, "sourceField")) ||
                    !properties.TryGetProperty(field, out var value) || value.ValueKind != JsonValueKind.String ||
                    !TextValue(value.GetString(), 4096) || Masked(value.GetString()!)) return null;
                bool secret = false;
                if (kind == "Static")
                {
                    bool? flag = Boolean(properties, "isSecret");
                    if (flag is null) return null;
                    secret = flag.Value;
                }
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(row);
                try
                {
                    if (bytes.Length > limits.MaximumRowBytes) throw new Boundary(Failure.Budget);
                    var attribute = Native<DeliveryAttributeMapping>(new BinaryData(bytes));
                    if (attribute.Name != name || (kind == "Static"
                        ? attribute is not StaticDeliveryAttributeMapping s || s.Value != value.GetString() || s.IsSecret != secret
                        : attribute is not DynamicDeliveryAttributeMapping d || d.SourceField != value.GetString())) return null;
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
                attributes.Add(new()
                {
                    Name = name,
                    Kind = kind == "Static" ? NotificationAttributeKind.Static : NotificationAttributeKind.Dynamic,
                    IsSecret = secret,
                    Value = SecretMaterial.FromText(value.GetString()!)
                });
            }
            material = SecretMaterial.FromText(url);
            var result = new NotificationConfiguration { Endpoint = material, Events = events.AsReadOnly(), Attributes = attributes.AsReadOnly() };
            transferred = true;
            return result;
        }
        finally
        {
            if (!transferred)
            {
                material?.Dispose();
                foreach (var attribute in attributes) attribute.Dispose();
            }
        }
    }

    private static T Native<T>(BinaryData bytes) => ModelReaderWriter.Read<T>(bytes) ?? throw new Boundary();

    private static void ValidateBinding(Capture.Binding b, bool statusDeniedVaultUpdateRead = false,
        bool statusDeniedVaultRecoverRead = false)
    {
        Require(b is not null && b.Selector is not null && b.Resource is not null && b.Selector.Nonce != Guid.Empty &&
            b.LeaseId != Guid.Empty && Segment(b.Location, 50) &&
            new[] { b.Selector.Scope, b.Selector.Operation, b.Selector.Variant, b.Selector.Case }.All(s => TextValue(s, 512)) &&
            b.Selector.Operation == ManagementOperationEffects.Members[0].Operation &&
            (b.Selector.Variant == "operation." + b.Operation ||
                b.Selector.Variant.StartsWith("status.", StringComparison.Ordinal) &&
                ManagementOperationEffects.Members[0].Variants.Contains(b.Selector.Variant, StringComparer.Ordinal)) &&
            b.Selector.Case is "selected-contract" or "denied-authority" or "cancellation-boundary" or "independent-effect");
        Require(b.Operation != ManagementMutation.PurgeDeletedVault || b.Selector.Variant != "status.Pending" ||
            b.Selector.Case is not ("selected-contract" or "independent-effect" or "cancellation-boundary"));
        Require(b.Operation != ManagementMutation.PurgeDeletedVault || b.Selector.Variant != "status.Failed" ||
            b.Selector.Case is not ("selected-contract" or "independent-effect" or "cancellation-boundary"));
        Require(b.Operation != ManagementMutation.PurgeDeletedVault || b.Selector.Variant != "status.Canceled" ||
            b.Selector.Case is not ("selected-contract" or "independent-effect" or "cancellation-boundary"));
        Require(b.Operation != ManagementMutation.PurgeDeletedVault ||
            b.Selector.Variant != "operation.PurgeDeletedVault" || b.Selector.Case != "denied-authority");
        Require(b.Operation switch
        {
            ManagementMutation.CreateOrUpdateVault => b.Resource is VaultScope ||
                (VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(b.Selector) ||
                    statusDeniedVaultUpdateRead && StatusDeniedVaultUpdateBinding(b)) &&
                b.Resource is DeletedVaultScope updated && Same(updated.Location, b.Location),
            ManagementMutation.RecoverVault => b.Resource is VaultScope ||
                (VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(b.Selector) ||
                    statusDeniedVaultRecoverRead && StatusDeniedVaultRecoverBinding(b)) &&
                b.Resource is DeletedVaultScope recovered && Same(recovered.Location, b.Location),
            ManagementMutation.DeleteVault => b.Resource is VaultScope ||
                VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(b.Selector) &&
                b.Resource is DeletedVaultScope counterpart && Same(counterpart.Location, b.Location),
            ManagementMutation.PurgeDeletedVault => b.Resource is DeletedVaultScope d && Same(d.Location, b.Location) ||
                VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(b.Selector) && b.Resource is VaultScope,
            ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection => b.Resource is PrivateConnectionScope,
            ManagementMutation.DeleteRoleAssignment => b.Resource is RoleAssignmentScope,
            ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or ManagementMutation.DeleteNotification => b.Resource is NotificationScope,
            _ => false
        });
        Require(b.ApiRevision == (b.Resource is RoleAssignmentScope ? "2022-04-01" :
            b.Resource is NotificationScope ? "2025-02-15" : "2026-02-01"));
        _ = Path(b.Resource);
    }
    private static string Parent(ManagementScope scope) => scope switch
    {
        VaultScope v => v.ExportResourceId(),
        ResourceGroupScope g => Parent(g.Subscription) + "/resourceGroups/" + g.ResourceGroup,
        SubscriptionScope s => "/subscriptions/" + s.SubscriptionId.ToString("D"),
        _ => throw new Boundary()
    };
    private static string Path(ManagementScope scope) => scope switch
    {
        VaultScope v => v.ExportResourceId(),
        DeletedVaultScope d => Parent(d.Subscription) + "/providers/Microsoft.KeyVault/locations/" + d.Location + "/deletedVaults/" + d.VaultName,
        PrivateConnectionScope p => p.Vault.ExportResourceId() + "/privateEndpointConnections/" + p.ConnectionName,
        RoleAssignmentScope r => Parent(r.Parent) + "/providers/Microsoft.Authorization/roleAssignments/" + r.AssignmentId.ToString("D"),
        NotificationScope n => n.Vault.ExportResourceId() + "/providers/Microsoft.EventGrid/eventSubscriptions/" + n.SubscriptionName,
        _ => throw new Boundary()
    };
    private static string Type(ManagementScope scope) => scope switch
    {
        VaultScope => "Microsoft.KeyVault/vaults",
        DeletedVaultScope => "Microsoft.KeyVault/locations/deletedVaults",
        PrivateConnectionScope => "Microsoft.KeyVault/vaults/privateEndpointConnections",
        RoleAssignmentScope => "Microsoft.Authorization/roleAssignments",
        NotificationScope => "Microsoft.EventGrid/eventSubscriptions",
        _ => throw new Boundary()
    };

    private void Shape(ReadOnlySpan<byte> bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = limits.MaximumDepth });
        var stack = new Stack<HashSet<string>?>();
        int nodes = 0, rows = 0;
        while (reader.Read())
        {
            if (++nodes > limits.MaximumNodes) throw new Boundary(Failure.Budget);
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                if (++rows > limits.MaximumRows) throw new Boundary(Failure.Budget);
                stack.Push(new(StringComparer.OrdinalIgnoreCase));
            }
            else if (reader.TokenType == JsonTokenType.StartArray) stack.Push(null);
            else if (reader.TokenType is JsonTokenType.EndArray or JsonTokenType.EndObject) stack.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string name = reader.GetString()!;
                Require(stack.Count > 0 && stack.Peek() is { } names && names.Add(name));
                foreach (string reserved in Reserved)
                    if (name.Equals(reserved, StringComparison.OrdinalIgnoreCase)) Require(name == reserved);
            }
        }
        Require(nodes > 0 && stack.Count == 0);
    }
    private static readonly string[] Reserved =
    [
        "id", "name", "type", "properties", "location", "tenantId", "sku", "family", "vaultUri", "provisioningState",
        "enableRbacAuthorization", "enablePurgeProtection", "enableSoftDelete", "softDeleteRetentionInDays", "publicNetworkAccess",
        "accessPolicies", "objectId", "applicationId", "permissions", "secrets", "keys", "certificates", "storage",
        "vaultId", "deletionDate", "scheduledPurgeDate", "purgeProtectionEnabled", "privateLinkServiceConnectionState",
        "privateEndpoint", "scope", "roleDefinitionId", "principalId", "principalType", "topic", "destination",
        "endpointType", "endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings", "filter", "includedEventTypes",
        "advancedFilters", "sourceField", "isSecret", "etag", "value", "nextLink", "error", "errors", "partial", "status",
        "code", "message", "details"
    ];
    private static long? ResponseHeaders(Response response, out string requestId)
    {
        Headers(response.Headers);
        Require(response.Status is not (>= 300 and < 400) && response.Status != 206);
        foreach (string header in new[] { "Content-Range", "Content-Encoding", "Location", "Azure-AsyncOperation", "Operation-Location", "Transfer-Encoding" })
            Require(!response.Headers.Contains(header));
        string contentType = Single(response.Headers, "Content-Type");
        string[] pieces = contentType.Split(';', StringSplitOptions.TrimEntries);
        Require(pieces.Length is 1 or 2 && pieces[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
            (pieces.Length == 1 || pieces[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
        requestId = Single(response.Headers, "x-ms-request-id");
        Require(Segment(requestId, 128));
        if (!response.Headers.Contains("Content-Length")) return null;
        string length = Single(response.Headers, "Content-Length");
        Require(long.TryParse(length, NumberStyles.None, CultureInfo.InvariantCulture, out long result) && result >= 0);
        return result;
    }
    private static string Single(ResponseHeaders headers, string name)
    {
        Require(headers.TryGetValues(name, out var source));
        string[] values = source.Take(2).ToArray();
        Require(values.Length == 1);
        return values[0];
    }
    private static void Headers(IEnumerable<HttpHeader> headers)
    {
        int count = 0, bytes = 0;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers)
        {
            if (++count > 32 || header.Name.Length > 128 || header.Value.Length > 4096)
                throw new Boundary(Failure.Budget);
            Require(names.Add(header.Name) && header.Name.Length > 0 &&
                header.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                !header.Value.Any(c => !char.IsAscii(c) || char.IsControl(c) && c != '\t'));
            bytes += header.Name.Length + header.Value.Length;
            if (bytes > 16384) throw new Boundary(Failure.Budget);
        }
    }
    private static void RecoveryAbsence(JsonElement error)
    {
        Require(Only(error, "code", "message", "details") &&
            Text(error, "code") is "NotFound" or "ResourceNotFound" or "VaultNotFound");
        if (error.TryGetProperty("details", out var details))
            foreach (var detail in details.EnumerateArray()) RecoveryAbsence(detail);
    }

    private static void Error(JsonElement error)
    {
        Require(error.ValueKind == JsonValueKind.Object);
        _ = Text(error, "code");
        if (error.TryGetProperty("message", out var message)) Require(message.ValueKind == JsonValueKind.String);
        if (error.TryGetProperty("details", out var details))
        {
            Require(details.ValueKind == JsonValueKind.Array);
            foreach (var detail in details.EnumerateArray()) Error(detail);
        }
    }
    private static JsonElement Object(JsonElement parent, string field)
    {
        var value = parent.GetProperty(field);
        Require(value.ValueKind == JsonValueKind.Object);
        return value;
    }
    private static string Text(JsonElement parent, string field) => String(parent.GetProperty(field));
    private static string String(JsonElement value)
    {
        Require(value.ValueKind == JsonValueKind.String && TextValue(value.GetString(), 4096));
        return value.GetString()!;
    }
    private static string? OptionalText(JsonElement parent, string field) =>
        !parent.TryGetProperty(field, out var value) || value.ValueKind == JsonValueKind.Null ? null : String(value);
    private static Guid Identifier(JsonElement parent, string field)
    {
        Require(Guid.TryParseExact(Text(parent, field), "D", out var id) && id != Guid.Empty);
        return id;
    }
    private static bool? Boolean(JsonElement parent, string field)
    {
        if (!parent.TryGetProperty(field, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        Require(value.ValueKind is JsonValueKind.True or JsonValueKind.False);
        return value.GetBoolean();
    }
    private static DateTimeOffset? Date(JsonElement parent, string field)
    {
        if (!parent.TryGetProperty(field, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        Require(value.ValueKind == JsonValueKind.String && value.TryGetDateTimeOffset(out _));
        return value.GetDateTimeOffset();
    }
    private static string[] Strings(JsonElement value)
    {
        Require(value.ValueKind == JsonValueKind.Array);
        var values = new List<string>();
        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in value.EnumerateArray())
        {
            string text = String(row);
            Require(unique.Add(text));
            values.Add(text);
        }
        return values.ToArray();
    }
    private static bool Only(JsonElement value, params string[] fields) =>
        value.ValueKind == JsonValueKind.Object && value.EnumerateObject().All(p => fields.Contains(p.Name, StringComparer.Ordinal));
    private static bool SettledResource(string? value) => value == "Succeeded";
    private static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static bool TextValue([NotNullWhen(true)] string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && !value.Any(char.IsControl);
    private static bool Segment(string? value, int maximum) => TextValue(value, maximum) &&
        value is not ("." or "..") && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static bool Masked(string value) => value.Contains('*') ||
        value.Contains("[redacted]", StringComparison.OrdinalIgnoreCase) || value.Contains("(redacted)", StringComparison.OrdinalIgnoreCase);
    private static bool Endpoint(string value) => TextValue(value, 4096) && !Masked(value) &&
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == "https" && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0;
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new Boundary();
    }
    private sealed class Boundary(Failure reason = Failure.Boundary) : Exception("management-resource-boundary")
    {
        internal Failure Reason { get; } = reason;
    }
    private sealed class Budget(TimeProvider time, DateTimeOffset armedAt, long timestamp, TimeSpan timeout)
    {
        private DateTimeOffset lastWall = DateTimeOffset.MinValue;
        private long lastStamp = long.MinValue;
        internal DateTimeOffset ObservedAt => lastWall;
        internal TimeSpan Remaining { get; private set; }
        internal CancellationTokenSource? Deadline { get; set; }
        internal void Check()
        {
            DateTimeOffset wall = time.GetUtcNow();
            long stamp = time.GetTimestamp();
            Require(wall >= armedAt && stamp >= timestamp && wall >= lastWall && stamp >= lastStamp);
            TimeSpan monotonic = time.GetElapsedTime(timestamp, stamp), elapsedWall = wall - armedAt;
            Require(monotonic >= TimeSpan.Zero && elapsedWall >= TimeSpan.Zero);
            lastWall = wall;
            lastStamp = stamp;
            Remaining = timeout - (monotonic > elapsedWall ? monotonic : elapsedWall);
            if (Remaining <= TimeSpan.Zero) throw new Boundary(Failure.Deadline);
            Deadline?.CancelAfter(Remaining);
        }
    }
    private sealed class ObserverCredential(TokenCredential inner, Budget budget) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) => throw new Boundary();
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            budget.Check();
            cancellationToken.ThrowIfCancellationRequested();
            Require(context.Scopes.Length == 1 && context.Scopes[0] == ArmOrigin + "/.default");
            var result = await inner.GetTokenAsync(context, cancellationToken).ConfigureAwait(false);
            budget.Check();
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
    }
    private sealed class ReadTransport(HttpPipelineTransport inner, Uri uri, Budget budget,
        PrivateRead? privateRead = null, int maximumBytes = 0, bool requireErrorRebuffer = false) : HttpPipelineTransport
    {
        private int sends;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new Boundary();
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            Task task = SendAsync(message);
            if (privateRead is not null) privateRead.Send = task;
            return new(task);
        }
        private async Task SendAsync(HttpMessage message)
        {
            budget.Check();
            Require(Interlocked.Increment(ref sends) == 1);
            Validate(message);
            var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            var request = message.Request;
            message.CancellationToken.ThrowIfCancellationRequested();
            message.BufferResponse = false;
            try { await inner.ProcessAsync(message).ConfigureAwait(false); }
            finally
            {
                if (privateRead is not null && message.HasResponse)
                {
                    privateRead.ObservedStatus = message.Response.Status;
                    privateRead.Storage.Own(message.Response);
                }
            }
            budget.Check();
            message.CancellationToken.ThrowIfCancellationRequested();
            Validate(message);
            Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
            if (privateRead is not null)
            {
                var response = message.Response;
                var stream = response.ContentStream;
                privateRead.Body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, privateRead.Storage)
                    .ConfigureAwait(false);
                Require(ReferenceEquals(message.Request, request) && ReferenceEquals(response.ContentStream, stream) &&
                    headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                Validate(message);
                privateRead.RequestSha256 = Convert.ToHexString(SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes("GET " + uri.AbsoluteUri)));
                privateRead.Parser = OwnedArmResponse.ParserCustody.Install(message, privateRead.Body.Response,
                    privateRead.Body.Bytes, privateRead.Storage, requireRebuffer: requireErrorRebuffer && message.Response.Status >= 400,
                    requireDownstreamRead: true);
            }
        }
        private void Validate(HttpMessage message)
        {
            Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri);
            Headers(message.Request.Headers);
            Require(message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
                authorization.StartsWith("Bearer ", StringComparison.Ordinal) && authorization.Length > 7);
            if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
        }
    }
    public override string ToString() => "[ManagementOperationResourceCollector]";
}
