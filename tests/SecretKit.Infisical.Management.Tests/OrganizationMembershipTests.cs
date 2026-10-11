using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class OrganizationMembershipTests
{
    private const string Org = "10000000-0000-0000-0000-000000000001";
    private const string Membership = "20000000-0000-0000-0000-000000000002";
    private const string User = "30000000-0000-0000-0000-000000000003";
    private const string Path = "/api/v2/organizations/" + Org + "/memberships";

    [Test]
    public async Task ListUsesNativeUnpaginatedWireAndProtectedUserProjection()
    {
        var wire = new Wire("GET", Path, ListBody(Row(list: true)));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant("infisical.get.v2.organizations.by.organizationId.memberships", new(Org)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Count).IsEqualTo(1);
        await Assert.That(result.Value.IsComplete).IsTrue();
        await Assert.That(result.Value.NextOffset is null).IsTrue();
        var summary = result.Value.Items[0];
        await Assert.That(summary.Id).IsEqualTo(Membership);
        await Assert.That(summary.OrganizationId).IsEqualTo(Org);
        await Assert.That(summary.UserId).IsEqualTo(User);
        await Assert.That(summary.User!.Id).IsEqualTo(User);
        await Assert.That(summary.User.Username).IsEqualTo("private-user");
        await Assert.That(summary.IsActive).IsFalse();
        await Assert.That(summary.Role).IsEqualTo("member");
        await Assert.That(summary.IncludesPermissions).IsFalse();
        await Assert.That(JsonSerializer.Serialize(summary)).IsEqualTo("""{"IncludesPermissions":false}""");
        await Assert.That(JsonSerializer.Serialize(summary.User)).IsEqualTo("{}");
        await Assert.That(summary.ToString().Contains(Membership, StringComparison.Ordinal)).IsFalse();
        await Assert.That(summary.User.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(wire.Observed).IsTrue();
        await Assert.That(wire.Body is null).IsTrue();
    }

    [Test]
    [Arguments("PATCH")]
    [Arguments("DELETE")]
    public async Task MutationsUseExactMembershipWireAndSingleUseReceipts(string method)
    {
        var wire = new Wire(method, Path + "/" + Membership, MutationBody(Row()));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        IdentityAttribute[] metadata = [new("private-key", "private-value")];
        using var request = method == "PATCH"
            ? OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership, "member", false, metadata)
            : OrganizationMembershipOperations.DeleteOrganizationMembership(Org, Membership);
        metadata[0] = new("changed-key", "changed-value");
        var receipt = client.CreateReceipt(request);
        var grant = authority.IssueGrant("infisical." + method.ToLowerInvariant() +
            ".v2.organizations.by.organizationId.memberships.by.membershipId", method == "PATCH"
                ? OrganizationMembershipOperations.OrganizationMembershipUpdateTarget(Org, Membership, "member", false,
                    [new("private-key", "private-value")])
                : new(Org, resourceId: Membership));
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Id).IsEqualTo(Membership);
        await Assert.That(result.Value.OrganizationId).IsEqualTo(Org);
        await Assert.That(result.Value.UserId).IsEqualTo(User);
        await Assert.That(result.Value.User is null).IsTrue();
        await Assert.That(result.Value.CreatedAt).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Observed).IsTrue();
        if (method == "PATCH")
        {
            using JsonDocument body = JsonDocument.Parse(wire.Body!);
            await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(3);
            await Assert.That(body.RootElement.GetProperty("role").GetString()).IsEqualTo("member");
            await Assert.That(body.RootElement.GetProperty("isActive").GetBoolean()).IsFalse();
            var item = body.RootElement.GetProperty("metadata")[0];
            await Assert.That(item.GetProperty("key").GetString()).IsEqualTo("private-key");
            await Assert.That(item.GetProperty("value").GetString()).IsEqualTo("private-value");
        }
        else await Assert.That(wire.Body is null).IsTrue();
        var replay = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(JsonSerializer.Serialize(request).Contains(Org, StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(request.Target)).IsEqualTo("{}");
    }

    [Test]
    [Arguments("role")]
    [Arguments("active")]
    [Arguments("metadata")]
    public async Task PatchPreservesOmissionFalseAndEmptyMetadata(string field)
    {
        var wire = new Wire("PATCH", Path + "/" + Membership, MutationBody(Row()));
        using var request = OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership,
            role: field == "role" ? "custom-role" : null, isActive: field == "active" ? false : null,
            metadata: field == "metadata" ? [] : null);
        var result = await Execute(request, wire, mutation: true,
            approved: OrganizationMembershipOperations.OrganizationMembershipUpdateTarget(Org, Membership,
                role: field == "role" ? "custom-role" : null, isActive: field == "active" ? false : null,
                metadata: field == "metadata" ? [] : null));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        using JsonDocument body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(1);
        if (field == "role")
            await Assert.That(body.RootElement.GetProperty("role").GetString()).IsEqualTo("custom-role");
        else if (field == "active")
            await Assert.That(body.RootElement.GetProperty("isActive").GetBoolean()).IsFalse();
        else await Assert.That(body.RootElement.GetProperty("metadata").GetArrayLength()).IsEqualTo(0);
    }

    [Test]
    [Arguments("GET", "organization")]
    [Arguments("GET", "membership")]
    [Arguments("PATCH", "organization")]
    [Arguments("DELETE", "organization")]
    [Arguments("PATCH", "membership")]
    [Arguments("DELETE", "membership")]
    [Arguments("DELETE", "operation")]
    [Arguments("DELETE", "issuer")]
    [Arguments("DELETE", "missing")]
    public async Task IndependentTargetsRejectBeforeTokenAcquisition(string method, string mismatch)
    {
        var wire = new Wire(method, Path + "/" + Membership, "{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var issuer = mismatch is "organization" or "issuer"
            ? new ManagementAuthority(client.Authority, tokens, mismatch == "organization" ? "other" : Org) : authority;
        var target = new ManagementTarget(mismatch == "organization" ? "other" : Org,
            resourceId: mismatch == "membership" ? "other" : method == "GET" ? null : Membership);
        if (method == "GET")
        {
            using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
            var result = await client.ExecuteAsync(request, authority, issuer.IssueGrant(request.OperationId, target));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        else
        {
            using var request = Single(method);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, mismatch == "missing" ? null :
                issuer.IssueGrant(mismatch == "operation" ? "other" : request.OperationId, target), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        }
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
    }

    [Test]
    [Arguments("PATCH", "orgId", "90000000-0000-4000-8000-000000000009", SecretStatus.Invalid)]
    [Arguments("DELETE", "orgId", "90000000-0000-4000-8000-000000000009", SecretStatus.Invalid)]
    [Arguments("PATCH", "id", "90000000-0000-4000-8000-000000000009", SecretStatus.Invalid)]
    [Arguments("DELETE", "id", "90000000-0000-4000-8000-000000000009", SecretStatus.Invalid)]
    [Arguments("PATCH", "orgId", null, SecretStatus.Unknown)]
    [Arguments("DELETE", "createdAt", null, SecretStatus.Unknown)]
    [Arguments("PATCH", "updatedAt", null, SecretStatus.Unknown)]
    [Arguments("DELETE", "role", null, SecretStatus.Unknown)]
    public async Task ReturnedMutationCoordinatesAndRequiredFieldsFailClosed(
        string method, string field, string? value, SecretStatus expected)
    {
        var fields = Row();
        if (value is null) fields.Remove(field);
        else fields[field] = value;
        var wire = new Wire(method, Path + "/" + Membership, MutationBody(fields));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = Single(method);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, SingleTarget(method)), receipt);
        await Assert.That(result.Status).IsEqualTo(expected);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("organization", SecretStatus.Invalid)]
    [Arguments("user", SecretStatus.Invalid)]
    [Arguments("missing-user", SecretStatus.Unknown)]
    [Arguments("missing-username", SecretStatus.Unknown)]
    [Arguments("active-type", SecretStatus.Unknown)]
    [Arguments("missing-id", SecretStatus.Unknown)]
    [Arguments("missing-role", SecretStatus.Unknown)]
    [Arguments("missing-orgId", SecretStatus.Unknown)]
    public async Task InventoryRejectsForeignScopeAndMalformedUser(string defect, SecretStatus expected)
    {
        var fields = Row(list: true);
        if (defect == "organization") fields["orgId"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "user") fields["userId"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "missing-user") fields.Remove("user");
        if (defect == "missing-username") fields["user"] = new { id = User };
        if (defect == "active-type") fields["isActive"] = "false";
        if (defect is "missing-id" or "missing-role" or "missing-orgId") fields.Remove(defect[8..]);
        using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
        var result = await Execute(request, new Wire("GET", Path, ListBody(fields)));
        await Assert.That(result.Status).IsEqualTo(expected);
    }

    [Test]
    public async Task MissingOptionalMembershipFieldsAreNotInferred()
    {
        var fields = Row(list: true);
        foreach (string field in new[] { "userId", "isActive", "status", "roleId", "inviteEmail" }) fields.Remove(field);
        using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
        var result = await Execute(request, new Wire("GET", Path, ListBody(fields)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var summary = result.Value.Items[0];
        await Assert.That(summary.UserId is null).IsTrue();
        await Assert.That(summary.IsActive is null).IsTrue();
        await Assert.That(summary.Status is null).IsTrue();
        await Assert.That(summary.User!.Id).IsEqualTo(User);
    }

    [Test]
    [Arguments(0, SecretStatus.Success)]
    [Arguments(1000, SecretStatus.Success)]
    [Arguments(1001, SecretStatus.Unknown)]
    public async Task UnpaginatedCollectionHasExplicitItemBound(int count, SecretStatus expected)
    {
        string response = JsonSerializer.Serialize(new { users = Enumerable.Repeat(Row(list: true), count) });
        using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
        var result = await Execute(request, new Wire("GET", Path, response));
        await Assert.That(result.Status).IsEqualTo(expected);
        if (expected == SecretStatus.Success)
        {
            await Assert.That(result.Value.Items.Count).IsEqualTo(count);
            await Assert.That(result.Value.IsComplete).IsTrue();
        }
    }

    [Test]
    [Arguments("PATCH", true)]
    [Arguments("PATCH", false)]
    [Arguments("DELETE", true)]
    [Arguments("DELETE", false)]
    public async Task CancellationPreservesExactDispatchBoundary(string method, bool before)
    {
        var wire = new Wire(method, Path + "/" + Membership, MutationBody(Row())) { Hold = !before };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var request = Single(method);
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        var operation = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, SingleTarget(method)), receipt, cancel.Token).AsTask();
        if (!before)
        {
            await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
        }
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(before
            ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
        await Assert.That(tokens.Acquired).IsEqualTo(!before);
        await Assert.That(wire.Observed).IsEqualTo(!before);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task InventoryCancellationPropagatesWithoutMutationReceipt(bool before)
    {
        var wire = new Wire("GET", Path, ListBody(Row(list: true))) { Hold = !before };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        var operation = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org)), cancellationToken: cancel.Token).AsTask();
        if (!before)
        {
            await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
        }
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(tokens.Acquired).IsEqualTo(!before);
    }

    [Test]
    [Arguments("PATCH", false)]
    [Arguments("PATCH", true)]
    [Arguments("DELETE", false)]
    [Arguments("DELETE", true)]
    public async Task MutationsAndLostResponsesObserveActualMembershipState(string method, bool drop)
    {
        var backend = new StatefulWire { DropAfterCommit = drop };
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = method == "PATCH"
            ? OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership, role: "admin", isActive: true)
            : OrganizationMembershipOperations.DeleteOrganizationMembership(Org, Membership);
        var receipt = client.CreateReceipt(request);
        var grant = authority.IssueGrant(request.OperationId, method == "PATCH"
            ? OrganizationMembershipOperations.OrganizationMembershipUpdateTarget(Org, Membership, role: "admin", isActive: true)
            : new(Org, resourceId: Membership));
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(drop ? SecretStatus.Unknown : SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(drop ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied);
        var replay = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        using var list = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
        var observed = await client.ExecuteAsync(list, authority, authority.IssueGrant(list.OperationId, new(Org)));
        await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(observed.Value.Items.Count).IsEqualTo(method == "PATCH" ? 1 : 0);
        if (method == "PATCH")
        {
            await Assert.That(observed.Value.Items[0].Role).IsEqualTo("admin");
            await Assert.That(observed.Value.Items[0].IsActive).IsTrue();
        }
        await Assert.That(backend.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments("PATCH")]
    [Arguments("DELETE")]
    public async Task OpaqueCoordinatesEscapeButNonUuidResponseEchoesRemainUnverified(string method)
    {
        const string organization = "org/with?query#fragment";
        const string membership = "member/with?query#fragment";
        string path = "/api/v2/organizations/" + Uri.EscapeDataString(organization) +
            "/memberships/" + Uri.EscapeDataString(membership);
        var row = Row();
        row["orgId"] = organization;
        row["id"] = membership;
        var wire = new Wire(method, path, MutationBody(row));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), organization);
        using var request = method == "PATCH"
            ? OrganizationMembershipOperations.UpdateOrganizationMembership(organization, membership, isActive: false)
            : OrganizationMembershipOperations.DeleteOrganizationMembership(organization, membership);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, method == "PATCH"
                ? OrganizationMembershipOperations.OrganizationMembershipUpdateTarget(organization, membership, isActive: false)
                : new(organization, resourceId: membership)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Observed).IsTrue();
    }

    [Test]
    public async Task TypedBudgetsRejectInvalidInputsWithoutTransport()
    {
        await Assert.That(() => OrganizationMembershipOperations.ListOrganizationMemberships("..")).Throws<ArgumentException>();
        await Assert.That(() => OrganizationMembershipOperations.DeleteOrganizationMembership(Org, "")).Throws<ArgumentException>();
        await Assert.That(() => OrganizationMembershipOperations.DeleteOrganizationMembership(Org, null!)).Throws<ArgumentException>();
        await Assert.That(() => OrganizationMembershipOperations.UpdateOrganizationMembership(Org, null!, isActive: true)).Throws<ArgumentException>();
        await Assert.That(() => OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership)).Throws<ArgumentException>();
        await Assert.That(() => OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership, role: "")).Throws<ArgumentException>();
        await Assert.That(() => OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership,
            metadata: Enumerable.Repeat(new IdentityAttribute("key", "value"), 101).ToArray())).Throws<ArgumentException>();
        await Assert.That(() => OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership,
            metadata: Enumerable.Repeat(new IdentityAttribute("key", new string('x', 4096)), 100).ToArray())).Throws<ArgumentException>();
    }

    private static ManagementRequest<OrganizationMembershipSummary> Single(string method) => method == "PATCH"
        ? OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership, isActive: false)
        : OrganizationMembershipOperations.DeleteOrganizationMembership(Org, Membership);

    [Test]
    [Arguments("GET", "lastInvitedAt", "2026-01-01")]
    [Arguments("GET", "lastInvitedAt", "2026-01-01T03:04:05")]
    [Arguments("GET", "lastInvitedAt", "2026-02-30T03:04:05Z")]
    [Arguments("GET", "lastLoginTime", "2026-01-01")]
    [Arguments("GET", "lastLoginTime", "2026-01-01T03:04:05")]
    [Arguments("GET", "lastLoginTime", "2026-02-30T03:04:05Z")]
    [Arguments("PATCH", "lastInvitedAt", "2026-01-01")]
    [Arguments("PATCH", "lastInvitedAt", "2026-01-01T03:04:05")]
    [Arguments("PATCH", "lastInvitedAt", "2026-02-30T03:04:05Z")]
    [Arguments("PATCH", "lastLoginTime", "2026-01-01")]
    [Arguments("PATCH", "lastLoginTime", "2026-01-01T03:04:05")]
    [Arguments("PATCH", "lastLoginTime", "2026-02-30T03:04:05Z")]
    [Arguments("DELETE", "lastInvitedAt", "2026-01-01")]
    [Arguments("DELETE", "lastInvitedAt", "2026-01-01T03:04:05")]
    [Arguments("DELETE", "lastInvitedAt", "2026-02-30T03:04:05Z")]
    [Arguments("DELETE", "lastLoginTime", "2026-01-01")]
    [Arguments("DELETE", "lastLoginTime", "2026-01-01T03:04:05")]
    [Arguments("DELETE", "lastLoginTime", "2026-02-30T03:04:05Z")]
    public async Task OptionalNativeDatesRejectDateOnlyMissingZoneAndInvalidCalendar(string method, string field, string invalid)
    {
        // Given valid selected UUIDs and exactly one defective optional date.
        var row = Row(list: method == "GET");
        row[field] = invalid;
        // When the named public adapter dispatches through its HTTP boundary.
        var result = await ExecuteDateRow(method, row);
        // Then the date cannot become verified membership metadata.
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("GET", "absent")]
    [Arguments("GET", "null")]
    [Arguments("GET", "2026-01-01T03:04:05Z")]
    [Arguments("GET", "2026-01-01T03:04:05.1234567+02:30")]
    [Arguments("GET", "2026-01-01T03:04:05-04:00")]
    [Arguments("PATCH", "absent")]
    [Arguments("PATCH", "null")]
    [Arguments("PATCH", "2026-01-01T03:04:05Z")]
    [Arguments("PATCH", "2026-01-01T03:04:05.1234567+02:30")]
    [Arguments("PATCH", "2026-01-01T03:04:05-04:00")]
    [Arguments("DELETE", "absent")]
    [Arguments("DELETE", "null")]
    [Arguments("DELETE", "2026-01-01T03:04:05Z")]
    [Arguments("DELETE", "2026-01-01T03:04:05.1234567+02:30")]
    [Arguments("DELETE", "2026-01-01T03:04:05-04:00")]
    public async Task OptionalNativeDatesPreserveAbsenceNullAndOriginalSignedOffsetText(string method, string shape)
    {
        // Given endpoint-owned optional dates, absent, null or explicitly zoned text.
        var row = Row(list: method == "GET");
        if (shape != "absent")
        {
            row["lastInvitedAt"] = shape == "null" ? null : shape;
            row["lastLoginTime"] = shape == "null" ? null : shape;
        }
        // When the transport has finished and been disposed.
        var result = await ExecuteDateRow(method, row);
        // Then native presence and the complete original offset text are copied.
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        foreach (var field in new[] { result.Value.LastInvitedAt, result.Value.LastLoginTime })
        {
            await Assert.That(field.IsPresent).IsEqualTo(shape != "absent");
            await Assert.That(field.IsNull).IsEqualTo(shape == "null");
            if (shape is not ("absent" or "null")) await Assert.That(field.Value).IsEqualTo(shape);
        }
    }

    private static async Task<SecretOutcome<OrganizationMembershipSummary>> ExecuteDateRow(
        string method, Dictionary<string, object?> row)
    {
        if (method == "GET")
        {
            using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
            var result = await Execute(request, new Wire(method, Path, ListBody(row)));
            return result.IsSuccess ? SecretOutcome<OrganizationMembershipSummary>.Success(result.Value.Items.Single())
                : SecretOutcome<OrganizationMembershipSummary>.Failure(result.Status);
        }
        using var single = Single(method);
        return await Execute(single, new Wire(method, Path + "/" + Membership, MutationBody(row)),
            mutation: true, approved: SingleTarget(method));
    }

    private static ManagementTarget SingleTarget(string method) => method == "PATCH"
        ? OrganizationMembershipOperations.OrganizationMembershipUpdateTarget(Org, Membership, isActive: false)
        : new(Org, resourceId: Membership);

    private static Dictionary<string, object?> Row(bool list = false)
    {
        var row = new Dictionary<string, object?>
        {
            ["id"] = Membership,
            ["orgId"] = Org,
            ["userId"] = User,
            ["role"] = "member",
            ["isActive"] = false,
            ["status"] = "accepted",
            ["roleId"] = null,
            ["inviteEmail"] = null
        };
        if (list) row["user"] = new { id = User, username = "private-user", email = "private@example.test" };
        else
        {
            row["createdAt"] = "2026-01-01T00:00:00Z";
            row["updatedAt"] = "2026-01-02T00:00:00Z";
        }
        return row;
    }

    private static string ListBody(Dictionary<string, object?> row) => JsonSerializer.Serialize(new { users = new[] { row } });
    private static string MutationBody(Dictionary<string, object?> row) => JsonSerializer.Serialize(new { membership = row });

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, Wire wire,
        bool mutation = false, ManagementTarget? approved = null) where T : notnull
    {
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            approved ?? new(Org, resourceId: mutation ? Membership : null)), mutation ? client.CreateReceipt(request) : null);
    }

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Wire(string method, string path, string response) : HttpMessageHandler
    {
        public bool Observed { get; private set; }
        public string? Body { get; private set; }
        public bool Hold { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method.Method != method || request.RequestUri!.PathAndQuery != path ||
                request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.NotFound);
            Observed = true;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))))));
        }
    }

    private sealed class StatefulWire : HttpMessageHandler
    {
        private Dictionary<string, object?>? _membership = Row();
        public bool DropAfterCommit { get; init; }
        public int Revision { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.Unauthorized);
            string response;
            if (request.Method == HttpMethod.Get && request.RequestUri!.PathAndQuery == Path)
            {
                if (_membership is null) response = """{"users":[]}""";
                else
                {
                    var row = Row(list: true);
                    row["role"] = _membership["role"];
                    row["isActive"] = _membership["isActive"];
                    response = ListBody(row);
                }
            }
            else if (request.RequestUri!.PathAndQuery == Path + "/" + Membership && _membership is not null)
            {
                if (request.Method == HttpMethod.Patch)
                {
                    using JsonDocument body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                    _membership["role"] = body.RootElement.GetProperty("role").GetString();
                    _membership["isActive"] = body.RootElement.GetProperty("isActive").GetBoolean();
                    response = MutationBody(_membership);
                }
                else if (request.Method == HttpMethod.Delete)
                {
                    response = MutationBody(_membership);
                    _membership = null;
                }
                else return new(HttpStatusCode.NotFound);
                Revision++;
                if (DropAfterCommit) throw new HttpRequestException("Protected provider response.");
            }
            else return new(HttpStatusCode.NotFound);
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
