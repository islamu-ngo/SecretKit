using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class NotificationWebhookAuthenticationTests
{
    private const string Tenant = "22222222-2222-2222-2222-222222222222";
    private const string Audience = "api://55555555-5555-5555-5555-555555555555";
    private static NotificationScope Scope() => new(ScopeAuthorityTests.Scope(), "notification-canary");
    private static string Path => ScopeAuthorityTests.Id + "/providers/Microsoft.EventGrid/eventSubscriptions/notification-canary";

    private static string Resource(string? tenant, string? audience)
    {
        var destination = new JsonObject { ["endpointUrl"] = "https://delivery.example.test/events" };
        if (tenant is not null) destination["azureActiveDirectoryTenantId"] = tenant;
        if (audience is not null) destination["azureActiveDirectoryApplicationIdOrUri"] = audience;
        return new JsonObject
        {
            ["id"] = Path,
            ["name"] = "notification-canary",
            ["type"] = "Microsoft.EventGrid/eventSubscriptions",
            ["properties"] = new JsonObject
            {
                ["topic"] = ScopeAuthorityTests.Id,
                ["provisioningState"] = "Succeeded",
                ["destination"] = new JsonObject { ["endpointType"] = "WebHook", ["properties"] = destination }
            }
        }.ToJsonString();
    }

    [Test]
    [Arguments(Tenant, null)]
    [Arguments(null, Audience)]
    [Arguments("00000000-0000-0000-0000-000000000000", Audience)]
    [Arguments(Tenant, "")]
    [Arguments(Tenant, "*")]
    [Arguments(Tenant, "api://audience?injected=true")]
    [Arguments("not-a-tenant", Audience)]
    [Arguments(Tenant, "audience-canary")]
    [Arguments(Tenant, "https://user@audience.example.test")]
    [Arguments(Tenant, "urn:audience#fragment")]
    public async Task IncompleteOrInvalidServerAuthenticationCannotBecomeObservation(string? tenant, string? audience)
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200, Resource(tenant, audience))));
        var result = await new VaultAdministration(new Credential(), backend).GetNotificationAsync(Scope());

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments("55555555-5555-5555-5555-555555555555")]
    [Arguments(Audience)]
    [Arguments("https://audience.example.test/app")]
    [Arguments("urn:example:application")]
    public async Task ValidAuthenticationPreservesExplicitCoordinatesWithoutFormattingThem(string audience)
    {
        var authentication = new NotificationWebhookAuthentication(Guid.Parse(Tenant), audience);

        await Assert.That(authentication.TenantId).IsEqualTo(Guid.Parse(Tenant));
        await Assert.That(authentication.ApplicationIdOrUri).IsEqualTo(audience);
        await Assert.That(authentication.ToString().Contains(audience, StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(authentication)).IsEqualTo("{}");
    }

    [Test]
    public async Task EmptyTenantIsRejected()
    {
        await Assert.That(() => new NotificationWebhookAuthentication(Guid.Empty, Audience))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments(" ")]
    [Arguments(" " + Audience)]
    [Arguments(Audience + " ")]
    [Arguments("api://aud ience")]
    [Arguments("api://audience\tvalue")]
    [Arguments("api://audience\u0001value")]
    [Arguments("*")]
    [Arguments("api://audience/*")]
    [Arguments("00000000-0000-0000-0000-000000000000")]
    [Arguments("relative/audience")]
    [Arguments("http://audience.example.test")]
    [Arguments("https://user:password@audience.example.test")]
    [Arguments("api://audience?value=canary")]
    [Arguments("urn:audience#canary")]
    public async Task InvalidAudiencesFailBeforeConfiguration(string? audience)
    {
        await Assert.That(() => new NotificationWebhookAuthentication(Guid.Parse(Tenant), audience!))
            .Throws<ArgumentException>();
    }

    [Test]
    [Arguments(2048, true)]
    [Arguments(2049, false)]
    public async Task AudienceLengthBudgetHasAnExactBoundary(int length, bool valid)
    {
        string audience = "urn:" + new string('a', length - 4);
        if (valid)
            await Assert.That(new NotificationWebhookAuthentication(Guid.Parse(Tenant), audience).ApplicationIdOrUri)
                .IsEqualTo(audience);
        else
            await Assert.That(() => new NotificationWebhookAuthentication(Guid.Parse(Tenant), audience))
                .Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ObservationUsesReturnedAuthorityRatherThanRequestedAuthority(bool absent)
    {
        const string returnedAudience = "urn:returned:audience-canary";
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            absent ? Resource(null, null) : Resource(Tenant, returnedAudience))));
        var result = await new VaultAdministration(new Credential(), backend).GetNotificationAsync(Scope());

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.WebhookAuthentication?.TenantId).IsEqualTo(absent ? (Guid?)null : Guid.Parse(Tenant));
        await Assert.That(result.Value.WebhookAuthentication?.ApplicationIdOrUri).IsEqualTo(absent ? null : returnedAudience);
        await Assert.That(result.Value.RuntimeDeliveryProven).IsFalse();
        await Assert.That(JsonSerializer.Serialize(result.Value).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(false, true)]
    [Arguments(true, false)]
    [Arguments(true, true)]
    public async Task WritesCarrySelectedAuthenticationOnNativeDestination(bool patch, bool authenticated)
    {
        string? sentTenant = null;
        string? sentAudience = null;
        bool destinationWritten = false;
        var backend = new WireBackend(async (request, token) =>
        {
            if (request.RequestUri!.AbsolutePath != Path ||
                request.Method != (patch ? HttpMethod.Patch : HttpMethod.Put))
                throw new InvalidOperationException("Unexpected notification write.");
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            var properties = patch ? body.RootElement : body.RootElement.GetProperty("properties");
            var destination = properties.GetProperty("destination").GetProperty("properties");
            sentTenant = destination.TryGetProperty("azureActiveDirectoryTenantId", out var tenant) ? tenant.GetString() : null;
            sentAudience = destination.TryGetProperty("azureActiveDirectoryApplicationIdOrUri", out var audience) ? audience.GetString() : null;
            destinationWritten = true;
            return WireBackend.Json(201, Resource(authenticated ? Tenant : null, authenticated ? Audience : null));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        using var configuration = new NotificationConfiguration("https://delivery.example.test/events",
            [VaultNotificationEvent.SecretNewVersionCreated], webhookAuthentication: authenticated
                ? new NotificationWebhookAuthentication(Guid.Parse(Tenant), Audience) : null);
        var receipt = client.PrepareReceipt(scope, patch ? ManagementMutation.UpdateNotification : ManagementMutation.CreateOrUpdateNotification);

        var result = patch ? await client.UpdateNotificationAsync(scope, configuration, receipt) :
            await client.CreateOrUpdateNotificationAsync(scope, configuration, receipt);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(destinationWritten).IsTrue();
        await Assert.That(sentTenant).IsEqualTo(authenticated ? Tenant : null);
        await Assert.That(sentAudience).IsEqualTo(authenticated ? Audience : null);
        await Assert.That(configuration.WebhookAuthentication?.ApplicationIdOrUri).IsEqualTo(authenticated ? Audience : null);
    }
}
