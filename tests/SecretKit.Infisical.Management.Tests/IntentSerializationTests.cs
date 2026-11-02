using System.Security.Cryptography;
using System.Text;

namespace SecretKit.Infisical.Management.Tests;

public sealed class IntentSerializationTests
{
    [Test]
    public async Task GroupIntentPreservesEscapingAndExplicitNullFields()
    {
        ManagementTarget target = ScopedAccessOperations.GroupCreationTarget("organization-fixture", "<&");
        const string expected = """{"name":"\u003C\u0026","slug":null,"role":null}""";
        await Assert.That(target.SecondaryId)
            .IsEqualTo(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expected))));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LegacyIntentPreservesOrderedCoordinatesAndNullableSelector(bool selected)
    {
        var selection = new LegacyPrivilegeSelection("organization-fixture", "project-fixture", "slug-fixture",
            "identity-fixture", "membership-fixture");
        ManagementTarget target = selection.GrantTarget(selected ? "privilege-fixture" : null);
        string expected = selected
            ? """["slug-fixture","membership-fixture","privilege-fixture"]"""
            : """["slug-fixture","membership-fixture",null]""";
        await Assert.That(target.SecondaryId)
            .IsEqualTo(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expected))));
    }
}
