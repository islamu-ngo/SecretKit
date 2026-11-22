using SecretKit.Infisical.Dynamic;

namespace SecretKit.Infisical.Tests;

public sealed class DynamicEndpointPolicyTests
{
    [Test]
    [Arguments("https://127.0.0.2")]
    [Arguments("https://[::]")]
    [Arguments("https://0.0.0.0")]
    [Arguments("https://[::ffff:169.254.169.254]")]
    [Arguments("https://169.254.169.254")]
    [Arguments("https://[fe80::1]")]
    [Arguments("https://[ff02::1]")]
    [Arguments("https://224.1.2.3")]
    [Arguments("https://service.localhost.")]
    [Arguments("http://10.1.2.3")]
    public async Task ExplicitOriginCannotAdmitProhibitedDestination(string origin)
    {
        await Assert.That(() =>
        {
            using var profile = new NativeCouchbaseDefinitionProfile(origin + "/cluster", "test", "org", "project",
                "cluster", ["role"], trustedEndpointOrigin: new(origin));
        }).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("https://10.0.0.2:6443")]
    [Arguments("https://10.0.0.1:8443")]
    [Arguments("https://10.0.0.1:6443/path")]
    [Arguments("https://10.0.0.1:6443/path/..")]
    [Arguments("https://10.0.0.1:6443?option=x")]
    [Arguments("https://10.0.0.1:6443#fragment")]
    [Arguments("https://user@10.0.0.1:6443")]
    public async Task PrivateRevocationRequiresAnExactBareOrigin(string origin)
    {
        await Assert.That(() =>
        {
            using var profile = new NativeOauthDefinitionProfile("client", "test", NativeOauthClientAuthentication.Basic,
                "https://oauth.test/token", "https://10.0.0.1:6443/revoke", trustedEndpointOrigin: new(origin));
        }).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("http://cluster.test")]
    [Arguments("https://localhost")]
    [Arguments("https://192.168.1.1")]
    [Arguments("https://cluster.test:6443")]
    [Arguments("https://[::ffff:169.254.169.254]")]
    public async Task DefaultRejectsNonPublicCluster(string endpoint)
    {
        await Assert.That(() =>
        {
            using var profile = new NativeKubernetesDefinitionProfile("ns", "role", true, [], url: endpoint);
        }).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("https://totp/label?secret=fixture")]
    [Arguments("otpauth://hotp/label?secret=fixture")]
    [Arguments("otpauth://totp/?secret=fixture")]
    [Arguments("otpauth://totp/label?issuer=fixture")]
    [Arguments("otpauth://totp/label?secret=")]
    [Arguments("otpauth://totp/label?secret=a&secret=b")]
    [Arguments("otpauth://totp/label?secret=a&secret")]
    [Arguments("otpauth://totp/label?secret=a&%73ecret=b")]
    [Arguments("otpauth://user@totp/label?secret=fixture")]
    [Arguments("otpauth://totp/label?secret=fixture#fragment")]
    public async Task RejectsNonProvisioningData(string value)
    {
        await Assert.That(() =>
        {
            using var profile = new NativeTotpDefinitionProfile(value);
        }).Throws<ArgumentException>();
    }
}
