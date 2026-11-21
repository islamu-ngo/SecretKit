using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.LiveProvisioner;
using SecretKit.TestFixtures;

namespace SecretKit.Consumer.Tests;

public sealed class LiveProvisionerRunnerTests
{
    [Test]
    [Arguments("distinct")]
    [Arguments("identity")]
    [Arguments("token")]
    public async Task RequiresIndependentIdentityAndFreshLoginForEveryRole(string scenario)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var origin = new Uri($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}");
        using var secrets = new SyntheticPrincipals();
        LivePrincipal[] principals = secrets.Principals(scenario == "identity");
        Task wire = scenario == "identity" ? Task.CompletedTask : ServeLogins(listener, scenario, deadline.Token);
        try
        {
            if (scenario == "distinct")
            {
                using LiveTokens tokens = await LiveRunner.MintAsync(origin, principals, deadline.Token);
                await wire;
                foreach (LiveRole role in Enum.GetValues<LiveRole>())
                    await Assert.That(tokens.Reveal(role)).IsEqualTo($"synthetic-token-{(int)role}");
            }
            else
            {
                var failure = await Assert.That(async () =>
                {
                    using LiveTokens tokens = await LiveRunner.MintAsync(origin, principals, deadline.Token);
                }).Throws<ProvisioningException>();
                await wire;
                await Assert.That(failure!.Message).IsEqualTo(scenario == "identity"
                    ? "Live fixture identities must be distinct."
                    : "Live fixture bearer tokens must be distinct.");
                if (scenario == "identity")
                    await Assert.That(listener.Pending()).IsFalse();
            }
        }
        finally
        {
            deadline.Cancel();
            listener.Stop();
            try { await wire; }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        }
    }

    [Test]
    [Arguments("valid")]
    [Arguments("empty")]
    [Arguments("duplicate")]
    [Arguments("linked")]
    [Arguments("oversize")]
    public async Task NativeQualificationRequiresBoundedExplicitSettingsWithoutFollowingLinks(string scenario)
    {
        DirectoryInfo root = Directory.CreateTempSubdirectory("secretkit-native-inputs-");
        try
        {
            string request = Path.Combine(root.FullName, "request.json");
            var input = new NativeHostInputs("development", "Infisical", "live-conformance", "linux-x64-net10.0",
                new string('1', 40), 1, 1, 1, [], []);
            await File.WriteAllBytesAsync(request, JsonSerializer.SerializeToUtf8Bytes(input, NativeRunProtocol.JsonOptions));
            string template = Path.Combine(root.FullName, "template.json");
            if (scenario == "linked") File.CreateSymbolicLink(template, request);
            else
            {
                using FileStream file = LiveProcess.OpenPrivate(template);
                if (scenario == "oversize") file.SetLength(1024 * 1024 + 1);
                else await file.WriteAsync(Encoding.UTF8.GetBytes(scenario switch
                {
                    "empty" => """{"families":{}}""",
                    "duplicate" => """{"families":{"operation":{},"operation":{}}}""",
                    _ => """{"families":{"operation":{"explicitInput":"synthetic"}}}"""
                }));
            }

            if (scenario == "valid")
            {
                using NativeLiveInputs loaded = await NativeLiveInputs.LoadAsync(root.FullName, request, template, CancellationToken.None);
                await Assert.That(loaded.Request.Provider).IsEqualTo("Infisical");
            }
            else
            {
                var failure = await Assert.That(async () =>
                {
                    using NativeLiveInputs loaded = await NativeLiveInputs.LoadAsync(root.FullName, request, template, CancellationToken.None);
                }).Throws<ProvisioningException>();
                await Assert.That(failure!.Message).IsEqualTo("Native request or settings template was rejected.");
            }
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    [Arguments("success")]
    [Arguments("nonzero")]
    [Arguments("throws")]
    [Arguments("canceled")]
    public async Task ProtectsEphemeralSettingsAndCapturesOnlySafeChildEvidence(string scenario)
    {
        using var cancellation = new CancellationTokenSource();
        DirectoryInfo root = Directory.CreateTempSubdirectory("secretkit-live-runner-");
        string? settings = null;
        const string secret = "offline-client-secret-canary";
        const string bearer = "offline-bearer-canary";
        string live = Path.Combine(root.FullName, "artifacts", "live");
        var start = new ProcessStartInfo("/bin/sh");
        start.Environment["SECRETKIT_LIVE_INHERITED"] = secret;
        start.Environment["secretkit_native_inherited"] = bearer;
        start.Environment["INFISICAL_REMOTE_AUTOMATION_CLIENT_SECRET"] = secret;
        start.Environment["AWS_SESSION_TOKEN"] = bearer;
        start.Environment["UNRELATED_SECRET"] = secret;
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add("""
            [ -z "${SECRETKIT_LIVE_INHERITED+x}${secretkit_native_inherited+x}${INFISICAL_REMOTE_AUTOMATION_CLIENT_SECRET+x}${AWS_SESSION_TOKEN+x}${UNRELATED_SECRET+x}" ] || exit 91
            [ "$SECRETKIT_NATIVE_SELECTION" = selected ] && [ -r "$SECRETKIT_NATIVE_SETTINGS" ] || exit 92
            printf '%s\n' "$1" INSTALLED_BOOTSTRAP_CONFIGURATION_AND_ASSESSMENT_PASSED
            printf '%s\n' "$2" >&2
            exit "$3"
            """);
        start.ArgumentList.Add("live-runner-test");
        start.ArgumentList.Add(secret);
        start.ArgumentList.Add(bearer);
        start.ArgumentList.Add(scenario == "nonzero" ? "37" : "0");
        var command = new LiveCommand(start, new Dictionary<string, string> { ["SECRETKIT_NATIVE_SELECTION"] = "selected" },
            writer => writer.WriteStringValue(bearer));
        try
        {
            Task<int> run = LiveProcess.RunAsync(root.FullName, command, cancellation.Token, async (child, evidence, token) =>
            {
                settings = child.Environment["SECRETKIT_NATIVE_SETTINGS"];
                await Assert.That(Path.GetDirectoryName(settings)).IsEqualTo(live);
                if (OperatingSystem.IsLinux())
                    await Assert.That(File.GetUnixFileMode(settings!)).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
                await Assert.That(JsonSerializer.Deserialize<string>(File.ReadAllText(settings!))).IsEqualTo(bearer);
                if (scenario == "throws") throw new IOException(secret);
                if (scenario == "canceled")
                {
                    cancellation.Cancel();
                    token.ThrowIfCancellationRequested();
                }
                return await LiveProcess.StartAsync(child, evidence, token);
            });
            if (scenario == "throws")
                await Assert.That(async () => await run).Throws<ProvisioningException>();
            else if (scenario == "canceled")
                await Assert.That(async () => await run).Throws<OperationCanceledException>();
            else
                await Assert.That(await run).IsEqualTo(scenario == "nonzero" ? 37 : 0);

            await Assert.That(settings).IsNotNull();
            await Assert.That(File.Exists(settings)).IsFalse();
            string log = File.ReadAllText(Directory.GetFiles(live, "*.log").Single());
            await Assert.That(log.Contains(secret, StringComparison.Ordinal) ||
                log.Contains(bearer, StringComparison.Ordinal)).IsFalse();
            if (scenario is "success" or "nonzero")
                await Assert.That(log.Contains("INSTALLED_BOOTSTRAP_CONFIGURATION_AND_ASSESSMENT_PASSED",
                    StringComparison.Ordinal)).IsTrue();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    private static async Task ServeLogins(TcpListener listener, string scenario, CancellationToken token)
    {
        int count = scenario == "token" ? 2 : 5;
        for (int index = 0; index < count; index++)
        {
            using TcpClient client = await listener.AcceptTcpClientAsync(token);
            await using NetworkStream stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            string? requestLine = await reader.ReadLineAsync(token);
            int length = 0;
            while (await reader.ReadLineAsync(token) is { Length: > 0 } header)
                if (header.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                    length = int.Parse(header.AsSpan("Content-Length:".Length), CultureInfo.InvariantCulture);
            if (requestLine != "POST /api/v1/auth/universal-auth/login HTTP/1.1" || length is <= 0 or > 1024)
                throw new InvalidOperationException("Expected a bounded Universal Auth login.");
            char[] body = new char[length];
            if (await reader.ReadBlockAsync(body.AsMemory(), token) != length)
                throw new InvalidOperationException("Truncated Universal Auth login.");
            using JsonDocument login = JsonDocument.Parse(new string(body));
            int role = int.Parse(login.RootElement.GetProperty("clientId").GetString()!.AsSpan("synthetic-id-".Length),
                CultureInfo.InvariantCulture);
            if (login.RootElement.GetProperty("clientSecret").GetString() != $"synthetic-secret-{role}")
                throw new InvalidOperationException("Unexpected explicit principal selection.");
            string payload = JsonSerializer.Serialize(new
            {
                accessToken = $"synthetic-token-{(scenario == "token" ? 0 : role)}",
                tokenType = "Bearer",
                expiresIn = 600,
                accessTokenMaxTTL = 600
            });
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n{payload}"), token);
        }
    }

    private sealed class SyntheticPrincipals : IDisposable
    {
        private readonly SecretMaterial[] secrets = Enumerable.Range(0, 5)
            .Select(role => SecretMaterial.FromText($"synthetic-secret-{role}")).ToArray();

        internal LivePrincipal[] Principals(bool shareIdentity) => secrets.Select((secret, role) =>
            new LivePrincipal($"synthetic-identity-{(shareIdentity ? 0 : role)}", $"synthetic-id-{role}", secret)).ToArray();

        public void Dispose()
        {
            foreach (SecretMaterial secret in secrets) secret.Dispose();
        }
    }
}
