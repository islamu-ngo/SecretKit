using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Xml.Linq;

namespace SecretKit.Release;

public sealed class NativeFeed(string certificateSha256, string owner, string? apiKey = null) : IPackageFeed
{
    internal Func<HttpClient> ClientFactory { get; init; } = CreateClient;
    internal Action? AuthorizePush { get; init; }

    public async Task<byte[]?> DownloadAsync(string id, string version, CancellationToken cancellationToken)
    {
        Guard.Require(Manifest.PackageIds.Contains(id), "feed-package");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        using HttpClient client = ClientFactory();
        string lowerId = id.ToLowerInvariant();
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://api.nuget.org/v3-flatcontainer/{lowerId}/{Uri.EscapeDataString(version)}/{lowerId}.{Uri.EscapeDataString(version)}.nupkg");
        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        Guard.Require(response.StatusCode == HttpStatusCode.OK &&
            response.Content.Headers.ContentLength is null or <= PackageArchive.MaximumBytes, "feed-read");
        using Stream source = await response.Content.ReadAsStreamAsync(timeout.Token);
        using var output = new MemoryStream();
        byte[] buffer = new byte[8192];
        while (true)
        {
            int read = await source.ReadAsync(buffer, timeout.Token);
            if (read == 0)
            {
                break;
            }

            Guard.Require(output.Length + read <= PackageArchive.MaximumBytes, "feed-budget");
            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    public async Task<bool> PushAsync(string id, byte[] package, CancellationToken cancellationToken)
    {
        Guard.Require(Manifest.PackageIds.Contains(id) && package.Length <= PackageArchive.MaximumBytes, "push-package");
        Guard.Require(apiKey is { Length: > 0 and <= 4096 } && !apiKey.Any(char.IsControl), "publish-credential");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(120));
        // One request on a fresh connection. No redirects, duplicate skipping,
        // status retries, token refresh, fallback source or mutation replay.
        using HttpClient client = ClientFactory();
        using var request = new HttpRequestMessage(HttpMethod.Put, "https://www.nuget.org/api/v2/package")
        {
            Version = HttpVersion.Version11,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact
        };
        request.Headers.ConnectionClose = true;
        request.Headers.Add("X-NuGet-ApiKey", apiKey);
        request.Headers.Add("X-NuGet-Protocol-Version", "4.1.0");
        using var body = new MultipartFormDataContent();
        using var content = new ByteArrayContent(package);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        body.Add(content, "package", id + ".nupkg");
        request.Content = body;
        Guard.Require(AuthorizePush is not null, "mutation-authorization-required");
        AuthorizePush!();
        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        return response.StatusCode is HttpStatusCode.Created or HttpStatusCode.Accepted;
    }

    public async Task VerifySignatureAsync(byte[] package, CancellationToken cancellationToken)
    {
        Guard.Require(Manifest.IsHash(certificateSha256), "signer-approval");
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-release-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string packagePath = Path.Combine(directory, "download.nupkg");
            string configPath = Path.Combine(directory, "NuGet.Config");
            await File.WriteAllBytesAsync(packagePath, package, cancellationToken);
            await File.WriteAllTextAsync(Path.Combine(directory, "global.json"),
                """{"sdk":{"version":"10.0.302","rollForward":"disable"}}""", cancellationToken);
            new XDocument(new XElement("configuration",
                new XElement("packageSources", new XElement("clear")),
                new XElement("config", new XElement("add",
                    new XAttribute("key", "signatureValidationMode"), new XAttribute("value", "require"))),
                new XElement("trustedSigners", new XElement("clear"),
                    new XElement("repository", new XAttribute("name", "nuget.org"),
                        new XAttribute("serviceIndex", "https://api.nuget.org/v3/index.json"),
                        new XElement("certificate", new XAttribute("fingerprint", certificateSha256),
                            new XAttribute("hashAlgorithm", "SHA256"), new XAttribute("allowUntrustedRoot", "false")),
                        new XElement("owners", owner))))).Save(configPath);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMinutes(2));
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo("dotnet")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = directory
                }
            };
            foreach (string argument in new[] { "nuget", "verify", packagePath, "--all",
                "--certificate-fingerprint", certificateSha256, "--configfile", configPath, "--verbosity", "quiet" })
            {
                process.StartInfo.ArgumentList.Add(argument);
            }

            process.StartInfo.Environment.Remove("NUGET_API_KEY");
            process.StartInfo.Environment.Remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
            process.StartInfo.Environment.Remove("ACTIONS_ID_TOKEN_REQUEST_URL");
            process.StartInfo.Environment.Remove("GH_TOKEN");
            process.StartInfo.Environment.Remove("GITHUB_TOKEN");
            process.Start();
            Task stdout = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, timeout.Token);
            Task stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token);
                await Task.WhenAll(stdout, stderr);
                Guard.Require(process.ExitCode == 0, "native-signature-verification");
            }
            catch
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }

                await process.WaitForExitAsync(CancellationToken.None);
                try
                {
                    await Task.WhenAll(stdout, stderr);
                }
                catch (OperationCanceledException)
                {
                    // The original bounded verification failure is retained.
                }

                throw;
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            Credentials = null,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(15),
            MaxResponseHeadersLength = 16
        })
        {
            Timeout = Timeout.InfiniteTimeSpan,
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SecretKit.Release/1.0");
        return client;
    }
}
