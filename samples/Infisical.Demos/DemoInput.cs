using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Samples.Infisical;

// Owns one selected credential; callers dispose it after their client stops.
internal sealed class DemoInput : IDisposable
{
    private readonly SecretMaterial? _token;

    private DemoInput(JsonElement input, SecretMaterial? token)
    {
        Origin = new Uri(DemoInputReader.Text(input, "origin", 2048), UriKind.Absolute);
        Project = DemoInputReader.Text(input, "project", 4096);
        Environment = DemoInputReader.Text(input, "environment", 4096);
        Folder = DemoInputReader.Text(input, "folder", 4096);
        Key = DemoInputReader.Text(input, "key", 4096);
        DevelopmentHttp = input.TryGetProperty("allowLoopbackDevelopmentHttp", out var development) &&
            development.GetBoolean();
        ValidateOrigin();
        _token = token;
    }

    internal Uri Origin { get; }
    internal string Project { get; }
    internal string Environment { get; }
    internal string Folder { get; }
    internal string Key { get; }
    internal bool DevelopmentHttp { get; }
    internal SecretMaterial Token => _token ?? throw new InvalidOperationException("Missing selected token.");
    internal SecretMaterial? ExistingToken => _token;

    internal static Task<DemoInput> ReadAsync(Stream source, CancellationToken cancellationToken) =>
        DemoInputReader.ReadAsync(source, Parse, cancellationToken);

    internal static DemoInput Create(JsonElement input, SecretMaterial? token)
    {
        try { return new DemoInput(input, token); }
        catch
        {
            token?.Dispose();
            throw;
        }
    }

    private static DemoInput Parse(JsonElement input)
    {
        DemoInputReader.ValidateFields(input);
        return Create(input, SecretMaterial.FromText(DemoInputReader.Text(input, "token", 16384)));
    }

    private void ValidateOrigin()
    {
        bool secure = Origin.Scheme == Uri.UriSchemeHttps;
        bool localDevelopment = DevelopmentHttp && Origin.Scheme == Uri.UriSchemeHttp && Origin.IsLoopback;
        if ((!secure && !localDevelopment) || Origin.UserInfo.Length != 0 || Origin.Query.Length != 0 ||
            Origin.Fragment.Length != 0 || Origin.AbsolutePath != "/")
            throw new ArgumentException("Invalid origin.");
    }

    public void Dispose() => _token?.Dispose();

    public override string ToString() => "[DemoInput]";
}
