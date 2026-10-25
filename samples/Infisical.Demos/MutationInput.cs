using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Samples.Infisical;

internal sealed class MutationInput(DemoInput connection, SecretMaterial value) : IDisposable
{
    internal DemoInput Connection { get; } = connection;
    internal SecretMaterial Value { get; } = value;

    internal static Task<MutationInput> ReadAsync(Stream source, CancellationToken cancellationToken) =>
        DemoInputReader.ReadAsync(source, Parse, cancellationToken);

    private static MutationInput Parse(JsonElement input)
    {
        DemoInputReader.ValidateFields(input, "value");
        DemoInput connection = DemoInput.Create(input,
            SecretMaterial.FromText(DemoInputReader.Text(input, "token", 16384)));
        try
        {
            return new MutationInput(connection,
                SecretMaterial.FromText(DemoInputReader.Text(input, "value", 32768)));
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Value.Dispose();
        Connection.Dispose();
    }

    public override string ToString() => "[MutationInput]";
}
