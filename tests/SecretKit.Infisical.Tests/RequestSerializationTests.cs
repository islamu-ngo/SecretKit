using System.Text;
using SecretKit.Infisical;

namespace SecretKit.Infisical.Tests;

public sealed class RequestSerializationTests
{
    [Test]
    public async Task OversizedSingleTokenReservationIsRejectedBeforeAllocation()
    {
        using var buffer = new InfisicalOperationBudget.RequestBuffer(1024);
        await Assert.That(() => buffer.GetMemory(100_000)).Throws<NotSupportedException>();
    }

    [Test]
    public async Task ActualEncodedBytesCannotAdvancePastTheBodyBudget()
    {
        using var buffer = new InfisicalOperationBudget.RequestBuffer(1024);
        buffer.GetMemory(4096).Span[..1025].Fill(17);
        await Assert.That(() => buffer.Advance(1025)).Throws<NotSupportedException>();
        await Assert.That(buffer.ToArray().Length).IsEqualTo(0);
    }

    [Test]
    public async Task WriterWorstCaseReservationDoesNotRejectFittingAscii()
    {
        string value = new('x', 800);
        byte[] encoded = InfisicalOperationBudget.Serialize(writer => writer.WriteStringValue(value), 1024);
        await Assert.That(encoded.SequenceEqual(Encoding.UTF8.GetBytes("\"" + value + "\""))).IsTrue();
        byte[] rejected = InfisicalOperationBudget.Serialize(
            writer => writer.WriteStringValue(new string('\u00e9', 600)), 1024);
        await Assert.That(rejected.Length).IsEqualTo(0);
    }
}
