using System.Buffers;
using System.Text;
using System.Text.Json;
using SecretKit.Infisical;
using SecretKit.Internal;

namespace SecretKit.Infisical.Tests;

public sealed class RequestSerializationTests
{
    [Test]
    public async Task OversizedSingleTokenReservationIsRejectedBeforeAllocation()
    {
        using var buffer = new BoundedRequestBuffer(1024);
        await Assert.That(() => buffer.GetMemory(100_000)).Throws<NotSupportedException>();
    }

    [Test]
    public async Task ActualEncodedBytesCannotAdvancePastTheBodyBudget()
    {
        using var buffer = new BoundedRequestBuffer(1024);
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

    [Test]
    public async Task GrowthAndDisposalReturnEveryRentedArrayFullyZeroed()
    {
        var pool = new RecordingPool();
        byte[] written;
        using (var buffer = new BoundedRequestBuffer(64 * 1024, pool))
        {
            for (int chunk = 0; chunk < 16; chunk++)
            {
                buffer.GetSpan(4096)[..4096].Fill((byte)(chunk + 1));
                buffer.Advance(4096);
            }
            written = buffer.ToArray();
        }

        await Assert.That(written.Length).IsEqualTo(64 * 1024);
        await Assert.That(written[^1]).IsEqualTo((byte)16);
        await Assert.That(pool.Returned.Count).IsGreaterThan(1);
        await Assert.That(pool.Returned.All(static zeroed => zeroed)).IsTrue();
        await Assert.That(pool.Outstanding).IsEqualTo(0);
    }

    [Test]
    public async Task FailedSerializationStillZeroesReservedBytesBeyondTheCommittedCount()
    {
        var pool = new RecordingPool();
        var buffer = new BoundedRequestBuffer(1024, pool);
        await Assert.That(() =>
        {
            using (buffer)
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStringValue("value-canary");
                writer.Flush();
                buffer.GetSpan(16)[..16].Fill(0x5A);
                throw new InvalidOperationException("writer failed");
            }
        }).Throws<InvalidOperationException>();

        buffer.Dispose();
        await Assert.That(pool.Returned).IsEquivalentTo(new[] { true });
        await Assert.That(pool.Outstanding).IsEqualTo(0);
    }

    // Rented arrays start dirty so a zeroed return proves the whole array, not a slice, was wiped.
    private sealed class RecordingPool : ArrayPool<byte>
    {
        internal List<bool> Returned { get; } = [];
        internal int Outstanding { get; private set; }

        public override byte[] Rent(int minimumLength)
        {
            Outstanding++;
            byte[] array = new byte[minimumLength + 31];
            array.AsSpan().Fill(0xAA);
            return array;
        }

        public override void Return(byte[] array, bool clearArray = false)
        {
            Outstanding--;
            Returned.Add(!array.AsSpan().ContainsAnyExcept((byte)0));
        }
    }
}
