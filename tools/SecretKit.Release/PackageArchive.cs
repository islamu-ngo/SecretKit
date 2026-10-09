using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace SecretKit.Release;

public sealed record ArchiveContent(byte[] Original, bool HasSignature, IReadOnlyDictionary<string, byte[]> Files);

public static class PackageArchive
{
    public const int MaximumBytes = 32 * 1024 * 1024;
    private const int MaximumExpandedBytes = 128 * 1024 * 1024;
    private const string SignatureName = ".signature.p7s";

    private sealed record Entry(string Name, int Central, int CentralLength, int Local, int LocalLength,
        int Data, int Compressed, int Expanded, ushort Method, uint Crc);

    // Deliberately supports only contiguous, single-disk ZIP32, ASCII names, no
    // extra fields/comments/descriptors, stored/deflate regular files. Other valid
    // ZIP variants are unsupported, not normalized into an equivalent archive.
    public static ArchiveContent Read(byte[] bytes)
    {
        Guard.Require(bytes.Length is >= 22 and <= MaximumBytes, "zip-size");
        int end = bytes.Length - 22;
        Guard.Require(U32(bytes, end) == 0x06054b50 && U16(bytes, end + 20) == 0, "zip-eocd");
        Guard.Require(U16(bytes, end + 4) == 0 && U16(bytes, end + 6) == 0, "zip-multidisk");
        int count = U16(bytes, end + 10);
        Guard.Require(count is > 0 and <= 2048 && U16(bytes, end + 8) == count, "zip-count");
        int centralStart = Length(bytes, end + 16);
        int centralSize = Length(bytes, end + 12);
        Guard.Require((long)centralStart + centralSize == end, "zip-directory");
        var entries = new List<Entry>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int cursor = centralStart;
        long expandedTotal = 0;
        for (int i = 0; i < count; i++)
        {
            Range(bytes, cursor, 46);
            Guard.Require(U32(bytes, cursor) == 0x02014b50, "zip-central-header");
            ushort flags = U16(bytes, cursor + 8);
            ushort method = U16(bytes, cursor + 10);
            Guard.Require((flags & ~0x0800) == 0 && method is 0 or 8 &&
                U16(bytes, cursor + 6) <= 20, "zip-format");
            int nameLength = U16(bytes, cursor + 28);
            Guard.Require(U16(bytes, cursor + 30) == 0 && U16(bytes, cursor + 32) == 0 &&
                U16(bytes, cursor + 34) == 0, "zip-extra-or-comment");
            uint attributes = U32(bytes, cursor + 38);
            uint fileType = (attributes >> 16) & 0xf000;
            Guard.Require(fileType is 0 or 0x8000 && (attributes & 0x10) == 0, "zip-file-type");
            Range(bytes, cursor + 46, nameLength);
            ReadOnlySpan<byte> nameBytes = bytes.AsSpan(cursor + 46, nameLength);
            Guard.Require(nameBytes.IndexOfAnyExceptInRange((byte)32, (byte)126) < 0, "zip-name-encoding");
            string name = Encoding.ASCII.GetString(nameBytes);
            Guard.Require(name.Length > 0 && !name.Contains('\\') && !name.Contains(':') &&
                !name.Contains('%') && name.Split('/').All(part => part.Length > 0 && part is not "." and not "..") &&
                names.Add(name), "zip-name");
            Guard.Require(!name.Equals(SignatureName, StringComparison.OrdinalIgnoreCase) || name == SignatureName,
                "zip-signature-name");
            int compressed = Length(bytes, cursor + 20);
            int expanded = Length(bytes, cursor + 24);
            expandedTotal += expanded;
            Guard.Require(expandedTotal <= MaximumExpandedBytes &&
                (method != 0 || compressed == expanded), "zip-expansion");
            int local = Length(bytes, cursor + 42);
            Range(bytes, local, 30);
            Guard.Require(U32(bytes, local) == 0x04034b50 &&
                U16(bytes, local + 4) == U16(bytes, cursor + 6) &&
                U16(bytes, local + 6) == flags && U16(bytes, local + 8) == method &&
                U32(bytes, local + 10) == U32(bytes, cursor + 12) &&
                U32(bytes, local + 14) == U32(bytes, cursor + 16) &&
                U32(bytes, local + 18) == compressed && U32(bytes, local + 22) == expanded &&
                U16(bytes, local + 26) == nameLength && U16(bytes, local + 28) == 0, "zip-local-header");
            Range(bytes, local + 30, nameLength + compressed);
            Guard.Require(bytes.AsSpan(local + 30, nameLength).SequenceEqual(nameBytes), "zip-local-name");
            Guard.Require(name != SignatureName || (method == 0 && flags == 0 && expanded > 0), "zip-signature-format");
            entries.Add(new(name, cursor, 46 + nameLength, local, 30 + nameLength + compressed,
                local + 30 + nameLength, compressed, expanded, method, U32(bytes, cursor + 16)));
            cursor += 46 + nameLength;
        }

        Guard.Require(cursor == end, "zip-directory-length");
        cursor = 0;
        foreach (Entry entry in entries.OrderBy(e => e.Local))
        {
            Guard.Require(entry.Local == cursor, "zip-local-layout");
            cursor += entry.LocalLength;
        }

        Guard.Require(cursor == centralStart, "zip-local-end");
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (Entry entry in entries)
        {
            byte[] content;
            if (entry.Method == 0)
            {
                content = bytes.AsSpan(entry.Data, entry.Expanded).ToArray();
            }
            else
            {
                using var compressed = new MemoryStream(bytes, entry.Data, entry.Compressed, writable: false);
                using var deflate = new DeflateStream(compressed, CompressionMode.Decompress);
                content = new byte[entry.Expanded];
                try
                {
                    deflate.ReadExactly(content);
                    Guard.Require(deflate.ReadByte() == -1, "zip-expanded-length");
                }
                catch (IOException)
                {
                    throw new ReleaseException("zip-deflate");
                }
            }

            Guard.Require(Crc32(content) == entry.Crc, "zip-crc");
            files.Add(entry.Name, content);
        }

        Entry? signature = entries.SingleOrDefault(entry => entry.Name == SignatureName);
        if (signature is null)
        {
            return new(bytes.ToArray(), false, files);
        }

        using var original = new MemoryStream(bytes.Length - signature.LocalLength - signature.CentralLength);
        original.Write(bytes.AsSpan(0, signature.Local));
        int after = signature.Local + signature.LocalLength;
        original.Write(bytes.AsSpan(after, centralStart - after));
        foreach (Entry entry in entries)
        {
            if (entry == signature)
            {
                continue;
            }

            byte[] header = bytes.AsSpan(entry.Central, entry.CentralLength).ToArray();
            if (entry.Local > signature.Local)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(42), (uint)(entry.Local - signature.LocalLength));
            }

            original.Write(header);
        }

        byte[] eocd = bytes.AsSpan(end).ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(eocd.AsSpan(8), (ushort)(count - 1));
        BinaryPrimitives.WriteUInt16LittleEndian(eocd.AsSpan(10), (ushort)(count - 1));
        BinaryPrimitives.WriteUInt32LittleEndian(eocd.AsSpan(12), (uint)(centralSize - signature.CentralLength));
        BinaryPrimitives.WriteUInt32LittleEndian(eocd.AsSpan(16), (uint)(centralStart - signature.LocalLength));
        original.Write(eocd);
        files.Remove(SignatureName);
        Guard.Require(files.Count > 0, "zip-empty-original");
        return new(original.ToArray(), true, files);
    }

    private static void Range(byte[] bytes, int start, int length) =>
        Guard.Require(start >= 0 && length >= 0 && (long)start + length <= bytes.Length, "zip-range");

    private static ushort U16(byte[] bytes, int at)
    {
        Range(bytes, at, 2);
        return BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(at));
    }

    private static uint U32(byte[] bytes, int at)
    {
        Range(bytes, at, 4);
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at));
    }

    private static int Length(byte[] bytes, int at)
    {
        uint value = U32(bytes, at);
        Guard.Require(value <= MaximumExpandedBytes, "zip-length");
        return (int)value;
    }

    private static uint Crc32(byte[] bytes)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in bytes)
        {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0 : 0xedb88320);
            }
        }

        return ~crc;
    }
}
