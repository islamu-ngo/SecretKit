using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using Azure;
using Azure.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// The parser receives source-owned bytes and the exact validated header/status
// snapshot. Host getters and ignored host setters cannot substitute its input.
// Dispose is deliberately not storage release: the invocation owns that lifetime.
internal sealed class OwnedArmResponse : Response
{
    private readonly HttpHeader[] headers;
    private readonly int status;
    private readonly string reason;
    private string clientRequestId;
    private Stream? content;

    internal OwnedArmResponse(int status, string reason, string clientRequestId,
        IEnumerable<HttpHeader> validatedHeaders, Stream content)
    {
        this.status = status;
        this.reason = reason;
        this.clientRequestId = clientRequestId;
        headers = validatedHeaders.ToArray();
        this.content = content;
    }

    public override int Status => status;
    public override string ReasonPhrase => reason;
    public override string ClientRequestId { get => clientRequestId; set => clientRequestId = value; }
    public override Stream? ContentStream { get => content; set => content = value; }
    public override void Dispose() { }
    protected override bool ContainsHeader(string name) =>
        headers.Any(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    protected override IEnumerable<HttpHeader> EnumerateHeaders() => headers.ToArray();
    protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
    {
        value = headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
        return value is not null;
    }
    protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
    {
        bool found = TryGetHeader(name, out var value);
        values = found ? [value!] : null;
        return found;
    }

    internal sealed class Storage : IDisposable
    {
        private readonly List<IDisposable> items = [];
        private readonly List<byte[]> bytes = [];
        internal void Own(IDisposable item) => items.Add(item);
        internal void Own(byte[] value) => bytes.Add(value);
        public void Dispose()
        {
            bool failed = false;
            foreach (var item in items.Distinct<IDisposable>(ReferenceEqualityComparer.Instance))
                try { item.Dispose(); }
                catch (Exception) { failed = true; }
            items.Clear();
            foreach (var value in bytes) CryptographicOperations.ZeroMemory(value);
            bytes.Clear();
            Require(!failed);
        }
    }

    internal sealed record Body(OwnedArmResponse Response, ReadOnlyMemory<byte> Bytes, string Sha256,
        string NativeRequestId)
    {
        public override string ToString() => "[OwnedArmBody]";
    }

    // Opt-in only. Capturing a body is not evidence that the actual native
    // parser received it, and disposing a displaced response proves nothing.
    internal sealed class ParserCustody
    {
        private readonly HttpMessage message;
        private readonly Storage storage;
        private readonly byte[] bytes;
        private readonly bool requireRebuffer;
        private readonly bool requireDownstreamRead;
        private readonly Envelope envelope;
        private readonly AccountingStream initial;
        private AccountingStream? downstream;
        private bool invalid;

        private ParserCustody(HttpMessage message, OwnedArmResponse response,
            ReadOnlyMemory<byte> capturedBytes, Storage storage, bool requireRebuffer, bool requireDownstreamRead)
        {
            this.message = message;
            this.storage = storage;
            this.requireRebuffer = requireRebuffer;
            this.requireDownstreamRead = requireDownstreamRead;
            bytes = capturedBytes.ToArray();
            Require(bytes.Length > 0);
            storage.Own(bytes);
            initial = new(bytes, Check, requireRebuffer);
            storage.Own(initial);
            envelope = new(this, response);
        }

        internal static ParserCustody Install(HttpMessage message, OwnedArmResponse response,
            ReadOnlyMemory<byte> capturedBytes, Storage storage, bool requireRebuffer, bool requireDownstreamRead = true)
        {
            Require(ReferenceEquals(message.Response, response));
            var custody = new ParserCustody(message, response, capturedBytes, storage, requireRebuffer, requireDownstreamRead);
            message.Response = custody.envelope;
            return custody;
        }

        private void Check()
        {
            if (message.HasResponse && !ReferenceEquals(message.Response, envelope)) invalid = true;
        }
        internal bool Invalid { get { Check(); return invalid; } }
        internal bool Complete => !Invalid && initial.Complete &&
            (downstream is null ? !requireRebuffer : !requireDownstreamRead || downstream.Complete);
        internal bool Owns(Response response) => ReferenceEquals(response, envelope) && Complete;

        private void Rebuffer(Stream? value)
        {
            Check();
            // Both ControlledTransport and native RequestFailedException buffer
            // a fully consumed stream. Neither may substitute different bytes.
            // The native error reader can buffer the adapter's buffer again.
            if (downstream is { Complete: false } || !initial.Complete ||
                value is not MemoryStream buffer || !buffer.CanRead || !buffer.CanSeek)
            {
                invalid = true;
                return;
            }
            storage.Own(buffer);
            // ToArray does not change Position and works for non-exposable buffers.
            byte[] copy = buffer.ToArray();
            storage.Own(copy);
            if (buffer.Position != 0 || !copy.AsSpan().SequenceEqual(bytes))
            {
                invalid = true;
                return;
            }
            downstream = new(bytes, Check, false);
            storage.Own(downstream);
        }

        private sealed class Envelope(ParserCustody custody, OwnedArmResponse response) : Response
        {
            // Native model/error readers use Response.Content, whose default
            // implementation requires a MemoryStream. Read our accounting stream
            // instead of bypassing its evidence or claiming that a getter parsed it.
            public override BinaryData Content
            {
                get
                {
                    custody.Check();
                    Stream stream = custody.downstream ?? custody.initial;
                    long position = stream.Position;
                    byte[] copy = new byte[custody.bytes.Length];
                    custody.storage.Own(copy);
                    try
                    {
                        stream.Position = 0;
                        stream.ReadExactly(copy);
                        return BinaryData.FromBytes(copy);
                    }
                    finally { stream.Position = position; }
                }
            }
            public override int Status { get { custody.Check(); return response.Status; } }
            public override string ReasonPhrase { get { custody.Check(); return response.ReasonPhrase; } }
            public override string ClientRequestId
            {
                get { custody.Check(); return response.ClientRequestId; }
                set { custody.Check(); if (value != response.ClientRequestId) custody.invalid = true; }
            }
            public override Stream? ContentStream
            {
                get { custody.Check(); return custody.downstream ?? custody.initial; }
                set => custody.Rebuffer(value);
            }
            public override void Dispose() => custody.Check();
            protected override bool ContainsHeader(string name)
            { custody.Check(); return response.Headers.Contains(name); }
            protected override IEnumerable<HttpHeader> EnumerateHeaders()
            { custody.Check(); return response.Headers.ToArray(); }
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
            { custody.Check(); return response.Headers.TryGetValue(name, out value); }
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
            { custody.Check(); return response.Headers.TryGetValues(name, out values); }
        }

        private sealed class AccountingStream(byte[] bytes, Action check, bool requireEof) : Stream
        {
            private int position, covered;
            private bool eof;
            internal bool Complete => covered == bytes.Length && (!requireEof || eof);
            public override bool CanRead => true;
            public override bool CanSeek => true;
            public override bool CanWrite => false;
            public override long Length { get { check(); return bytes.Length; } }
            public override long Position
            {
                get { check(); return position; }
                set
                {
                    check();
                    if (value < 0 || value > bytes.Length) throw new ArgumentOutOfRangeException(nameof(value));
                    position = (int)value;
                }
            }
            public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
            public override int Read(Span<byte> buffer)
            {
                check();
                int count = Math.Min(buffer.Length, bytes.Length - position);
                bytes.AsSpan(position, count).CopyTo(buffer);
                if (position <= covered) covered = Math.Max(covered, position + count);
                position += count;
                if (buffer.Length != 0 && count == 0 && position == bytes.Length) eof = true;
                return count;
            }
            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.FromResult(Read(buffer.Span));
            }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
                ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
            public override long Seek(long offset, SeekOrigin origin)
            {
                Position = origin switch
                {
                    SeekOrigin.Begin => offset,
                    SeekOrigin.Current => position + offset,
                    SeekOrigin.End => bytes.Length + offset,
                    _ => throw new ArgumentOutOfRangeException(nameof(origin))
                };
                return position;
            }
            public override void Flush() => check();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            protected override void Dispose(bool disposing) => check();
        }
    }

    // The caller retains the host response even if its send throws. Capture
    // adds the actual stream before awaiting it; timeout never releases storage.
    internal static async Task<Body> CaptureAsync(HttpMessage message, int maximum, Storage storage,
        bool allowContinuation = false)
    {
        var original = message.Response;
        storage.Own(original);
        int status = original.Status;
        string reason = original.ReasonPhrase, request = original.ClientRequestId;
        var headers = original.Headers.Take(33).ToArray();
        Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => h.Name.Length is > 0 and <= 128 &&
                h.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                h.Value.Length <= 16384 && !h.Value.Any(char.IsControl)) &&
            reason.Length <= 256 && !reason.Any(char.IsControl) &&
            request.Length <= 1024 && !request.Any(char.IsControl));
        string? Header(string name) => headers.FirstOrDefault(h =>
            h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
        Require(new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Retry-After", "WWW-Authenticate" }
            .All(n => Header(n) is null));
        Require(allowContinuation ||
            new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }.All(n => Header(n) is null));
        string? type = Header("Content-Type"), nativeId = Header("x-ms-request-id");
        Require(type is not null && type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
            nativeId is { Length: > 0 and <= 256 } && nativeId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'));
        long? declared = null;
        if (Header("Content-Length") is { } text)
        {
            Require(long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long length) &&
                length >= 0 && length <= maximum);
            declared = length;
        }
        byte[] bytes = new byte[maximum + 1];
        storage.Own(bytes);
        int count = 0;
        if (original.ContentStream is { } input)
        {
            storage.Own(input);
            int read;
            while ((read = await input.ReadAsync(bytes.AsMemory(count), message.CancellationToken).ConfigureAwait(false)) != 0)
            {
                count += read;
                Require(count <= maximum);
            }
        }
        message.CancellationToken.ThrowIfCancellationRequested();
        Require(count > 0 && count <= maximum && (declared is null || declared == count) &&
            ReferenceEquals(message.Response, original) && original.Status == status &&
            headers.SequenceEqual(original.Headers) && original.ReasonPhrase == reason &&
            original.ClientRequestId == request);
        var stream = new MemoryStream(bytes, 0, count, false, false);
        storage.Own(stream);
        var response = new OwnedArmResponse(status, reason, request, headers, stream);
        message.Response = response;
        return new(response, bytes.AsMemory(0, count),
            Convert.ToHexString(SHA256.HashData(bytes.AsSpan(0, count))), nativeId!);
    }

    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new InvalidOperationException("owned-arm-response");
    }
    public override string ToString() => "[OwnedArmResponse]";
}
