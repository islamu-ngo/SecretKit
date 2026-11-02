# SecretKit.Core

BCL-only contracts for provider-selected reads, metadata inventory, bounded
outcomes, disposable material and mutation dispatch evidence. This development
preview makes no provider connection and discovers no credentials by itself.

## Consume a read

Integration fragment: `reader` is your selected `ISecretReader`, `reference` is a
`SecretReference` bound to its authority, and cancellation comes from the host.

```csharp
using SecretKit.Core;

using SecretRead read = await reader.GetSecretAsync(reference, cancellationToken);
int byteCount = read.Material.UseUtf8(static bytes => bytes.Length);
```

`TryGetSecretAsync` returns `null` only for `SecretStatus.Absent`; other failed
outcomes throw `SecretUnavailableException`. Its message uses bounded status and
failure reason, excluding provider payloads and protected coordinates. Cancellation
still propagates as cancellation.

For explicit control, call `ReadAsync` and branch with `TryGetValue` or `Match`.
`GetValueOrThrow` returns the same successful value; none of these helpers copy or
dispose it. `SecretStatusExtensions` classifies statuses without authorizing retries.

## Own the material lifetime

`SecretMaterial.Use` and `UseUtf8` snapshot material before invoking a callback.
They support state arguments without captured closures. A concurrent or reentrant
`Dispose` cannot clear the callback snapshot while it is in use. Temporary buffers
are cleared when the callback returns or throws. Never retain callback spans.

Dispose each successful `SecretRead`. `Reveal()` creates an ordinary managed
string, and downstream copies are outside the SDK buffer lifetime. No managed
API promises process-wide erasure.

Metadata inventory is not value access or a point-in-time remote snapshot.
`MutationReceipt` records dispatch evidence; retry timing and transient status
alone never authorize replay after a possible remote effect.

See the [Core guide](../../docs/public/core-api.md),
[security and ownership](../../docs/public/security-and-ownership.md), and
[current preview](../../docs/public/current-preview.md).
