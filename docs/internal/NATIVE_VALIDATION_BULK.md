# Native bulk evidence and retained receipts

This is an offline-tested development preview, not native deployment
qualification or a remote transaction guarantee.

Create, update and delete batches require a caller-held `InfisicalBulkReceipt`.
Construct it before awaiting with the exact client, target object, ordered input
selectors, operation and update mode. It stores no secret values or value hashes.
Key, rename, type and path selectors are protected coordinates, not log fields.
The receipt is not an attestation of submitted plaintext.

```csharp
var receipt = new InfisicalBulkReceipt(
    client, target, inputs, InfisicalBulkOperation.Create);
var outcome = await client.CreateSecretsAsync(target, inputs, authority, receipt, cancellationToken);
```

This is a composition fragment; the host supplies the selected typed client,
target, inputs, authority and cancellation token.

## Evidence boundaries

- Before handoff, every item is NotDispatched. One envelope handoff marks every
  included ordinal PossiblyDispatched before the sending await.
- Supported response rows refine only their matching ordinal. Missing rows stay
  uncertain; the SDK does not infer success from HTTP status or array position.
- A contradictory, duplicate or malformed later row rejects the batch response
  without erasing earlier observations. Item snapshots remain accessible through
  the receipt after a failed outcome or OperationCanceledException.
- A supported approval response records Pending, not Applied. Complete observed
  item success can refine the envelope to Applied; an empty collection cannot
  establish AllApplied.
- A lost response may follow a real native effect. Never replay that receipt.
  Reconcile using an independently authorized read or explicit operator action.

`Items` returns an immutable snapshot; older snapshots never mutate. Construct a
fresh receipt for each intended invocation. A receipt admitted once cannot be
reused even if acquisition failed before dispatch. Foreign clients, changed
target references, order, operation, mode or selectors fail before acquisition.
Caller-owned material remains caller-owned; bulk serialization is an explicit
managed-plaintext boundary.

The generic reader keeps strict duplicate-property parsing. Bulk parsing alone
permits initial structural materialization so that each response row can be
checked in order for duplicate properties and scope contradictions, preserving
earlier supported evidence. Root and non-item properties remain validated.
Depth and response-byte bounds remain unchanged.

## Offline evidence

`BulkReceiptTests` covers malformed/foreign/duplicate later rows, immutable
snapshots, post-dispatch cancellation, response loss, changed intent and empty
batches. `ImportEffectTests` retains native mode, rename, pending approval,
partial application and response-loss cases. Controlled backend state is an
effect oracle; these tests do not qualify an actual Infisical edition or issuer.
