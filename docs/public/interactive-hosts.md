# Interactive operator hosts

Use an explicitly selected identity and a short, bounded workflow. The
[offline operator sample](../../samples/Infisical.OperatorWorkflow/Program.cs)
demonstrates Universal Auth, value-free inspection, reviewed bulk updates,
intended-identity reads and explicit sign-out. Its HTTP handler holds synthetic
state and never contacts a provider. It is a host example, not a provisioning
framework or native qualification.

```bash
dotnet run --project samples/Infisical.OperatorWorkflow --configuration Release
```

Run from the checkout with the pinned .NET SDK. The successful run prints
`REVIEWED_TWO_UPDATES`, `APPLY_Applied`, `READY` and `SIGNOUT_Applied`.
The sample is nonpackable and source-referenced by Consumer tests; it does not
qualify installed package archives.

## Select credentials and retain their owners

Universal Auth remains the pilot. Inject bootstrap material through a protected
host channel, retain `CreateReceipt()` before login, check the outcome, and
dispose the successful login. Do not copy the sample's synthetic credentials
into a deployment. For supplied tokens, `InfisicalSuppliedTokenSource` copies
borrowed material, returns a new owned token on each acquisition and disposes
only its copy. Supply observed expiry when known; null expiry does not establish
remote validity. Source disposal never revokes a token or renews it.

Runtime and administrative credentials are separate selections. The sample's
Management grant uses independently approved organization/project coordinates;
its mutation authority is selected explicitly. Neither an admin view nor
describe-only inventory proves that the intended runtime identity can read
required material. Do not use admin credentials as a fallback after denial.

Machine OIDC is not human delegation. Delegated OAuth remains deferred:
token exchange needs organization-owned confidential middleware, while
authorization code is currently read-only and has its own client-secret custody
decision. Follow [authentication and hosting](authentication-and-hosting.md#interactive-operator-tools)
and [ADR-006](../internal/adr/ADR-006-configurator-provisioning-and-credential-sources.md).
Configurator's separate ADR and clients have not been changed.

## Inspect, review, recheck and apply

1. Inspect `ProjectSummary.AutoCapitalization` using separately selected
   Management authority. Omission, explicit null, false and true are distinct;
   check presence/null before accessing the value. Unknown required policy
   blocks this host's automatic apply.
2. Call `InspectNativeAsync` with explicit namespace and item/folder/request/
   byte/depth/time budgets. Value reading, reference expansion and personal
   overrides remain disabled. `IsComplete` describes only the selected visible
   view; it never proves ACL completeness or absence of hidden resources.
3. Review exact canonical keys. A direct target needs a returned revision and
   explicit `IsRotatedSecret == false`. Null rotation is unknown. Imported
   candidates retain ordered groups and source metadata; they have no direct
   writable reference/revision and establish no effective winner. This sample
   refuses imported, managed, ambiguous and incomplete targets.
4. Read required material through the intended runtime identity before apply.
   Reinspect metadata immediately before dispatch and stop on changed revisions
   or unestablished coverage. Missing revisions, ancestry, provenance or exhausted
   bounds remain incomplete. A revision recheck is an observation, not CAS or
   a guaranteed rotation lock; provider state may change immediately afterward.
5. Retain `InfisicalBulkReceipt` before calling the typed update. A successful
   envelope is insufficient: require `AllApplied` and no `ApprovalPending`.
   Pending needs separately authorized operator/provider follow-up. Partial
   application, lost responses and cancellation preserve per-item receipts;
   stop without replay or guessed reconciliation.
6. Verify delivery through the intended identity, dispose returned material,
   then explicitly sign out. Read success proves delivery only for that
   observation, not future permission or application readiness.

The sample approves a fixed synthetic two-key intent for demonstration. A real
interactive host must obtain operator approval of the exact proposed changes.
It must also own value validation, durable recovery evidence and application
activation. The SDK does not provide a human review UI.

## Create folders and delete explicitly

The executable [composition recipes](../../tests/SecretKit.Consumer.Tests/OperatorCompositionTests.cs)
show two reviewed path segments. List a bounded complete child view; explicitly
create a reviewed missing child with its own retained receipt. A confirmed
conflict may be inspected once to verify the expected child's environment,
name and returned path. Unknown creation stops immediately; do not treat a
timeout as absence or replay creation. No secret operation assumes that missing
folders are created automatically.

For a single deletion, construct one `InfisicalBulkSecret` without material,
an `InfisicalBulkAddress`, and an `InfisicalBulkReceipt` selecting `Delete`,
then call `DeleteSecretsAsync`. Inspect its outcome and item evidence. A lost
acknowledgment may accompany an actual deletion; retain uncertainty and stop.
The recipes exercise this with actual backend state, not a second policy model.

## Own networking, renewal, sign-out and support

Use safe networking by default. A private issuer can use
`InfisicalTransportOptions.SafeWithPrivateTrust(roots)` with selected public
certificates and normal hostname/chain validation. Explicit proxy configuration
belongs in `InfisicalNetworkOptions.Proxy`. The host owns borrowed credentials,
clients and handlers; dispose them after their accepted operations drain.
The sample selects `HostControlled(handler)` solely for offline transport.
A real arbitrary host pipeline controls TLS, redirects, retries and logging;
the SDK cannot enforce safe-network guarantees within it.

Token acquisition does not renew. Select independently established lifetime
evidence and call renewal explicitly or opt into the documented maintenance
helper. Observe the renewal outcome separately from session recovery state;
neither retry advice nor a 429 authorizes automatic replay or re-login.
On recovery, obtain a newly authorized handoff for the selected identity.

Sign-out is an explicit `RevokeTokenAsync` operation with a caller-held receipt,
bounded cancellation and an outcome. An acknowledgement is not independent
proof of remote invalidation. Source disposal clears local copies only.
The sample attempts sign-out once even after workflow failure; uncertain
sign-out returns a failed exit and is never retried.

Report closed status/reason, safe receipt evidence and, only through an
explicitly authorized support channel, protected correlation metadata.
Do not print secret values, tokens, keys, coordinates, provider prose, approval
IDs or full inventory objects. The [workflow tests](../../tests/SecretKit.Consumer.Tests/OperatorWorkflowTests.cs)
exercise the real entrypoint for denial, concealed routes, incomplete metadata,
pending/partial/lost responses and disclosure. Offline results establish no
issuer acceptance, hosted platform success, edition availability or production readiness.
