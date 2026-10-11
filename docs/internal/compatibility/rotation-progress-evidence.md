# Native rotation observation and control evidence

Observed contract date: 2026-10-09. Phase 7.3 is a native metadata/control
slice, not Phase 8.2 connector configuration completion. No live conformance,
edition compatibility, permission entitlement or consumer delivery is claimed.

## Owned observation and edition gate, 2026-10-11

The 30-profile protocol/observer regression passed37/37. A separate positive
owned v0.166.3 case passed1/1: PostgreSQL connection creation, fresh inspection
and actual query of a separate no-host-ingress backend on an owned private
bridge. This is not rotation completion or downstream password-change evidence.

The dedicated rotation scenario reached successful connection creation, then
native rotation creation failed with HTTP400/Rejected:
"Failed to create secret rotation due to plan restriction. Upgrade plan to
create secret rotations." That scenario remains an explicit entitlement gate,
not a passed or skipped case. Manual trigger, provider completion/recovery,
consumer delivery and fleet convergence remain unverified.

## Sources and implementation boundary

The approved task is `dev/active/secretkit-sdk/secretkit-sdk-tasks.md`, Phase 7.3.
The current inventory is `../providers/infisical-operations.json`: 305 current
v2 rotation method/path decisions, 30 profiles. Request/response facts, not
vendor source or generated classes, informed independently authored code.
The registry remains research evidence; this slice does not change its global
`implemented` flags.

Official functional sources:

- [Public API metadata](https://app.infisical.com/api/docs/json), snapshot
  recorded in `dev/active/secretkit-sdk/infisical-contract-facts.md`.
- [Project rotation list](https://infisical.com/docs/api-reference/endpoints/secret-rotations/list.md).
- [PostgreSQL manual rotation](https://infisical.com/docs/api-reference/endpoints/secret-rotations/postgres-credentials/rotate-secrets.md),
  retrieved directly on 2026-10-09 to confirm the bodyless POST and observation
  envelope. Tavily's extraction omitted its embedded OpenAPI; direct retrieval
  supplied the published interface facts, not implementation source.
- [Rotation behavior](https://infisical.com/docs/documentation/platform/secret-rotation/overview):
  overlapping and immediate-invalidation models have different consumer risks.

Files:

- `src/SecretKit.Infisical/InfisicalRotationClient.cs`
- `src/SecretKit.Infisical/InfisicalRotationModels.cs`
- `src/SecretKit.Infisical/InfisicalRotationApi.cs`
- `tests/SecretKit.Infisical.Tests/RotationOutcomeTests.cs`

No Core, existing provider client, management, root project, README, dependency,
registry or existing test file is modified by this slice.
The parent owns the explicitly approved central Refit package/version/reference
and lockfile changes. No official Infisical SDK is used by this rotation client.
The four native Refit methods are handwritten and internal, not generated
from a vendor schema. Refit's ordinary implementation generation is its own
build-time mechanism, not copied connector models.

## Exhaustive current operation status

Use `B = /api/v2/secret-rotations` and `P = one exact profile below`.
The table accounts for all 305 current operations: 2 catalog operations,
10 operations for each of 30 profiles, and 3 special reconcile operations.

| Method/path | Count | Delivered status |
| --- | ---: | --- |
| `GET B?projectId=...` | 1 | `ListAsync`: bounded project-wide metadata projection |
| `GET B/options` | 1 | Not implemented; typed options are Phase 8.2 |
| `GET B/P?projectId=...` | 30 | Not implemented; generic project list is implemented, not these routes |
| `POST B/P` | 30 | Not implemented; connector configuration creation is Phase 8.2 |
| `GET B/P/{rotationId}` | 30 | `GetAsync`: one matched observation, including native progress |
| `GET B/P/rotation-name/{rotationName}` | 30 | Not implemented; no implicit name-to-ID resolution |
| `PATCH B/P/{rotationId}` | 30 | Partial: `SetAutomaticRotationAsync` sends only `isAutoRotationEnabled`; all other fields remain unimplemented |
| `DELETE B/P/{rotationId}` | 30 | Not implemented |
| `POST B/P/{rotationId}/check-credentials` | 30 | Not implemented; inspection never invokes this effect |
| `GET B/P/{rotationId}/generated-credentials` | 30 | Not implemented; no generated credential material is exported |
| `POST B/P/{rotationId}/move` | 30 | Not implemented |
| `POST B/P/{rotationId}/rotate-secrets` | 30 | `RotateSecretsAsync`: explicit bodyless manual trigger with pre-dispatch receipt |
| `POST B/hp-ilo-local-account/{rotationId}/reconcile` | 1 | Not implemented; distinct from restart or receipt reconciliation |
| `POST B/unix-linux-local-account/{rotationId}/reconcile` | 1 | Not implemented |
| `POST B/windows-local-account/{rotationId}/reconcile` | 1 | Not implemented |

There is no established restart endpoint, dedicated progress endpoint,
dedicated enable/disable endpoint, CAS, idempotency key or attributable
operation-status lookup in this snapshot. No callable stub is exposed for them.
Mandatory CAS/idempotency requirements fail as `Unsupported` before token
acquisition. Progress is the published GET/trigger response, not a fabricated
job API. Overall depth is 61 complete observation/trigger routes plus 30 partial
enablement update routes, not 305 implemented contracts.

The native routing profiles are exactly:

| Profile | Profile | Profile |
| --- | --- | --- |
| `auth0-client-secret` | `aws-iam-user-secret` | `azure-client-secret` |
| `cloudflare-api-token` | `cloudflare-r2-access-key` | `convex-access-key` |
| `databricks-service-principal-secret` | `datadog-api-key` | `datadog-application-key-secret` |
| `dbt-service-token` | `fireworks-api-key` | `gcp-service-account-key` |
| `hp-ilo-local-account` | `ldap-password` | `litellm-api-key` |
| `mongodb-credentials` | `mssql-credentials` | `mysql-credentials` |
| `okta-client-secret` | `open-router-api-key` | `openai-service-account` |
| `oracledb-credentials` | `postgres-credentials` | `redis-credentials` |
| `salesforce-oauth-credentials` | `snowflake-user-key-pair` | `stripe-api-key` |
| `supabase-api-key` | `unix-linux-local-account` | `windows-local-account` |

These enum choices constrain routing. They do not implement typed parameters,
secret mappings, connection credentials, rotation schedules, per-profile
overlap models or generated credential schemas. Credentials/configuration in a
response are deliberately discarded, not returned as JSON or objects.

## Authority, ownership and bounds

Hosts explicitly select a trusted HTTPS origin, host-owned `HttpClient`,
`SecretAuthority`, and existing `InfisicalNativeAuthority`. Client construction
does not fetch tokens or state. Each operation checks instance and exact native
project/environment/path selection before tokens; provider permissions remain
the server's responsibility. Project-wide listing requires project-wide local
authority: a folder-scoped authority cannot list the wider project and then
claim that filtering enforced server scope.

The host must disable transport redirects, replay/retry handlers, cookies and
coordinate/material diagnostics. A host-owned `HttpClient` does not expose
handler configuration for the adapter to enforce this retrospectively.
Requests use absolute URIs under the fixed origin; changed final response URI
is rejected if the handler reports it. No endpoint override or arbitrary JSON
request API is exposed.

Refit 16.3.0 is centrally selected by the parent. An operation-local Refit client
receives a request-construction-only HTTP wrapper with the fixed base origin.
Its narrow methods return `Task<HttpRequestMessage>` (documented since Refit
14), have explicit `CancellationToken` parameters, and disable exception
factories retaining provider response bodies. Its handler rejects any attempted
send. The adapter owns the returned request, validates its final origin, marks
the native receipt immediately before the sole host-owned `HttpClient.SendAsync`
call, and requests `ResponseHeadersRead`. There is no ambient operation context,
double send, clone forwarding or response deserialization by Refit.
The temporary builder wrapper and request are disposed; the supplied transport
remains host-owned. Native status/parsing checks and byte budgets therefore
remain fully adapter-controlled. The
[Refit breaking-change documentation](https://github.com/reactiveui/refit/blob/main/docs/breaking-changes.md)
establishes the request-builder behavior; no vendor implementation was copied.

Responses are bounded by both declared length and actual stream bytes
(default 1 MiB; permitted 1 KiB through 16 MiB), with JSON depth 32 and duplicate
property rejection. Lists export at most 1 through 4096 items (default 128);
truncation sets `IsComplete=false`. The published list input is only project ID:
there is no paging/continuation contract. Exactly one request is made; no
follow-up paging, polling, waiting, retries or automatic reconciliation.
Metadata strings and native coordinates are capped at 1024 characters; IDs
must be UUIDs and paths absolute without dot traversal.

Returned project, ID, profile, environment slug and folder path are validated.
Consumed status, date and optional boolean/job fields must have their actual
types. Missing observed booleans stay unknown; schema defaults are not invented
observations. This is validation of a metadata projection, not validation or
implementation of every connector's configuration schema.

Metadata strings are independent managed copies, immutable after document
disposal; they are excluded from default JSON and formatting. Native profile,
project, environment, path, job, timestamps, status and ID are protected.
Provider messages and configuration are not retained. The bounded staging
buffer is cleared; the JSON document and response/stream are disposed.
Managed strings, HTTP bearer header exports and JSON internals do not provide
a universal memory-erasure promise. A token source supplies an independent
token copy, disposed by the operation; the source and transport stay host-owned.

## Evidence and progress semantics

`InfisicalRotationReceipt` is created by the caller before invoking a control.
It binds the exact reference object and selected action. At the final controlled
send boundary it becomes `ResponseUnknown` and cannot be dispatched again,
including concurrent use. Pre-send cancellation leaves `NotDispatched`;
post-send cancellation propagates without provider payload or inner exception,
retaining unknown effect. Transport failures, malformed/mismatched responses,
oversized bodies and lost committed responses remain unknown, never replayed.

Validated trigger responses record `ResponseObserved` and retain their exact
progress projection with `AcceptedPending`. This is conservative acceptance
evidence, not an assertion that a displayed last job belongs to this call.
Published `rotationStatus` is an open string, with no declared enum or complete
transition/attribution contract. Values such as `pending`, `failed`, `success`
and future statuses are preserved under `NativeStatus`, not guessed into a
portable success/failure machine. Fixture strings test preservation, not remote
status vocabulary conformance. Even a success-looking status cannot reconcile a
lost-response receipt. Caller-issued later GET observes current state only.

Enablement responses count as `AutomaticRotationSettingApplied` only when their
matched response observes the requested boolean. This means the setting was
observed, not that a credential rotation or consumer refresh occurred.
Definite HTTP rejection is distinct from uncertain transport/5xx outcomes.
HTTP 202/204 are not accepted as valid 200 observation envelopes.

No read issues leases or invokes credential checks. No control creates or
activates a runtime client/configuration generation. `ConsumerDeliveryVerified`
and `FleetConvergenceVerified` remain false. There is no common lifecycle
promotion into Core.

## Managed verification and remaining gates

`RotationOutcomeTests` drives the real public native client/HTTP seam with an
independently authored managed wire fixture. It retains actual committed
rotation/enablement state, rejects unexpected routes/body fields, and uses
exact commit/release barriers for cancellation/concurrent-dispatch tests.
It covers all 30 route profiles, explicit controls, no replay, open native
statuses, coordinate/type/envelope validation, status codes, list/item/input
bounds, known/unknown content-length body bounds, lost commits, pre/post-send
cancellation, protected serialization, token-copy disposal, immutable
observations and host transport reuse. Offline fixture behavior is not live
provider certification.

Exact check results are recorded after execution below.

Live gates remain: no selected deployed origin/project/environment/path or
credential injection, entitlement, exact permission keys, actual credentials,
native transition vocabulary/attribution guarantee, cloud/self-hosted revision
floor or per-profile behavior has been verified. Older v1 rotation contracts
are not compatibility fallbacks. Unsupported mandatory preconditions are not
emulated. Parent-owned Refit dependency selection remains a verification gate
until its version and restored assets are present. This deliverable performs no live mutations,
commit, worktree creation or publication.
