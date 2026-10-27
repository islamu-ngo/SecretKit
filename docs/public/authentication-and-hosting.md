# Authentication and hosting

> **Audience:** .NET application developers, operators and AI coding assistants
> **Status:** Implemented Infisical authentication and optional hosting; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against source and tests; no checks rerun
> **Source anchors:** [Token contract](../../src/SecretKit.Infisical/InfisicalAuthentication.cs), [Universal Auth](../../src/SecretKit.Infisical/InfisicalUniversalAuthentication.cs), [proof exchanges](../../src/SecretKit.Infisical/InfisicalProofAuthentication.cs), [session](../../src/SecretKit.Infisical/InfisicalPeriodicTokenSession.cs), [maintenance](../../src/SecretKit.Extensions.Hosting/InfisicalAuthenticationMaintenance.cs)

Choose one host-authorized identity and supply its token source to the Infisical
client. Login, token handoff, renewal scheduling and recovery are explicit,
separate operations. Constructing a client, session or maintenance helper performs
no implicit login and starts no background worker.

`SecretKit.Extensions.Hosting` is optional and independent of the configuration
adapter. It maintains one selected Infisical token session; it does not rotate
business secrets, activate application clients or implement application readiness.
For Azure credential composition, use the
[Azure provider guide](providers/azure-key-vault.md); administrative identities
remain separate in the [management guide](providers/management.md).

## Supply independently owned token copies

`IInfisicalTokenSource.GetTokenAsync(CancellationToken)` returns
`SecretOutcome<InfisicalAccessToken>`. A successful result owns disposable
`SecretMaterial` and optional `ExpiresAt`. The native client disposes that result
after use; it does not dispose the host's source or its original credentials.

The `InfisicalAccessToken` constructor **takes ownership of the material passed
to it**; it does not make a copy. Never return a wrapper around the source's only
buffer. This minimal source borrows host material and copies it for each request:

```csharp
using SecretKit.Core;
using SecretKit.Infisical;

sealed class SelectedTokenSource(
    SecretMaterial hostMaterial, DateTimeOffset? expiresAt) : IInfisicalTokenSource
{
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
            new InfisicalAccessToken(hostMaterial.Copy(), expiresAt)));
    }
}
```

Keep `hostMaterial` alive until the client's accepted work has drained. This
example adds neither renewal nor persistence. A real source doing asynchronous
credential acquisition must propagate the supplied cancellation through that
work. Give client calls a caller-controlled deadline covering token acquisition,
send and response reads. `InfisicalClient` rejects a supplied expired token;
omitting expiry does not establish that a token remains valid at the service.

Use protected host injection, not credentials in arguments, committed settings
or logs. Explicit `Reveal()` and HTTP/JSON processing can create ordinary managed
strings; disposing protected buffers does not erase all process copies.

## Perform an explicit login exchange

### Universal Auth

Construct `InfisicalUniversalAuthentication` with a trusted origin, call
`CreateReceipt()` before the attempt, then
`LoginAsync(clientId, clientSecret, receipt, organizationSlug, cancellationToken)`.
`organizationSlug` is optional. The protected client secret remains caller-owned;
the disposable successful `InfisicalUniversalLogin` owns the returned token.

This helper is for a deployment whose **finite** token policy the host has
independently verified. It does not discover that policy from the response.
The caller constructs `InfisicalUniversalAuthentication` with its trusted origin,
retains a receipt from that instance's `CreateReceipt()` before calling the
helper, and supplies a bounded cancellation token. The caller owns the
authentication object, receipt and `authorizedBootstrap`; cancellation cannot
hide the receipt inside a failed helper invocation.

```csharp
using SecretKit.Core;
using SecretKit.Infisical;

static async Task<InfisicalPeriodicTokenSession> LoginFiniteSessionAsync(
    InfisicalUniversalAuthentication authentication,
    InfisicalUniversalLoginReceipt receipt,
    string selectedClientId, SecretMaterial authorizedBootstrap,
    CancellationToken cancellationToken)
{
    var result = await authentication.LoginAsync(selectedClientId,
        authorizedBootstrap, receipt, cancellationToken: cancellationToken);
    if (!result.IsSuccess)
        throw new InvalidOperationException(
            $"Login requires a host decision: {result.Status}/{receipt.Evidence}.");

    using InfisicalUniversalLogin login = result.Value;
    var bound = login.BindLifetimeEvidence(new InfisicalTokenLifetimeEvidence
    {
        OriginalIssuedAt = login.RequestStartedAt,
        ExpiresAt = login.Token.ExpiresAt!.Value,
        Lifetime = InfisicalTokenLifetime.Finite,
        ReportedMaximumTtl = TimeSpan.FromSeconds(login.AccessTokenMaxTTL)
    });
    return new InfisicalPeriodicTokenSession(login, bound,
        renewBefore: TimeSpan.FromSeconds(10),
        requestTimeout: TimeSpan.FromSeconds(5));
}
```

The returned session is caller-owned and must be asynchronously disposed.
Check its `State` before admitting work: constructing a session does not prove
that lifetime evidence is usable. Disposing the login does not invalidate the
session's independent token copy. On cancellation or a failed outcome, inspect
the caller-held receipt before deciding recovery. The helper reports failed
outcomes but does not persist a durable receipt journal.

`RequestStartedAt` is the caller-observed request start, a conservative lower
bound for a fresh login, **not server issuance evidence**. Do not replace it with
a later handoff time. `Token.ExpiresAt` is based on reported positive `expiresIn`
from that request start. `AccessTokenMaxTTL` is reported metadata, not proof of
finite or periodic semantics.

### Host-supplied proofs

`InfisicalProofAuthentication` takes a disposable `InfisicalLoginProof` and a new
receipt from its own `CreateReceipt()`. The named factories are `AliCloud`, `Aws`,
`Azure`, `Gcp`, `Jwt`, `Kubernetes`, `Ldap`, `Oci`, `Oidc`, `Spiffe` and
`TlsCertificate`.

- Cloud signing and workload JWT acquisition belong to the host. AWS accepts
  host-signed request body/headers in native base64 representation; AliCloud and
  OCI take completed signed fields.
- `Spiffe` accepts JWT-SVID, not X.509-SVID. `TlsCertificate` selects identity
  only; the host presents the certificate through its controlled transport.
- Factory construction copies the supplied proof into bounded owned storage.
  Dispose the proof and successful `InfisicalProofLogin`; original host material
  stays host-owned.

For example, within an async method with `trustedOrigin`, `selectedIdentityId`,
`hostJwt` and a bounded `cancellationToken` supplied by the host:

```csharp
using var authentication = new InfisicalProofAuthentication(trustedOrigin);
using var proof = InfisicalLoginProof.Jwt(selectedIdentityId, hostJwt);
var receipt = authentication.CreateReceipt();
var result = await authentication.LoginAsync(proof, receipt, cancellationToken);
if (!result.IsSuccess)
    throw new InvalidOperationException(
        $"Proof exchange: {result.Status}/{receipt.Evidence}.");
using InfisicalProofLogin login = result.Value;
using var tokenCopy = new InfisicalAccessToken(
    login.Token.Material.Copy(), login.Token.ExpiresAt);
// Hand a source an independent copy, not login.Token itself.
```

Proof login exposes `Token`, `ExpiresIn` and `AccessTokenMaxTTL`; it has no
`BindLifetimeEvidence` handoff API. To maintain an externally supplied or
proof-derived token, use the origin/material session constructor only with
independently established original timing and lifetime policy. Do not invent
issuance evidence, decode a JWT to infer authority or reuse Universal's
login-bound evidence for a different token.

### Receipts, errors and network boundaries

Login receipts belong to the authentication instance and cannot replay a
dispatched attempt. `Evidence` distinguishes `NotDispatched`,
`PossiblyDispatched`, `Applied` and `Rejected`. Lost responses, malformed success
and post-dispatch cancellation can leave uncertainty even if a token was issued.
Cancellation propagates; retain the receipt rather than treating cancellation
as proof of no effect. No exchange performs automatic retries, fallback login
or principal discovery.

Both login paths accept a strict four-member success object: `accessToken`,
`accessTokenMaxTTL`, `expiresIn` and `tokenType` (`Bearer`). Duplicate/extra
members, invalid fields and over-budget responses do not publish token material.
Provider error prose is not returned. These are the SDK's accepted wire subset,
not a claim of every server response shape.

Authentication/session constructors accept network options, optional
`TimeProvider`, and the shared `network.Transport` selection. SafeDefault uses
normal HTTPS trust, no redirects/cookies/propagation or ambient proxy; HTTP
requires explicit loopback development opt-in. Private issuers use
`SafeWithPrivateTrust(roots)` and retain hostname/chain checks; explicit proxies
use `network.Proxy`. `HostControlled(clientOrHandler)` deliberately accepts
arbitrary host HTTP(S)/TLS/redirect/retry/diagnostic policy without enforcing
network guarantees inside it. Both modes keep a fixed origin without userinfo,
path beyond `/`, query or fragment. Borrowed clients/handlers remain unmodified
and host-owned; the old public injection overloads are removed.

## Establish lifetime before renewal

`InfisicalTokenLifetimeEvidence` is a host assertion for the selected token and
deployment. Supply:

| Field | Required meaning |
| --- | --- |
| `OriginalIssuedAt` | Original timing, or an explicitly conservative lower bound; never a new handoff timestamp. |
| `ExpiresAt` | Current token expiry, including when handing off a previously renewed token. |
| `ReportedMaximumTtl` | The verified numeric maximum TTL reported by this deployment. Zero alone proves no periodic policy. |
| `Lifetime` | Explicit `Finite` or independently verified `Periodic`; `Unknown` cannot authorize renewal. |
| `Period` | Required for periodic semantics and greater than `renewBefore`; absent for finite semantics. |
| `AbsoluteLifetimeLimit` | Optional additional periodic ceiling; not accepted for finite semantics. |

Finite lifetime ends no later than `OriginalIssuedAt + ReportedMaximumTtl`.
Renewal and handoff never reset that ceiling. Periodic evidence must independently
establish the period; initial remaining lifetime cannot exceed it. Service-side
revocation and use limits remain authoritative; the session does not invent
remaining-use counts.

`login.BindLifetimeEvidence(evidence)` binds host policy to that exact Universal
login and checks matching expiry, maximum TTL and original timing no later than
`RequestStartedAt`. It does not verify the policy itself. The login-based session
constructor requires the bound result and rejects cross-wired login/token/origin
evidence.

The session has two public constructor families, both using network options:

```csharp
// Token and lifetime facts come from an authorized host handoff.
await using var session = new InfisicalPeriodicTokenSession(
    trustedOrigin, hostTokenMaterial, verifiedLifetimeEvidence,
    renewBefore: TimeSpan.FromSeconds(30),
    requestTimeout: TimeSpan.FromSeconds(10));
// Or: new InfisicalPeriodicTokenSession(login, boundEvidence, renewBefore,
//                                      requestTimeout);
```

`renewBefore` must be positive and at most one day; `requestTimeout` must be
positive and at most one minute. `InfisicalNetworkOptions.ShutdownTimeout`
separately bounds native session drain and must be positive and at most one
minute. Invalid construction budgets throw; unknown/inconsistent lifetime,
expired input or a null input token starts `RecoveryRequired` without dispatch.
Null explicitly represents lost in-memory credentials, not a request to log in.

## Separate token reads, renewal and scheduling

`GetTokenAsync` checks cancellation and local deadlines and returns an independent
copy; it does not renew. A valid token inside its renewal window remains usable
in `RenewalDue`. Expiry or recovery-required returns `SecretStatus.RecoveryRequired`;
a stopped session rejects further use.

`RenewAsync(CancellationToken)` explicitly starts or joins one shared renewal.
Cancelling one waiter does not cancel that operation or other waiters. The actual
request deadline is bounded by `requestTimeout` and remaining token lifetime;
session stop cancels the shared operation. Successful renewal publishes a new
owned token, leaving previously returned copies independently owned.

`LastRenewal` exists before dispatch and can be retained as material-free evidence.
Its `Evidence` is `NotDispatched`, `PossiblyDispatched`, `Applied` or `Rejected`.
The native request posts an `accessToken` body to `/api/v1/auth/token/renew`.
Response metadata must match the established lifetime policy. Rejection,
malformed/ambiguous success, transport loss or deadline exhaustion requires
recovery, not replay. The automatic retry budget is **zero**, including 429 and
5xx responses.

## Start, observe health, stop and drain

For end-to-end verification from original packages, use the separate
[runtime-hardening profile](../internal/compatibility/runtime-hardening-profile.md).
It exercises complete generation publication, pinned old handles, renewal,
explicit recovery and bounded stop. Controlled installed records and explicitly
authorized native observations remain separate. A matching token shape,
declaration or prior report is not fresh login/policy proof.

Native client/session and helper shutdown publish one shared attempt before
running callbacks outside state locks. Notification, drain and cleanup share
one original injected-time budget. Reentrant or repeated stop/disposal does not
start another attempt or reset that budget. Caller cancellation only ends that
caller's wait. If host callbacks or transport work do not cooperate, timeout
does not mean successful drain: eventual cleanup remains retained and observed,
and late tokens cannot publish. Later cleanup cannot change the original timeout
to success. Callback fault messages and inner exceptions are not exposed.

`InfisicalAuthenticationMaintenance(session, shutdownTimeout)` implements
`IHostedService`, `IHealthCheck` and `IAsyncDisposable`. Its shutdown bound is
positive and at most one minute, separate from the session's native drain budget.
Use one helper per session lifecycle.

```csharp
using SecretKit.Extensions.Hosting;
using Microsoft.Extensions.Diagnostics.HealthChecks;

await using var maintenance = new InfisicalAuthenticationMaintenance(
    session, shutdownTimeout: TimeSpan.FromSeconds(10));
await maintenance.StartAsync(startupCancellation);
HealthCheckResult health = await maintenance.CheckHealthAsync(
    new HealthCheckContext(), operationCancellation);
// The host admits, runs and drains application work separately.
await maintenance.StopAsync(shutdownCancellation);
```

Construction or ordinary DI registration starts nothing. Explicit `StartAsync`
starts scheduling at `session.RenewalDueAt`; it does not await application
admission or prove a remote read succeeds. Its token cancels startup admission to
the helper, not its entire running lifetime. Scheduling ends after a failed
renewal or terminal session state.

`CheckHealthAsync` performs no provider probe:

| Maintenance state | Health |
| --- | --- |
| `Ready` | Healthy |
| `RenewalDue`, `Renewing` | Degraded |
| `NotStarted`, `Expired`, `RecoveryRequired`, `Stopped` | Unhealthy |

This is authentication maintenance health, not database connectivity,
required-secret delivery or application readiness. A stopped helper cannot be
restarted.

Stop application intake and drain/cancel its work before ending its credential
generation. `StopAsync` stops scheduling, calls the session's `StopAsync`, and
cancels/drains in-flight renewal within the helper's timeout and caller
cancellation. A timeout/cancellation is observable, not a successful drain.
The helper does not dispose the host's session object, transport, original token
or returned copies. The host still disposes its session and clients after drain.
`DisposeAsync` invokes stop; the underlying session's stop/disposal is idempotent.

### DI ownership traps

For Generic Host integration, explicitly register the helper as `IHostedService`
so host startup invokes it. Registering only its concrete type does not schedule
maintenance. For an application-owned pre-created instance:

```csharp
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

services.AddSingleton<IHostedService>(maintenance);
// Build/start/stop the host explicitly; dispose maintenance/session in their
// enclosing application-owned scopes after host work drains.
```

The [worker's actual host composition](../../samples/Infisical.WorkerDemo/WorkerDemoApplication.cs)
uses this instance-registration pattern. Supplied instances remain
application-owned. DI-created disposable services instead need container-managed
lifetimes; do not mix ownership models, create a second helper for the same
session, or let disposal order stop credentials before accepted work finishes.
Register the same helper with the application's health-check system if desired;
hosted-service registration alone does not expose a health endpoint. Await
required material before constructing/starting dependent services, as shown in
[configuration and runtime](configuration-and-runtime.md).

## Recovery is a new authorized handoff

Expiry, lost in-memory tokens, unknown lifetime evidence, rejected renewal and
uncertain effects require an explicit host decision. Retain safe dispatch/status
evidence, stop/drain the old lifecycle, obtain newly authorized material for the
selected principal, construct a new session and rebuild its consumers.
A consumed bootstrap credential is not a recovery mechanism. There is no
bootstrap callback, implicit login, fallback identity, token persistence or
restart recovery in these packages.

The [offline authentication scenario](../../samples/RuntimeConfiguration/AuthenticationScenario.cs)
demonstrates explicit Universal login, lifetime binding, renewal, response-loss
recovery and separately authorized replacement under the same selected principal.
The installed [WorkerDemo](../../samples/Infisical.WorkerDemo/README.md) awaits a
required read before building its host, opts into scheduled maintenance only with
`run --maintain`, and provides bounded work/renew/stop controls.
[WebDemo](../../samples/Infisical.WebDemo/README.md) demonstrates separate
liveness/readiness and request-pinned application clients.

## Evidence and remaining qualification

The source anchors above and these tests define inspectable implementation
contracts; they are not new test-run results:

- [UniversalAuthenticationTests](../../tests/SecretKit.Infisical.Tests/UniversalAuthenticationTests.cs):
  handoff retains timing/expiry after login disposal, rejects cross-wired
  evidence and cannot infer periodic policy from maximum TTL.
- [ProofAuthenticationTests](../../tests/SecretKit.Infisical.Tests/ProofAuthenticationTests.cs):
  named routes/fields, reported expiry, bounded errors, uncertain malformed
  success, cancellation and no replay.
- [TokenMaintenanceTests](../../tests/SecretKit.Hosting.Tests/TokenMaintenanceTests.cs):
  independent waiter cancellation, finite ceilings, explicit idle scheduling,
  response-loss recovery, stop cancellation, caller-copy/transport ownership
  and restart without a token.
- [WorkerDemoTests](../../tests/SecretKit.Demo.Tests/WorkerDemoTests.cs):
  admission before hosted work, explicit scheduling opt-in, unknown-outcome
  non-replay and bounded stop/drain through the actual process surface.

Controlled wire/process tests and injected time do not establish issuer/signature
acceptance, mTLS/proxy behavior, deployment identity/policy binding, native
wall-clock longevity, platform/AOT support or production readiness. Host-asserted
lifetime evidence remains an assertion, not independent server proof.
See [current preview](current-preview.md) for dated native observations and open
gates, and [demos and recovery](demos-and-recovery.md) for operator workflows.
