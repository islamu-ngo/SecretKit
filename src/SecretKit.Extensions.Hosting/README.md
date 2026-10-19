# Explicit Infisical authentication maintenance

See [current support](../../docs/public/provider-support.md) for current
offline evidence and the separate native renewal/entitlement limits.

This optional package references Core, the native Infisical provider,
Hosting.Abstractions and HealthChecks.Abstractions. It does not require the
configuration adapter. Merely constructing or registering a session/helper
starts no worker. A host must explicitly call `StartAsync`, or explicitly
register this helper as its hosted service so host startup calls it.

```csharp
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Extensions.Hosting;

// These inputs come from the host's authorized token handoff and verified
// deployment/identity facts, not inferred defaults or a login performed here.
await using var session = new InfisicalPeriodicTokenSession(
    trustedOrigin, hostTokenMaterial, verifiedLifetimeEvidence,
    renewBefore: TimeSpan.FromSeconds(30),
    requestTimeout: TimeSpan.FromSeconds(10));
await using var maintenance = new InfisicalAuthenticationMaintenance(
    session, shutdownTimeout: TimeSpan.FromSeconds(10));

// The host passes session as IInfisicalTokenSource to its native read client.
await maintenance.StartAsync(hostStartupCancellation);
// ... host work; maintenance.CheckHealthAsync exposes material-free health ...
await maintenance.StopAsync(hostShutdownCancellation);
```

`InfisicalTokenLifetimeEvidence` is an explicit host assertion for the selected
token and deployment. Supply original issue time, current expiry, the verified
numeric maximum TTL returned by this deployment and either finite semantics or
an independently verified periodic period. Unknown or inconsistent metadata
returns recovery-required before dispatch. An optional absolute lifetime limit
can restrict a periodic token. Finite lifetime is always bounded by original
issue time plus maximum TTL; renewals never reset that ceiling. Previously
renewed periodic tokens can be supplied with their original issue time and
current expiry. Token-use limits and external revocation are still enforced by
the service; the session does not invent remaining-use counts.

The native session copies the input material. Each `GetTokenAsync` result owns
another independent copy. The caller retains its original material and any
supplied transport. A supplied `SocketsHttpHandler` must already disable
redirects, cookies and activity propagation. The host owns proxy configuration,
trust roots, transport instrumentation and credential access. The built-in
transport uses normal TLS validation; HTTP requires explicit loopback-only
development opt-in. There are no logger callbacks, arbitrary HTTP commands,
automatic credential creation or hidden identity chains.

Renewal sends `POST /api/v1/auth/token/renew` with an `accessToken` JSON body.
It requires `accessToken`, `tokenType: Bearer`, numeric `expiresIn` and numeric
`accessTokenMaxTTL` in the response. Responses have byte/depth budgets; requests
have token/body limits and an injected-time deadline no later than current
expiry. Clearable owned buffers are cleared; HTTP/parsers and explicit exports
can still create managed copies that cannot be erased.

Concurrent demand shares one renewal. Cancelling one waiter does not cancel
that shared operation. `LastRenewal` is established before dispatch and retains
possibly-dispatched evidence after transport loss/cancellation. No safe replay
is admitted by the registry or public docs, so the automatic retry budget is
**zero**, including 429, 5xx and lost responses. Recovery is required instead of
replaying an unknown side effect. This package is not a retry/relogin scheduler.

`StopAsync` ends the helper's session credential generation, cancels/drains its
in-flight renewal within the configured bound and stops scheduling. Share one
helper per session lifecycle. It does not dispose the host's session object,
transport, original token or returned copies. The host disposes its session.
Disposal is idempotent. Expiry, rejected or ambiguous renewal, unknown metadata
and process restart after losing a token require a new explicitly authorized
token/session. A null input token explicitly represents a restart with lost
in-memory material and reports recovery-required without dispatch. A consumed
bootstrap credential cannot be reused by this package;
there is no bootstrap callback, token persistence or automatic recovery.

Focused local verification (from the repository root):

```sh
dotnet run --project tests/SecretKit.Hosting.Tests/SecretKit.Hosting.Tests.csproj \
  --configuration Release -- --minimum-expected-tests 28
dotnet pack src/SecretKit.Extensions.Hosting/SecretKit.Extensions.Hosting.csproj \
  --configuration Release --no-build --output artifacts/packages
```

Sources checked on 2026-10-09:

- [Renewal interface](https://infisical.com/docs/api-reference/endpoints/universal-auth/renew-access-token)
- [Periodic Universal Auth semantics](https://infisical.com/docs/documentation/platform/identities/universal-auth)
- [Creation-bound finite Token Auth maximum TTL](https://infisical.com/docs/documentation/platform/identities/token-auth)
- Independent local registry: `infisical.post.v1.auth.token.renew`,
  profiles `wire-facts-0400` / `wire-facts-0347`.

Local tests do not prove hosted/self-hosted server version, edition, permissions,
provider clock behavior, actual token-use limits or live periodic conformance.
Those remain live gates. Solution graph, central versions and operation-ledger
integration belong to the lead and are not modified by this package.
