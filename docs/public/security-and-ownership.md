# Security and resource ownership

> **Audience:** Application developers, operators, and security reviewers
> **Status:** Implemented library boundaries and consumer responsibilities
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against linked source and runtime contracts
> **Source anchors:** [security policy](../../SECURITY.md), [runtime contracts](../internal/RUNTIME_CONTRACTS.md), [Core](core-api.md)

Use this guide when deciding who owns credentials, material, transport and
application activation. **In development. Not ready for production.** These
mechanisms do not constitute certification or establish a deployment's policy.

## Trust boundaries

```text
Host-selected credential -> selected provider client -> provider response
                                                    -> owned SecretRead
                                                    -> explicit application use
                                                    -> optional plaintext export
```

The host chooses the provider origin, identity, allowed coordinates and
application tenant binding. The provider enforces its remote permissions.
SecretKit checks the selected operation's admitted response and scope; it does
not infer the application's authorization policy.

| Boundary | Library behavior | Host responsibility |
| --- | --- | --- |
| Identity | Uses explicitly supplied credentials/token sources | Inject least-privilege runtime identities; select administration separately |
| Scope | Binds references to client instances and checks returned coordinates | Authorize tenant-to-project/vault/environment/path mappings |
| Networking | Bounds SDK-controlled responses and preserves TLS validation | DNS, proxies, private trust, external instrumentation and deployment reachability |
| Secret lifetime | Owns disposable character buffers and independent read copies | Dispose reads and manage any copies made by consumers |
| Configuration | Explicitly exports strings and publishes local generations | Precedence, debug views, options, reload scheduling and client activation |
| Mutations | Preserves caller-held dispatch evidence without automatic replay | Authorization, durable reconciliation, approvals and cleanup decisions |
| Application health | Exposes bounded operation/maintenance evidence | Readiness, freshness, downstream verification and replica policy |

## Ownership and disposal order

| Object | Owner and disposal |
| --- | --- |
| `SecretRead` / `InfisicalSecretRead` | Caller disposes each successful result; material belongs to the read |
| `SecretMaterial.Copy()` / `InfisicalAccessToken` returned by a source | Recipient owns and disposes the independent copy |
| Default `InfisicalClient` transport | Client owns it; asynchronously dispose the client after accepted work drains |
| Supplied token source / credential / transport | Host owns it; client disposal does not transfer ownership |
| `SecretSnapshotLoader` | Application owns it; dispose after stopping collection/acquisition |
| `SecretSnapshotHandle` | Each logical operation owns its acquired handle |
| Read copied from a snapshot handle | Caller owns it independently of the handle |
| `InfisicalPeriodicTokenSession` | Host owns it, including after maintenance stops |
| `InfisicalAuthenticationMaintenance` | Host owns its explicit start/stop/disposal lifecycle |

Stop accepting new work, cancel/drain owned operations, stop maintenance, then
dispose dependent clients and credential owners. An acquired snapshot handle
keeps old material storage alive across replacement; a consumer-owned client
lease similarly needs explicit retirement. Do not dispose a shared downstream
client while requests still use it.

Use [configuration and runtime](configuration-and-runtime.md) for generation
lifetimes and [authentication and hosting](authentication-and-hosting.md) for
session shutdown. Package-only worker/web examples show application-owned
ordering rather than a library-wide readiness policy.

## Plaintext is an explicit boundary

`SecretMaterial.Reveal()` creates a managed string. `ExportCharacters()` creates
an independent array that the caller must clear. Configuration export, JSON
parsers, HTTP headers, database connection strings and downstream libraries may
also create copies.

SDK disposal clears only storage it owns. It cannot erase pre-existing strings,
exported values, old options, process dumps, debugger captures or host logs.
Default SDK formatting/serialization omits protected material and coordinates;
that protection does not carry over to strings or arbitrary host serializers.

For explicit `IConfiguration` export:

1. Map only the required consumer keys to destination keys.
2. Keep exported roots, options and downstream fields within an owned lifecycle.
3. Use the SDK's redacted debug summary rather than a standard configuration dump.
4. Review logging, exception enrichment, telemetry and crash capture in the host.

Do not return raw provider bodies, token material or secret values from health
checks, error pages or issue reports.

## Transport and cancellation

Use trusted HTTPS origins and normal certificate validation. Infisical accepts
development HTTP only with explicit loopback-only opt-in. A proxy configuration
is not permission to bypass certificates.

Supplied Infisical `SocketsHttpHandler` instances must disable redirects,
cookies and activity propagation and preserve certificate validation.
Keep their configuration stable during use. Host-installed HTTP/credential
instrumentation remains outside SDK-owned diagnostic controls.

The read client has no automatic operation deadline: supply a cancellation token
with your request/shutdown deadline. Construction and DI registration do not
perform credential acquisition or validate live access. See
[operational limits](operations-and-compatibility.md) for exact budgets and
provider-specific controls.

## Separate observation, effect and activation

- Inventory is metadata, not permission to read a value.
- Administrator visibility is not runtime delivery.
- A successful read is not downstream authentication.
- An approval submission is not an applied change.
- An applied mutation is not application client activation.
- A local generation/reload is not a remote transaction or fleet convergence.
- Token metadata supplied by a host is not independently observed principal or
  policy binding.

Preserve those distinctions in readiness checks and operator interfaces.
After an uncertain mutation, use its native reconciliation path under explicit
authority; never substitute an administrator or replay the write silently.

## Deployment evaluation

Before relying on an integration, establish the selected package bytes and
version, provider deployment/API family/edition, intended identities, denied and
cross-scope behavior, operation deadlines, material disposal, redacted
diagnostics, and owned recovery/cleanup. Test the application's own activation,
staleness and downstream behavior separately.

The [support reference](provider-support.md) and [current preview](current-preview.md)
identify existing evidence and open gates. No checklist here upgrades that
evidence to production readiness.

## Report vulnerabilities privately

Follow [SECURITY.md](../../SECURITY.md). Supply a sanitized description and
affected package/version without credentials or material. Ordinary SDK failures
follow [troubleshooting](troubleshooting.md) and the contribution workflow.
