# Security Policy

SecretKit handles provider credentials and secret material inside the consuming process. This unpublished preview has no established stable-release support window or security certification. The [current preview](docs/public/current-preview.md) records implemented slices and verification limits.

## Reporting a vulnerability

Send a private report to [contact@openislamu.org](mailto:contact@openislamu.org). Do not open a public issue or pull request containing an undisclosed vulnerability. Coordinate security fixes from forks through the same channel.

Include:

- Affected SecretKit package and version or commit.
- .NET SDK/runtime, operating system, and provider/API version or edition where relevant.
- A minimal reproduction using synthetic material and sanitized coordinates.
- Expected and observed behavior, impact, and any proposed remediation.
- Whether the evidence comes from a controlled transport or an authorized live provider.

Never send real tokens, credentials, secret values, confidential provider coordinates, or personal data. Maintainers will assess the report and coordinate disclosure and a fix where applicable; no response-time SLA or bounty is promised.

Test only environments you own or have explicit permission to assess. Reporting guidance grants no authority to scan infrastructure, access another tenant, mutate provider state, or test third-party services.

## SDK security boundaries

- **Authority:** Hosts select the client, origin, and credentials explicitly. References bind to that client. Provider policy enforces access; metadata visibility is not value-read permission.
- **Ownership:** Successful reads contain independently owned disposable material. Protected values and coordinates stay out of default formatting, serialization, exceptions, and SDK diagnostics.
- **Plaintext export:** `Reveal` and configuration export deliberately create managed strings. Disposing the original buffer cannot erase exported strings or downstream copies.
- **Networking:** SDK-owned transports apply the documented origin, response-budget, redirect, retry, and diagnostic controls. Injected transports, credentials, proxies, and host instrumentation remain host-owned boundaries.
- **Effects:** Cancellation propagates. Supported mutations retain pre-dispatch receipts; uncertain writes are not silently retried. Approval submission is not evidence of application or downstream delivery.
- **Lifecycle:** Optional hosting starts through explicit host participation. Application activation, readiness, persistence, and replica convergence remain consumer responsibilities.

Exact implemented behavior is described in the [current preview](docs/public/current-preview.md); design invariants are in [runtime contracts](docs/internal/RUNTIME_CONTRACTS.md). Controlled offline tests do not establish live permissions, editions, cloud compatibility, Native AOT, or trimming support. Azure live verification remains deferred.

## Application responsibility

Use least-privilege runtime and administrative identities, protect credential injection, review host diagnostics, and dispose owned material after use. Review configuration debug views, logs, exception sinks, and downstream clients before exporting plaintext. SecretKit is not a vault, process-isolation boundary, or forensic-erasure guarantee.

Report a reproducible failure of the SDK's stated boundaries even when it requires a particular host configuration. Provider service vulnerabilities belong with the provider as well; explain SecretKit's role without assuming a remote service issue is an SDK defect.
