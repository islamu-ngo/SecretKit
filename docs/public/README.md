# SecretKit developer documentation

> **Audience:** .NET application developers, operators, and AI coding agents
> **Status:** Guides to implemented development-preview APIs, with explicit evidence limits
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against repository source; provider qualification is separate
> **Source anchors:** [package map](../../PROJECTS.md), [current preview](current-preview.md), [Core](../../src/SecretKit.Core/)

SecretKit is an in-process .NET 10 library family for explicitly selected
Infisical and Azure Key Vault access. Start with one provider, add configuration
or hosting only when needed, and keep application policy in your application.

**In development. Not ready for production. APIs may change without backward
compatibility.** Packages are evaluated locally; these guides do not describe an
available public NuGet release or certify a provider deployment.

## Start here

1. [Get started](getting-started.md): run an offline example, understand its
   output, and move to a selected provider.
2. [Choose packages and check support](provider-support.md): distinguish runtime,
   optional composition, administration, and qualification.
3. [Read the Core API contract](core-api.md): outcomes, references, material
   ownership, inventory, and mutation receipts.
4. Follow the [Infisical](providers/infisical.md) or
   [Azure Key Vault](providers/azure-key-vault.md) guide.

## Complete a task

| Your task | Guide |
| --- | --- |
| Install exact local package archives in another application | [Local packages](local-packages.md) |
| Read a secret or inspect metadata | [Provider guides](providers/README.md) |
| Collect required settings and export configuration deliberately | [Configuration and runtime](configuration-and-runtime.md) |
| Supply credentials, maintain a token, or recover after token loss | [Authentication and hosting](authentication-and-hosting.md) |
| Use selected provider-native lifecycle or administration APIs | [Provider guides](providers/README.md), [management](providers/management.md) |
| Run a console, worker, or loopback web consumer | [Demos and recovery](demos-and-recovery.md) |
| Handle a failed read, uncertain write, or startup failure | [Troubleshooting](troubleshooting.md) |
| Review plaintext boundaries and resource ownership | [Security and ownership](security-and-ownership.md) |

## Look up a contract

| Reference | Contents |
| --- | --- |
| [Core API](core-api.md) | Every public Core type, status meanings, disposal and cancellation |
| [Current preview](current-preview.md) | Current implemented boundary and unresolved verification |
| [Provider support](provider-support.md) | Packages, operation families and evidence owners |
| [Operations and compatibility](operations-and-compatibility.md) | Transport controls, budgets and compatibility limits |
| [Database credentials](database-credentials.md) | Provider API support without shipped database clients |
| [Package source](../../src/) | Exact declarations and package-specific operation inventories |

The public reference explains contracts and points to exact declarations. It is
not a generated per-member API browser. Use the linked source for complete
overload signatures and provider model fields.

## Understand the design

- [Adoption and value](adoption-and-value.md): when the library helps and what it
  leaves to a consumer.
- [Scope and orchestration](scope-and-orchestration.md): application access,
  optional administration and future deployment tooling.
- [Connector scope decision](connector-scope-decision.md): why broad third-party
  app-connection/sync administration is outside current scope.
- [Architecture and runtime specifications](../internal/README.md): engineering
  contracts, decisions and retained research.

## Working with an AI agent

Use the same task guides as a human developer. The
[agent reading map](ai-agents.md) identifies the smallest source and test slice
for each task, the terms that must not be conflated, and the evidence needed for
a support claim. Repository changes follow [AGENTS.md](../../AGENTS.md);
application integration is not permission to access a provider.

## Support and evidence

Read [current preview](current-preview.md) before relying on an operation.
Implemented code, offline protocol tests, installed-package execution, live
provider conformance, and application acceptance establish different things.
Historical results retain their original dates and scope.

Report ordinary problems through the [contribution workflow](../../CONTRIBUTING.md).
Send vulnerabilities through [private security disclosure](../../SECURITY.md),
without credentials, secret values, or confidential coordinates.
