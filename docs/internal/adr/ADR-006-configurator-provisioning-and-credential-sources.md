# ADR-006: Configurator provisioning, credential sources and the vendor CLI boundary

Status: Accepted product decision, 2026-11-14. Documentation only: no SDK
source, public API, package, test or dependency changed. Roadmap items below are
proposals with owners and evidence gates, not implemented support. No build,
test, restore or provider call was run for this record.

Human-sign-in guidance corrected 2026-11-15 against official OAuth documentation.
The accepted decision remains dated 2026-11-14. Configurator's separate ADR
has not been edited.

## Context

ISLAMU Configurator plans an operator-confirmed provisioning workflow on its
native Desktop, Terminal and CLI clients. It compares a local, secret-free
snapshot with a new definition and with live provider key names, then applies
only reviewed changes. Its earlier documents named two transports for Infisical
and Azure Key Vault: the official provider CLIs (`infisical`, `az`) or
SecretKit. The question was whether Configurator should use both, or only
SecretKit with missing capabilities added to this roadmap.

SecretKit already describes this consumer shape. The
[architecture](../SDK_ARCHITECTURE.md#consumer-workflows-and-ownership) names a
"Configurator-like workflow" that inspects metadata, reads through the intended
identity, reviews changes and submits typed operations with per-item receipts.
Configurator owns orchestration, review, recovery and destination clients
([scope](../../public/scope-and-orchestration.md#future-configurator-workflow)).

## Decision

1. **Configurator is a named consumer for provisioning work.** SecretKit is
   Configurator's only path for secret-store operations: value-free inventory,
   reads through the intended identity, typed writes and their receipts. This
   satisfies the "named consuming application" part of
   [provider admission](../PROVIDER_ADMISSION.md). It does not admit a provider
   or implement any roadmap item by itself.
2. **SecretKit never launches processes or wraps vendor CLIs.** No package runs
   `infisical`, `az` or another executable, parses CLI output or passes secret
   values, coordinates or mutations through a child process. This extends the
   existing "no arbitrary request execution" boundary in
   [AGENTS.md](../../../AGENTS.md).
3. **A vendor CLI may only be a host-selected credential source.** The host
   decides, outside SecretKit, whether an operator's existing CLI login supplies
   a short-lived access token. For Azure this is Azure.Identity's
   `AzureCliCredential`, passed as the ordinary `TokenCredential`; SecretKit
   cannot tell it apart from any other credential and needs no change. It must be an explicit
   operator choice, never an implicit discovery chain or a fallback principal.
   The reason is enterprise adoption: the Azure CLI is a Microsoft first-party
   application already approved in tenants that block consent to new apps.
4. **Azure operator sign-in uses the operator's own client ID.** An interactive
   host registers its own Entra public-client application and supplies its
   client ID and tenant to Azure.Identity. SecretKit ships no client ID and no
   default. An ISLAMU-published, publisher-verified multi-tenant application is
   a possible future expansion that needs its own decision.
5. **Infisical operator identity starts with Universal Auth.** The implemented
   [Universal Auth exchange](../../public/authentication-and-hosting.md#universal-auth)
   remains the pilot path under an explicitly selected machine identity.
   Machine OIDC Auth is a separate workload exchange: the
   [`InfisicalLoginProof.Oidc`](../../../src/SecretKit.Infisical/Authentication/InfisicalProofAuthentication.cs)
   exchange already exists, and proof acquisition stays host-owned; it does
   not establish human delegation. Infisical documents human-authorized OAuth
   applications. Their implementation is deferred: token exchange is a roadmap
   for organization-owned confidential middleware, while authorization code
   is currently read-only and needs a separate client-secret custody decision.
   Neither permits embedding a confidential client secret in a desktop binary.
   The Infisical CLI's user-session login has no documented
   third-party contract, so no host should borrow it.
6. **Configurator's browser client is not a SecretKit host.** Configurator has
   made a permanent policy that its Blazor WebAssembly client never gains
   secret-store access. SecretKit does not add browser, CORS, trimming or AOT
   work for that client.

## Why a CLI is not a data path

Infisical's own documentation describes its REST API as covering "everything
the CLI and SDKs do". A vendor CLI is an API client plus a login flow, a local
credential store and a terminal interface. Decomposed:

| CLI capability | Library-feasible | Owner after this decision |
| --- | --- | --- |
| Secret read, list, write, delete, versions, folders, imports | Yes; implemented subsets exist | SecretKit provider packages |
| Projects, environments, identities, roles, vault and access administration | Yes; partial subsets exist | SecretKit management packages |
| Azure interactive sign-in, device code, broker, MFA and Conditional Access | Yes, through Microsoft's Azure.Identity/MSAL | Host-selected `TokenCredential` |
| Infisical human sign-in | Documented OAuth authorization code and token exchange; not implemented in SecretKit | Future host integration; confidential middleware owns token-exchange credentials, authorization code needs its own custody decision |
| Infisical machine authentication | Universal Auth and machine OIDC/JWT Auth; implemented exchanges exist | Host selects machine identity and acquires credentials/proofs; no human-delegation claim |
| Session persistence between runs | Yes (Azure.Identity persistent cache, OS keyrings) | Host; SecretKit has no material cache by design |
| Default organization, project, environment and profiles | Yes | Host application state |
| Running a child process with injected secrets, `.env` export | Yes | Host; Configurator already owns artifacts |
| Offline cache of fetched secret values | Possible, intentionally excluded | Nobody |

Routing secret operations through a CLI would lose SecretKit's contracts:

- **Material ownership.** CLI output arrives as ordinary strings, bypassing
  `SecretMaterial` callbacks. Writes need the value in command-line arguments
  (process listings, shell history) or a temporary plaintext file.
- **Outcomes and receipts.** An exit code and localized error text cannot
  distinguish absence, denial and unavailability, or "not dispatched" from
  "possibly dispatched". Killing a process on cancellation leaves the remote
  effect unknown.
- **Provenance and testing.** A CLI found on `PATH` floats outside lockfiles,
  notices and deterministic seam tests, and its text output is not an API contract.

"Official" does not mean "stricter custody" in the observed facts below. The
Azure CLI stores its token cache as plaintext on Linux and macOS, while
Azure.Identity's persistent cache refuses unprotected storage unless the host
opts in. The security that matters for Azure, vendor-maintained sign-in, is
available as a vendor library.

## Consequences and roadmap

The [core scope and roadmap](../CORE_SCOPE_AND_ROADMAP.md#configurator-provisioning-consumer)
owns the proposed items: Windows/macOS qualification for desktop consumers,
multi-folder value-free Infisical inventory, a documented interactive-operator
composition, write-conflict honesty for compare-then-apply, Azure subscription
discovery, deferred delegated OAuth and a possible third-provider proposal.
The [integration follow-ups](../INTEGRATION_QUALITY_FOLLOW_UPS.md) record
Configurator-side adoption as a separately authorized consumer task.

Non-goals remain explicit:

- No CLI wrapper, process launcher or "CLI provider".
- No common Core writer until two or three providers show genuinely shared write
  semantics. Configurator owns its provisioning-sink abstraction meanwhile.
- No restoration of the removed connector/sync catalog.
- No trimming/AOT work driven by this consumer: Configurator's native clients
  publish untrimmed, and its browser client is excluded.

## Alternatives considered

| Alternative | Disposition |
| --- | --- |
| CLI for secret operations, SecretKit only for verification | Rejected: two transports, plaintext custody loss and no receipts |
| SecretKit only, with no CLI credential option | Rejected: enterprise tenants may block consent to a new application |
| SecretKit launching `az` itself | Rejected: Azure.Identity already provides `AzureCliCredential`; process execution violates SDK boundaries |
| ISLAMU multi-tenant Entra application now | Deferred: needs tenant ownership, publisher verification and its own decision |
| Infisical machine OIDC as human sign-in | Not equivalent: machine OIDC authenticates a machine identity, not the delegating user |
| Infisical delegated OAuth now | Deferred: Universal Auth pilot retained; token exchange requires organization-owned confidential middleware and active OIDC SSO with prior user sign-in; authorization code currently offers only `secrets:read` and needs separate client-secret custody |
| Reusing the Infisical CLI's user session | Rejected: no documented third-party contract |

## Revisit triggers

- The documented delegated-sign-in trigger is already met for Infisical:
  OAuth applications provide authorization code and token exchange. This
  correction does not implement either flow. Revisit implementation after
  selecting middleware ownership, client-secret custody, deployment/SSO
  availability and required operation permissions; delegated tokens cannot
  mutate administration.
- A provider Configurator needs offers human sign-in only through its CLI or
  desktop application, with no .NET SDK or public protocol. That needs a new,
  narrowly scoped credential-source decision, never a data path.
- A second consumer needs the same interactive proof acquisition, which would
  justify proposing an optional companion package.

## Functional sources (retrieved 2026-11-14)

These are interface facts for the decision, not SecretKit evidence or live
verification:

OAuth correction sources checked 2026-11-15 (public documentation facts only):

- [OAuth applications](https://infisical.com/docs/documentation/platform/oauth-applications/overview):
  user delegation exists; neither flow permits administration mutations.
- [Authorization code](https://infisical.com/docs/documentation/platform/oauth-applications/authorization-code):
  currently only `secrets:read`; exact registered redirects, optional/required
  S256 PKCE and client credentials at the token endpoint. PKCE does not remove
  the documented client-secret custody question for native clients.
- [Token exchange](https://infisical.com/docs/documentation/platform/oauth-applications/token-exchange):
  confidential middleware uses its client secret and a user token; requires
  active organization OIDC SSO and prior user SSO sign-in. Tokens carry the
  user's effective permissions within delegated-token limits; no refresh token.

- [Infisical llms-full](https://infisical.com/llms-full.txt): REST API described as covering
  "everything the CLI and SDKs do"; SDKs listed include .NET.
- [Infisical CLI vault reference](https://infisical.com/docs/cli/reference/vault): system keyring by
  default; automatic switch to an encrypted `file` vault whose random passphrase
  is kept in the CLI's own configuration file.
- [Infisical CLI FAQ](https://infisical.com/docs/cli/faq): fetched secrets are saved for later
  offline use.
- [Infisical machine identities](https://infisical.com/docs/documentation/platform/identities/machine-identities)
  and [OIDC Auth](https://infisical.com/docs/documentation/platform/identities/oidc-auth/general):
  workloads use machine identities; OIDC Auth validates issuer, subject,
  audience and claims at `/api/v1/auth/oidc-auth/login`.
- [MSAL-based Azure CLI](https://learn.microsoft.com/en-us/cli/azure/msal-based-azure-cli):
  token cache encrypted on Windows, plaintext on Linux and macOS;
  [azure-cli#23495](https://github.com/Azure/azure-cli/issues/23495) requests Linux encryption.
- [What is the Azure CLI](https://learn.microsoft.com/en-us/cli/azure/what-is-azure-cli):
  telemetry is collected by default.
- [Azure.Identity token cache sample](https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/identity/Azure.Identity/samples/TokenCache.md):
  persistence raises `CredentialUnavailableException` without OS data protection
  unless `UnsafeAllowUnencryptedStorage` is set.
- [InteractiveBrowserCredentialOptions](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.interactivebrowsercredentialoptions):
  without `ClientId`, users authenticate to an Azure development application
  "not recommended for production scenarios".
- [azure-cli#23911](https://github.com/Azure/azure-cli/issues/23911): `AzureCliCredential` calls
  `az account get-access-token` in a subprocess.
- [az keyvault secret](https://learn.microsoft.com/en-us/cli/azure/keyvault/secret): `--value` takes
  plain text on the command line; `--file` is the alternative.
