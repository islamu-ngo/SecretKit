# Core delivery scope and deferred orchestration

Decision: user scope correction on 2026-10-11. This supersedes the R6 requirement
to finish every admitted connector before delivering the core SDK.

The [public scope guide](../public/scope-and-orchestration.md) preserves the
product rationale, examples and distinction between secret access, optional
Infisical administration and Configurator orchestration.

## Current exit criteria

- Finish the Infisical/Azure Key Vault SDK using the existing typed architecture,
  explicit authority, host-owned transports and caller-held mutation receipts.
- Preserve existing integrated connector code and its measured evidence.
  Stop broad connector expansion; retain unfinished source outside package
  compilation rather than publishing unbound factories.
- Run relevant offline regressions, solution build/format/pack and an isolated
  installed-package consumer. Verify owned Infisical workflows where the local
  fixture and intended authority permit them.
- Azure live testing remains deferred without an account. Infisical licensed
  replication and SQL acquisition/rotation failures and unspecified event/output schemas remain
  explicit gates, not SDK passes or invented contracts.

Fresh core verification on 2026-10-11 passed 15,870 offline solution tests,
locked restore, build, formatting and packaging. A freshly packed, isolated
package-only consumer passed separately. Owned live identity, installed
read/write/configuration/assessment workflows, mutation uncertainty and ordinary
import delivery passed. Native replicated-import verification was rejected
(`Invalid` / `Rejected`) by the owned deployment's license restriction; its
test remains failing and unchanged. Live authentication, token policy and
bootstrap recovery also passed. Across eight native class invocations,
10 cases were attempted: nine passed and one hit the replication entitlement
gate. This is not a whole-green native matrix. Independent scope review found
three documentation consistency issues; current acceptance and historical
resume text were corrected, and local links and archive preservation checked.
The bounded review is not a whole-SDK or native-effect audit.
- Report the core result and remaining gates. No commits or publication.

## Later workflow: a selected Configurator deployment

Coolify is an illustrative destination, not an approved working integration.
Choose one actual application, destination and secret-delivery mechanism before
implementing orchestration. Confirm available native APIs, authority and
destination capabilities from their current contracts; do not infer support
from an app-connection name or a marketing integration claim.

Configurator owns project/environment setup, grants, destination configuration,
deployment sequencing and recovery. SecretKit owns typed provider access and
native administrative request contracts. Destination clients remain separate;
neither deployment logic nor hidden orchestration workers belong in Core.

Each workflow step needs independently selected authority, observable state
and a recovery decision. After a lost mutation response, reconcile actual
state using its caller-held receipt rather than automatically replaying it.
Verify fresh source state, destination delivery and application access. Do not
promise cross-system atomicity or credential effects based on metadata.

## Deferred comprehensive administration

The frozen registry describes 69 connection variants, 49 sync destinations,
30 rotations, 28 dynamic-definition profiles and 13 authentication variants.
These are admitted design scope, not delivered support totals.

At the scope correction, 60 connection increments and 14 sync increments had
offline integration evidence. The latest coherent management-only run passed
15,182 cases on 2026-10-11 at 09:36:24 UTC; it does not prove the entire SDK,
native effects or current installed-package support. Its exact report digest
and bounded audit limits remain in the excluded execution ledger.

Four source-only units were stopped: Fireworks, Spacelift, Daytona and TeamCity
sync. Preserve their authored work for later, explicitly unverified and
unbound. Do not finish them merely to inflate coverage under the new scope.

The latest Hasura/Qovery/LiteLLM/Vault audit found no scoped production-contract
defect but identified two P2 fixture-evidence gaps: Qovery fault tests asserted
dispatch counts without substantive effects; Vault action fixtures lacked
delete/import/remove/sync effect state. Preserve these findings for any future
administration work. Passing counts do not close them. They do not block core
secret access and are not being silently relabeled as verified effects.
