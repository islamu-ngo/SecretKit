# Intended-identity assessment

Run from the SecretKit root:

```sh
dotnet run --project samples/ProviderAssessment/ProviderAssessment.csproj --configuration Release
```

This nonpackable .NET 10 sample is an offline controlled demonstration, not a
provider simulator or live-provider conformance claim. It inspects administrator
metadata, reports an optional integration unavailable, then checks again after
the controlled intended reader changes to return valid material. No credential,
provider write, network request, activation, email or business action is involved.

## Public flow

1. The host creates `AssessmentScenario(adminInventory, intendedReader)` with
   explicitly separate identities. The same client instance is rejected; the
   host remains responsible for selecting distinct credentials behind wrappers.
2. The consumer supplies an admin-native inventory scope and ordered
   `FeatureRequirement` objects. Each has a consumer feature key, required/optional
   policy, and all keys needed to enable it. Each `KeyRequirement` supplies its
   own intended-authority `SecretReference` and `DeliveryKind`.
3. Call `CheckAsync` to collect a complete report. Call it again for Check again
   or refresh: every check inspects and reads afresh through the injected seams.
   There is no cached absence or last-good report. Cancellation propagates and
   no partially built report is returned. Hosts must not inject a caching reader
   if they require freshness; the Core reader contract has no implicit cache.
4. `CanProceed` requires all required features to have every key `Ready`.
   Optional failures disable only that feature (`CanEnable` is false).
   This is sample consumer policy, not SDK activation or application validation.

Keep required startup keys and optional capability keys in separate
`FeatureRequirement` groups. All keys within each group are required for that
group; there is no optional-key relaxation inside a loader. A successful fresh
`CheckAsync` only returns evidence. The application must independently choose
activation and construct/validate its consumer. The RuntimeConfiguration sample
demonstrates that separate activation boundary, authority-only export, and
generation pinning without a network client or database driver.

Pass native addresses without normalization: Azure `AzureSecretAddress` retains
the selected name/version; Infisical `InfisicalSecretAddress` retains explicit
version, `Raw`/`ExpandedReferences`, and `includeImports` choices. Runtime references
are never derived from admin inventory or rebound to its identity.

`Absent`, `Denied`, `Unverified`, `Indirect` and `Unusable` remain distinct.
The original bounded `ReadStatus` and observed validity accompany each key.
`NotChecked` performs no read. Unknown validity and unsuccessful unestablished
operations remain unverified. Successful expanded/imported Infisical reads, or
consumer-declared indirect bindings, remain `Indirect`, not enable-ready: this
workflow cannot certify dependency/source-side resolution. It never parses
plaintext or recursively traverses imports. Direct `Ready` means a valid read
was observed at this seam, not target acceptance, live conformance or rotation
convergence.

Admin inventory status, completeness, count and collection window are separate
from runtime assessment. Failed or incomplete listing neither blocks independent
runtime reads nor establishes absence, permissions or a point-in-time snapshot.
Output uses feature/key input indices for correlation; values, names, references
and versions are not retained in reports. Successful material is always disposed
without export. Keep the original consumer input private.

## Verification and limits

```sh
dotnet build tests/SecretKit.Assessment.Tests/SecretKit.Assessment.Tests.csproj --configuration Release --verbosity quiet
dotnet run --project tests/SecretKit.Assessment.Tests/SecretKit.Assessment.Tests.csproj --configuration Release --no-build -- --minimum-expected-tests 1
```

Controlled reader tests prove local policy, state, cancellation and safe output.
Authorized remote identities, provider editions/import precedence/resolution,
installed-package execution and source-side/target acceptance evidence remain
open. This standalone project does not modify the solution or shared configuration.
