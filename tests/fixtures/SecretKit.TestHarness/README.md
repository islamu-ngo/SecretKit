# SecretKit test host harness

This nonpackable library owns candidate selection, isolated consumer launching,
and native observation report validation for repository test hosts. Its dependency
on the release tool is for artifact verification; it is not a shipped SDK package.

The case and run protocol sources remain in `tests/fixtures/`. This harness
compiles them once for source-built test hosts. Installed-package consumers link
those protocol sources directly and must not reference this harness or product
projects. That separation keeps their evidence tied to the selected packages.

Public types here are test-host contracts, not supported SecretKit APIs. Their
behavior is exercised by Release, Package, Demo and conformance tests.
