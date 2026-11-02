# QuickStart

Run `dotnet run --project samples/QuickStart --configuration Release` from the repository root.
The sample is entirely offline: it seeds a nonpackable test reader, reads through an
Infisical scope, and consumes a borrowed span without printing the material.
An executable assertion verifies the callback sees the expected synthetic value.

A real application replaces the fixture with an explicitly authenticated Infisical
runtime client. The fixture is test infrastructure, not a production secret store.
