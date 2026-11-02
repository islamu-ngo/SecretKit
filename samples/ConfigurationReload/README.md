# ConfigurationReload

Run `dotnet run --project samples/ConfigurationReload --configuration Release` from
the repository root. This offline sample asserts that old and new client leases
retain separate material across activation, then explicitly replaces an
`IConfiguration` export. No provider, credentials, or database is required.

Client activation and configuration replacement are separate operations. Export
creates ordinary managed strings; disposing the SDK cannot erase copies held by
configuration consumers. The synthetic values are never printed.
