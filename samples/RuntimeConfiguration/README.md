# Selected-authority bootstrap

Run `dotnet run --project samples/RuntimeConfiguration --configuration Release`
from the SecretKit repository. This offline executable uses generated material;
it does not connect to a database or provider.

The consumer selects one installed reader and its references before preparation.
Every required controlled key must succeed through that authority. Preparation
never uses an administrative identity or local default to repair a denied or
missing required value. Foreign references fail before I/O. An all-or-nothing
candidate owns its reads, and each logical read returns a disposable copy.

Database-dependent construction belongs after awaited complete preparation.
An optional disabled integration needs no credential and does not block startup.
That application policy is separate from required bootstrap policy.

`ExportOver` is deliberate ordinary-string export: controlled keys replace local
values only after all required reads succeed. Do not log the exported dictionary.
Disposing the candidate cannot erase exported strings. Collection is locally
coherent, not a remote point-in-time transaction.

The sample owns these policies. It is not Event/Configurator code or a migration,
a hidden SDK worker, a database adapter, or proof of live-provider delivery.
