# Selected-authority bootstrap

Run `dotnet run --project samples/RuntimeConfiguration --configuration Release`
from the SecretKit repository. This offline executable uses generated material;
it does not connect to a database or provider.

The consumer selects one installed reader and its references before preparation.
Every required controlled key must succeed through that authority. Preparation
never uses an administrative identity or local default to repair a denied or
missing required value. Foreign references fail before I/O. An all-or-nothing
candidate owns its reads, and each logical read returns a disposable copy.

Dependent object construction belongs after awaited complete preparation.
`BootstrapScenario.RunCompositionAsync()` demonstrates separate all-required
loaders for required startup and an optional capability. Missing optional material
leaves the required application-owned delegate usable. A fresh check observes and
validates the optional candidate but does not enable it or replace its active
client. Only explicit `EnableAsync` activates or hands over; `DisableAsync` invalidates
older in-flight candidates.

The composition workload is offline and serial: two required keys collected in
two passes (four reads), plus one optional key checked while absent, checked while
available, and explicitly enabled (three reads). The executable reports the seven
selected reads and measured elapsed milliseconds, including local preparation,
application validation, export and handover. These are controlled local costs,
not provider latency, a startup SLA, or a rate-limit qualification. No evidence
justifies adding parallel collection.

Each logical operation pins one snapshot handle or client lease while a fresh
generation is collected and accepted. The old operation retains its own material
or client; new acquisitions see the accepted replacement. A failed or cancelled
required collection cannot publish a partial generation. The sample coordinator
uses an explicit fail-closed or bounded-last-known policy and never extends a
stale generation's original deadline.

The sample's client/coordinator/lease lifetimes are asynchronous. Use
`await using` for coordinators and acquired leases. The lease's `Revision` is
the pinned local accepted revision, not the current coordinator revision or a
provider snapshot. Release does not invalidate an executing operation: it holds
its own reference until completion.

Final retirement invokes and awaits client cleanup outside coordination locks,
exactly once. The coordinator retains completion for outstanding generations
and candidate validation/cleanup. A cancelled shutdown waiter does not cancel
that owned cleanup; do not force disposal under a held request after a timeout.
Rejecting/superseding a candidate also awaits its cleanup. Failure is observed
as a bounded retirement error without the application's exception text.
An operator can bound their wait, but cannot report successful drain until the
underlying disposal completes. These are sample application policies, not a
new shipped SDK activation service.

The composition creates a dedicated `IConfigurationRoot` with only the explicit
`SecretConfigurationExport` mapping. It has no environment/local fallback source,
and case-insensitive destination collisions fail before any reveal. Only complete
export preparation can replace strings or signal reload. `ExportOver` remains an
explicit application merge for callers who want uncontrolled local settings next
to authority-selected values; never use that merged view to repair missing
controlled keys. Exports create ordinary managed strings: do not log them, and
disposal cannot erase escaped strings. Local coherence is not a remote transaction.

The sample owns these policies. It is not Event/Configurator code or a migration,
a hidden SDK worker, a database adapter, or proof of live-provider delivery.
