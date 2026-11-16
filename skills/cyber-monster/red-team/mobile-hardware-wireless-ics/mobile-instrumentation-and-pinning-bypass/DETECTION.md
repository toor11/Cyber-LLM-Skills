# Detection Signals and Blue-Team Handoff

> Sub-skill: [`mobile-instrumentation-and-pinning-bypass`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Attestation metric: assertion verification failures per client version, which is the server-side control working.
- Network telemetry: app traffic arriving at a proxy or an unexpected TLS terminator, visible from certificate pinning violation reports if the app reports them.
- Client telemetry: a root or jailbreak signal reported for fraud scoring, with the server action gated independently.
- Build diff: a new `pin-set` or a pin removed, reviewed at release because it changes the interception surface.
- Device event: a debugger or instrumentation framework attached to the app on a managed device.
- Server audit: a request to a sensitive endpoint carrying an assertion that failed verification, which is the attempted bypass.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
