# Detection Signals and Blue-Team Handoff

> Sub-skill: [`matter-protocol-commissioning-and-fabric-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Commissioner log: an attestation verification failure, which is the DCL check firing.
- Fabric audit: an ACL write from a group-authenticated session, which is the escalation attempt.
- Commissioning metric: PASE sessions opened outside a window, or more than one per device.
- Device event: a certificate revocation list update applied to a fabric, which Matter 1.4.2 enables.
- Network capture: a CASE session establishment with a NOC issued by an unexpected fabric.
- Build audit: a shipping commissioner built with the test attestation verifier.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
