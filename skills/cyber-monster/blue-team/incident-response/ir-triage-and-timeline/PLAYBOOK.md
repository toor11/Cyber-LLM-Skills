# Operational Triage and Response Playbook

> Sub-skill: [`ir-triage-and-timeline`](SKILL.md) | Family: **Incident Response**

Structured runbook for `ir-triage-and-timeline`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- A detection names a host, principal or destination and someone asks "how far did this get".
- An external party reports activity — a customer, a partner, an insurer, a law-enforcement notification — before internal telemetry shows it.
- Available evidence must be preserved before an owner reboots, rebuilds or cleans a machine.
- A regulatory or contractual clock may attach, and the clock start has to be established from records rather than recollection.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Two independent planes agree on one host and principal inside one UTC minute | Confirmed Malicious | Freeze the slice, preserve volatile state, hand the scope to containment |
| New object on one host with no baseline and no second plane yet | Inconclusive - single source | Widen to identity and network planes before stating scope |
| Decisive channel disabled, cleared or rotated inside the window | Inconclusive - Telemetry Gap | Do not close; open a log-onboarding action and state the unprovable interval |
| Clock offset on the anchor host exceeds slice resolution | Inconclusive - Order Unknown | Normalise or re-anchor on a host with a trustworthy clock |
| Activity matches a scanning window, patch cycle or imaging workflow | Benign Baseline | Record the change identifier and narrow the exclusion, not the whole rule |
| Named host is clean but a principal shows new post-access actions | Confirmed Malicious - identity led | Pivot identity-first; the host is a decoy, the session is the intrusion |

## Containment and Recovery

1. **Preserve before mutating:** capture volatile state — running processes, network connections, loaded modules, active sessions — and hash every artifact before any isolation, reboot or credential reset. The order is the point; a reset before capture destroys the token evidence that proves the session existed.
2. **Decide the containment order from the anchor, not from the org chart:** identity actions (session revocation, token invalidation) usually precede host isolation when the principal is confirmed, because an isolated host with a live refresh token still gives the actor access.
3. **Check the blast-radius allowlist before acting:** domain controllers, DNS, identity providers and the jump path responders use cannot be isolated without an alternate access route already validated.
4. **Hand off with the timeline, not a summary:** the receiving skill needs the anchor, the confirmed-versus-inferred marking, the coverage gaps and the unproven intervals, or it will re-derive them and lose time.
5. **Convert every gap into an owned action:** a channel that was off, a clock that drifted, a collector that lagged — each becomes a dated item, because the next incident inherits the same blind spot.
