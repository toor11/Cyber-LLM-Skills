# Detection Signals and Blue-Team Handoff

> Sub-skill: [`c2-infrastructure-and-redirectors`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Proxy logs for a destination whose SNI does not match the certificate subject, a redirector signature.
- DNS logs for high-entropy subdomains or a high query rate to one parent domain.
- NetFlow for regular small transfers to one external address at a fixed interval, the beacon cadence.
- Certificate transparency monitoring for lookalike names registered against the organisation's brands.
- Zeek `ssl` log entries with a self-signed or recently issued certificate for a name in a category the estate uses.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
