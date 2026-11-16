# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cryptocurrency-and-onchain-tracing-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- RPC endpoints receiving `eth_getLogs` over wide block ranges from one client.
- Repeated `eth_getTransactionReceipt` calls for a contiguous transaction set.
- Explorer API usage above the anonymous rate limit for one address.
- Bridge contract event queries immediately followed by destination-chain queries.
- Archive-node access for historical state from an unexpected host.
- Bulk address clustering jobs on a workstation that normally runs only development tooling.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
