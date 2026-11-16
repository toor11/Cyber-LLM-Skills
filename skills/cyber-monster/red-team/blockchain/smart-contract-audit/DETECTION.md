# Detection Signals and Blue-Team Handoff

> Sub-skill: [`smart-contract-audit`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Transaction sequences from a newly funded address interacting with privileged selectors.
- Governance or admin function calls outside the protocol's normal operational window.
- A single address receiving a large share of a contract's balance within one block.
- Proxy admin slot changes, visible as `AdminChanged` events on an upgradeable contract.
- Calls to `initialize` on a deployed proxy, indicating an uninitialised implementation.
- Repeated near-identical transactions from one address, characteristic of a scripted exploit or fuzz replay.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md) | Query authoring, triage, and hardening |
