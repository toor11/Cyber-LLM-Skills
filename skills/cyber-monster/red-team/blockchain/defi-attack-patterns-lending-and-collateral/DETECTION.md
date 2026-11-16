# Detection Signals and Blue-Team Handoff

> Sub-skill: [`defi-attack-patterns-lending-and-collateral`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Borrows at exactly the maximum LTV followed by a small price move and a liquidation.
- Liquidation calls against positions whose health factor was above one at the start of the block.
- Bad-debt events without a corresponding collateral seizure.
- Interest index updates that lag the elapsed time by more than one block.
- Self-liquidation, where the borrower and liquidator are related addresses.
- A cluster of liquidations in one block around a single asset, indicating a price shock or an oracle gap.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
