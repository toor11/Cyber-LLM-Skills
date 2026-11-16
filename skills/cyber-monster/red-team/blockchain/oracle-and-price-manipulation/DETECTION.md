# Detection Signals and Blue-Team Handoff

> Sub-skill: [`oracle-and-price-manipulation`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Protocol decisions executed immediately after a large swap in the same or the preceding block.
- Borrow or liquidation events at prices far from the aggregator's answer.
- Feed update transactions with a large deviation from the previous answer.
- Repeated reads of a feed's `latestRoundData` from an unverified contract, characteristic of a probe.
- Liquidation calls clustered in one block, indicating a price movement exploited for liquidation.
- Answer values outside the asset's plausible range, which suggests a decimals or negative-answer bug.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
