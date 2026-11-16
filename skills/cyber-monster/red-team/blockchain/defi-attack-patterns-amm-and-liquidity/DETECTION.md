# Detection Signals and Blue-Team Handoff

> Sub-skill: [`defi-attack-patterns-amm-and-liquidity`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A swap executed in the same block as a large trade in the opposite direction, the sandwich pattern.
- Reserve changes without a corresponding `Swap` event.
- First liquidity provision followed immediately by a large swap against the new pool.
- `Sync` or `Update` events whose values differ from the token balances at that block.
- Liquidity removed and re-added within a block to shift the share price.
- Swaps with `amountOutMin` set to zero, which forfeits slippage protection.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
