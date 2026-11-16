# Detection Signals and Blue-Team Handoff

> Sub-skill: [`arithmetic-and-precision-bugs`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A large number of tiny deposits or withdrawals from one address, characteristic of rounding extraction.
- Positions whose redeemed value exceeds their deposited value with no price movement.
- Transactions involving a token with non-18 decimals against a protocol that behaves as if it were 18.
- Share price decreasing after a deposit, which indicates the rounding direction is inverted.
- Balance differences of a few wei repeated across many accounts.
- Unchecked blocks executed with inputs near the type boundary.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
