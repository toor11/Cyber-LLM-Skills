# Detection Signals and Blue-Team Handoff

> Sub-skill: [`defi-attack-patterns`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A single transaction containing a large borrow, a swap, and a protocol call in that order.
- Pool reserve changes within one block followed immediately by a protocol action that reads them.
- Direct ERC-20 transfers to a vault contract with no corresponding deposit event.
- A newly created address performing a multi-step sequence with no prior history.
- Large `FlashLoan` or `flashLoan` events immediately preceding a protocol interaction.
- Share price movement with no deposit or withdrawal in the same block.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
