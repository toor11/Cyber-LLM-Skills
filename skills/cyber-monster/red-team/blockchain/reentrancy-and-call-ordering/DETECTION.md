# Detection Signals and Blue-Team Handoff

> Sub-skill: [`reentrancy-and-call-ordering`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A transaction where one contract calls itself recursively within the same call stack, visible in a trace.
- Withdrawal events for the same account twice in one transaction.
- A price or share view read by a third-party contract inside the same transaction as a withdrawal.
- Gas usage far above a comparable single withdrawal, indicating repeated execution.
- Calls from a newly deployed contract to a vault immediately after receiving funds.
- `ReentrancyGuard` revert reasons in failed transactions, indicating an attempted re-entry.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
