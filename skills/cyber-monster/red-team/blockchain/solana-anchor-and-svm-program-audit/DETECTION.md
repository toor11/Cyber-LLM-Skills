# Detection Signals and Blue-Team Handoff

> Sub-skill: [`solana-anchor-and-svm-program-audit`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Transactions where `remaining_accounts` contain an account owned by a different program.
- CPI calls to a program ID that is not in the protocol's known set.
- Duplicate mutable accounts in one instruction, characteristic of an aliasing attempt.
- Instructions with an account count different from the documented shape.
- PDAs derived with a non-canonical bump, visible as a failed seed check.
- Closing an account to a destination not owned by the authority.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
