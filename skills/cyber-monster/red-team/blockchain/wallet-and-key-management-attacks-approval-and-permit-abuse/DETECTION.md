# Detection Signals and Blue-Team Handoff

> Sub-skill: [`wallet-and-key-management-attacks-approval-and-permit-abuse`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- `Approval` events with the maximum uint256 value for a newly deployed spender.
- `Permit` followed by `transferFrom` in the same transaction, which is the normal flow; unusual is a permit for the full balance.
- `ApprovalForAll` granted to an operator whose contract was deployed recently.
- Allowance resets to zero followed immediately by a large transfer, indicating a race attempt.
- Signature submissions with a deadline already in the past.
- A spender contract whose implementation changed while approvals were outstanding.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
