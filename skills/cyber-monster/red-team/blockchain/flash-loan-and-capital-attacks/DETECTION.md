# Detection Signals and Blue-Team Handoff

> Sub-skill: [`flash-loan-and-capital-attacks`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A single transaction containing a borrow, a protocol action, and a repayment in that order.
- Balance or share reads immediately following a large inbound transfer in the same transaction.
- Voting or reward weight that changes within one transaction and reverts afterwards.
- A newly funded address performing a collateralised borrow with no prior history.
- Flash-loan provider events immediately preceding a governance or lending call.
- Positions opened and closed in the same block by the same address.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
