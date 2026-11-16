# Detection Signals and Blue-Team Handoff

> Sub-skill: [`governance-and-token-attacks`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A large token acquisition immediately before a proposal snapshot, followed by a withdrawal after voting.
- Deposits in the same block as a reward distribution, especially from addresses with no prior position.
- Proposal creation and voting from the same address within one block.
- Timelock queue and execute calls separated by less than the documented delay.
- Delegation events concentrating weight on a new address shortly before a vote.
- Reward claims by addresses whose deposit age is zero.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
