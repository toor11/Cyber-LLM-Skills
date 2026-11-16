# Detection Signals and Blue-Team Handoff

> Sub-skill: [`wallet-and-key-management-attacks`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- `Approval` events granting an unlimited allowance to a newly deployed spender.
- `Permit` calls followed immediately by a `transferFrom` in the same block.
- A spender contract whose implementation changed after approvals were granted.
- Allowance reads followed by transfers to an address with no prior relationship to the owner.
- Signatures submitted from a different address than the signer, characteristic of a relayer or an attacker.
- Key material appearing in process arguments, environment variables, or logs on a host that also holds funds.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
