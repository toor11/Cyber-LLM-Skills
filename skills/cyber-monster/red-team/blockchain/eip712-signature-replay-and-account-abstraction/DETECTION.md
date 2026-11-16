# Detection Signals and Blue-Team Handoff

> Sub-skill: [`eip712-signature-replay-and-account-abstraction`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- The same signature hash submitted twice from different relayers.
- A `permit` or `execute` call whose calldata differs from the signed payload in a field the relayer controls.
- Initialisation transactions for a delegated account not sent by the account itself.
- UserOperations whose gas fields are far above the account's historical pattern.
- Signature verification failures clustered from one relayer, characteristic of a replay probe.
- Delegation changes to an address without deployed code.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
