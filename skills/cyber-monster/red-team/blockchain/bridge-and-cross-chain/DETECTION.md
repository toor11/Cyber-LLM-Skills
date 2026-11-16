# Detection Signals and Blue-Team Handoff

> Sub-skill: [`bridge-and-cross-chain`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- The same message id released twice on the destination chain.
- Bridge outflows without a corresponding deposit event on the source chain in the same window.
- Validator signature submissions from an address not in the current set.
- Large releases immediately after a validator set change.
- Destination releases with a source chain id that does not match the configured value.
- Wrapped token supply increasing without matching locks on the source chain.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
