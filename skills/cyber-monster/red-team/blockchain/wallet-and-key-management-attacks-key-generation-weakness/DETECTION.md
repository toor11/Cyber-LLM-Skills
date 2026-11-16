# Detection Signals and Blue-Team Handoff

> Sub-skill: [`wallet-and-key-management-attacks-key-generation-weakness`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Wallet files created in bulk within the same millisecond, indicating a time-seeded generator.
- Two on-chain signatures from one address sharing an identical `r` value.
- Key material appearing in process arguments, environment variables, or logs.
- Derivation of the same address across wallets that claim separate accounts.
- Seed phrases stored in plaintext files or clipboard history.
- A wallet's first transaction occurring seconds after its key file was created by a script.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
