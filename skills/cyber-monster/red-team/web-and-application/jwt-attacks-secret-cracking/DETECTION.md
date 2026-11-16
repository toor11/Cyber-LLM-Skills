# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jwt-attacks-secret-cracking`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Source-control or container-image scans finding a hardcoded HS256 secret in config or environment defaults.
- Auth config showing HMAC secrets shorter than 32 bytes or equal to dictionary words.
- Many tokens from different users sharing a forged signature pattern after a suspected secret compromise.
- Absence of key-rotation events in the secret-manager audit log over long periods.
- The verifier accepting a token signed with a secret found in a common wordlist, from red-team validation.
- Metrics showing HS256 in use for externally reachable, high-value audiences.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
