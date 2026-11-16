# Detection Signals and Blue-Team Handoff

> Sub-skill: [`saml-and-webauthn-passkey-implementation-flaws`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WebAuthn assertion events whose clientDataJSON.origin does not match the relying party's registered origin allowlist.
- Repeated authentications presenting the same clientDataJSON.challenge value, indicating a non-single-use challenge store.
- authenticatorData signCount values that stay flat or decrease across successive logins for the same credentialId.
- Assertion-verification logs where rpIdHash recomputation is absent or the comparison result is never recorded.
- Authentications that succeed with the UV flag clear while policy records userVerification as required.
- FIDO server logs where a non-discoverable credential with an empty userHandle satisfies a resident-key-required ceremony.
- Bursts of assertion POSTs to /webauthn/assertion from a single source replaying captured clientDataJSON blobs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
