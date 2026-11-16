# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jwt-attacks-claim-tampering`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Resource-server logs accepting tokens whose exp is in the past beyond the configured clock-skew policy.
- Tokens accepted with an aud claim naming a different service than the one validating them.
- The same jti or sub honored after a logout or token-revocation event recorded in the session store.
- Auth metrics showing tokens with missing exp, aud, or iss claims passing validation.
- The iss field in accepted tokens not matching the configured trusted-issuer allowlist.
- A long gap between iat and request time exceeding the intended token lifetime.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
