# Detection Queries and Telemetry Artifacts

> Sub-skill: [`authentication-and-session-design-review`](SKILL.md) | Family: **Application Security**

Authentication and session checks. Each row is replayable against a staging tenant with two clients.

## Credential and Factor

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Password storage | hash algorithm and cost parameters in the user table | Argon2id, scrypt or bcrypt with current cost; never a bare SHA family |
| MFA enrolment | endpoint that adds a factor | Requires a fresh re-authentication and revokes existing sessions |
| Recovery path | reset token issuance and consumption | Single-use, short TTL, bound to the account and not to a caller-supplied identifier |

## Session Validation

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Cookie attributes | `Set-Cookie` on the session | `HttpOnly`, `Secure`, `SameSite`, `__Host-` prefix, no `Domain` |
| Token verification | JWT verifier configuration | Pinned algorithm and key set, `aud` and `iss` checked, exp enforced |
| Epoch check | session record or claim compared to the user's current epoch | Mismatch rejects the request |

## Transition Effects

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Password change | replay an existing second session | Rejected after the change |
| Role change | replay a session issued before the role changed | Reflects the new role or is rejected; never the old elevated role |
| Logout | replay the captured cookie | Rejected server-side, not only cleared client-side |

## Telemetry Prerequisites

- Two clients (browser profile plus a scripted client) authenticated as the same user.
- Access to session storage or the token verifier configuration, since the validation path is the control.
- The documented session TTL and revocation policy, so acceptance criteria are explicit.

## Deployment Gates

- No authentication change ships without the replay probe recorded for password change, role change, and logout.
- Any new token type is added to the verifier matrix with its algorithm and key source before use.
