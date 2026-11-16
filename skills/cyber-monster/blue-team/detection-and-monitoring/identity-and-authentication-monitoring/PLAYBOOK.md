# Operational Triage and Response Playbook

> Sub-skill: [`identity-and-authentication-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `identity-and-authentication-monitoring`. Paired offensive/mechanics reference: [`oauth-oidc-misconfiguration`](../../../red-team/web-and-application/oauth-oidc-misconfiguration/SKILL.md).

## Triggers

- Repeated MFA challenge failures for one account from an unfamiliar address.
- A successful non-interactive sign-in from an address absent from the account's baseline.
- A new authentication method, credential, or consent grant on an account that did not request one.
- A role assignment or application permission change by an account that has never performed one.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Failure burst then success from the same address, plus a new authentication method registered | Confirmed Malicious (Account Compromise) | Preserve sign-in and audit evidence, revoke sessions, reset credentials, remove the added method, then check mailbox and application activity |
| Non-interactive success from a new address with no preceding interactive event and no persistence artifact | Confirmed Malicious (Token Replay) | Revoke refresh tokens for the account, inspect device registration and token-protection state, and review resource access from the new session |
| Many accounts failing from a few addresses with one code | Confirmed Malicious (Password Spray) | Block the source addresses, confirm no account succeeded, and enable the sign-in risk policy for the affected population |
| Failures with a single code, single app, and single address over days | Benign Baseline (Stale Cached Credential) | Record the client and app, instruct remediation, and exclude that app-and-address pair from the spray rule |
| New MFA method with a matching self-service registration record and helpdesk ticket | Benign Baseline (Device Replacement) | Record the ticket, no containment; keep the rule for registrations without a ticket |
| Role assignment by a newly appointed administrator | Benign Baseline (Legitimate Provisioning) | Record the appointment, add the actor to the known-administrator set, and re-check after the role stabilises |
| Non-interactive stream not collected for the tenant | Inconclusive (Telemetry Gap) | State that token replay cannot be assessed, and open an onboarding action; do not report the account as clean |
| Sign-in data retained for less than the window under investigation | Inconclusive (Retention Gap) | Report the retention boundary and extend the retention before the next review |

## Containment and Recovery

1. **Preserve before mutating:** export the sign-in records, the audit events, and the registered authentication methods before revoking anything; revocation removes the session identifiers that tie activity to the actor.
2. **Revoke then reset, in that order:** revoke refresh tokens and sessions first, then reset the credential, then remove any authentication method the actor added; resetting first leaves the actor's token valid.
3. **Check the blast radius across applications:** an account used for federation may grant access to many downstream applications with their own sessions; enumerate the resources reached from the new session before declaring containment.
4. **Fix the control that should have caught it:** a session that bypassed conditional access is a policy gap, and it becomes a named change with an owner in the same incident record.
