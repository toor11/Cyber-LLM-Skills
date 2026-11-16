# Operational Triage and Response Playbook

> Sub-skill: [`compromised-credentials-and-token-revocation-playbook`](SKILL.md) | Family: **Incident Response**

Structured runbook for `compromised-credentials-and-token-revocation-playbook`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- A credential, session token or refresh token is confirmed exposed through phishing, infostealer output, a public repository or a third-party breach notice.
- A sign-in succeeds from infrastructure the user does not use, with a valid MFA challenge and a token issued afterwards.
- Kerberos anomaly detection reports forged or anomalous tickets, or a service account authenticates from an unexpected host.
- An identity provider raises a token-theft or anomalous-token pattern, or reports a device-code flow completion the user did not initiate.
- A device enrolled in the estate is reported stolen or compromised while holding a primary refresh token.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Refresh token held by the actor, password unchanged, MFA satisfied once | Confirmed token theft | Revoke at the issuer, verify a failed refresh, then reset the password; the reset alone changes nothing |
| Successful interactive sign-in from actor infrastructure after session revocation | Control Gap (surviving path) | Look for a device PRT, a certificate credential, or a token minted by a different issuer; revocation on one surface is not containment |
| `krbtgt` reset performed once, tickets still validating | Incomplete containment | Complete the second reset beyond the maximum ticket lifetime, after confirming replication to every writable controller |
| Mass sign-in failures immediately after a bulk reset | Baseline (policy rotation) | Confirm the rotation schedule and restore service; the failures are the change, not a second compromise |
| Service-account failures clustering right after the reset | Baseline (incomplete dependant map) | Attribute each failing dependant, extend the map, and record the outage as planned rather than accidental |
| Certificate-based app authenticating successfully after a password reset | Baseline (different credential class) | Enumerate certificate credentials in the chain; their success does not indicate a failed reset |

## Containment and Recovery

1. **Freeze the identity record first.** Export sign-in logs, token issuance records and audit entries for the window with hashes. Revocation events become the containment evidence, and pre-revocation sign-ins are what establish the actor's reach.
2. **Sequence by artefact dependency, not by severity.** Tokens and consent grants, then passwords on both authorities, then device trust, then `krbtgt` after the persistence sweep. Each step has a different propagation delay; the sequence exists to prevent a later step from re-issuing what an earlier step invalidated.
3. **Preserve the responder path explicitly.** Enumerate the jump host, the break-glass identity and the out-of-band management route, exempt them, and record the exemption. An unplanned self-lockout during revocation is the most common way this playbook fails.
4. **Reconcile both authorities in a hybrid estate.** Decide and document which authority is source of truth, revoke on both, and confirm the synchronisation direction. A cloud-only or on-premises-only revocation leaves a working credential on the other side.
5. **Attest every artefact individually.** Each revocation needs an issuer event naming the artefact plus a failed re-use after the propagation window. Report per artefact, never in aggregate, because "sessions revoked" covers five different objects with five different lifetimes.
6. **Publish the residual risk with an owner.** A device left trusted, a certificate left valid, a service account left on an old secret — each is named, dated and owned. The incident closes with the residual list, not before it exists.
