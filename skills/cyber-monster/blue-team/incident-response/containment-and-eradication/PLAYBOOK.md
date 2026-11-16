# Operational Triage and Response Playbook

> Sub-skill: [`containment-and-eradication`](SKILL.md) | Family: **Incident Response**

Structured runbook for `containment-and-eradication`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- A confirmed intrusion requires the affected assets be removed from adversary reach.
- An actor is observed moving laterally, staging data, or preparing destructive action.
- A rebuilt or remediated asset shows the same artefact again, indicating incomplete eradication.
- A credential used on a compromised asset has been reused elsewhere.
- A regulator, insurer or legal hold requires that containment be demonstrable rather than asserted.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Actor conducting destructive or extortion activity | Confirmed, active harm | Contain broadly now and accept service impact; scope afterwards from the preserved evidence |
| Actor present but not yet destructive, scope partially known | Confirmed, bounded | Contain narrowly and reversibly per asset, revoke the credentials used on each, and re-scope continuously |
| Contained host but credential still authenticating from elsewhere | Container Gap (identity) | Revoke the credential immediately; host isolation without revocation is not containment |
| Artefact re-created after eradication with a new creation time | Incomplete eradication | Return to the persistence layer: services, tasks, run keys, GPO, and the account that created them |
| Rebooting, re-joining host during a maintenance window | Baseline (maintenance) | Confirm with the asset owner and the change record before treating re-registration as re-entry |
| No containment state reported and no heartbeat from the asset | Inconclusive (Enforcement Gap) | State that isolation cannot be verified; use a network-layer control and record the dual mechanism |

## Containment and Recovery

1. **Preserve, then contain.** Capture volatile state, the current log set and the agent status with hashes before the state changes. Every later attestation depends on the baseline taken here.
2. **Contain by primitive, per asset.** Endpoint isolation, identity revocation, mail-flow restriction, cloud policy change and network segmentation break different things and are proven differently. Apply the narrowest primitive that removes the actor's reach to that asset.
3. **Treat every credential on a contained asset as compromised.** Host containment without credential revocation is the single most common re-entry path; revocation is part of containment, not part of eradication.
4. **Eradicate the mechanism, not the artefact.** Remove the initial-access vector, the persistence mechanism, and the authorising credential. A deleted binary with a surviving scheduled task is a temporary quiet period.
5. **Prove from the enforcing layer.** Isolation is proven by the agent or the packet filter reporting the contained state plus a failed egress attempt; eradication is proven by a monitored window on the specific vector with the detection version recorded.
6. **Return assets deliberately.** A rebuilt host rejoins under a new identity, with a documented build record and a monitoring window in place before it carries production traffic. Returning it to the old trust is a re-entry performed by the responder.
