# Operational Triage and Response Playbook

> Sub-skill: [`edr-api-triage-and-containment-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for an endpoint-containment incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A containment action was requested and the host is still communicating.
- A protected or business-critical host was contained.
- A batch triage reports hosts as unknown during a mass alert.
- An isolation appears twice in the vendor audit log.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| 2xx returned, host still online | Async action or wrong target | Re-read `isIsolated`; verify the resolved machine id |
| Protected host contained | Policy gap | Release immediately, add the asset to the refusal list, add a fixture |
| Mass "host not found" | Rate limiting | Back off, retry, and separate unreached from unresolved |
| Duplicate isolation entries | No state check | Read state before acting; reconcile the audit log |
| Token rejected with a correct-looking URL | Audience mismatch | Re-issue the token for the endpoint family in use |

## Containment and Recovery

1. **Preserve before mutating:** keep the audit log, the resolved machine ids, and the vendor-side action records; the mapping between your request id and the vendor's action id is the chain of custody.
2. **Check blast radius:** enumerate every host acted on in the run and every dependency of those hosts (DC, DNS, jump host) before releasing or re-isolating in bulk.
3. **Eradicate the root cause:** fix the identifier resolution, state check, or protected list, re-run dry-run across the same target set, and confirm the plan matches intent before executing.
