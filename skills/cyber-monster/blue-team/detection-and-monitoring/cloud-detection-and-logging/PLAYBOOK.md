# Operational Triage and Response Playbook

> Sub-skill: [`cloud-detection-and-logging`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `cloud-detection-and-logging`. Paired offensive/mechanics reference: [`ssrf`](../../../red-team/web-and-application/ssrf/SKILL.md).

## Triggers

- A cloud detector finding names a principal or resource that nobody on the team recognises.
- A principal performs a credential, policy, or key operation for the first time in the baseline window.
- An object store, secret store, or queue shows anomalous read volume and the data-event selector state is unknown.
- A cross-account role assumption terminates in an action outside the assuming caller's usual address or user agent.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| First-seen privileged action by a known role, corroborated by resulting resource state | Confirmed Malicious / Gap | Freeze the role's permission set, capture the full session chain, then rotate the specific credentials the session used |
| Same action set in the baseline for that role, executed from the pipeline's published role and address range | Benign Baseline | Record the pipeline identity, add the role-plus-commit condition as a narrow exclusion, and leave the rule otherwise intact |
| Data-plane question with no data-event selector covering the resource | Inconclusive (Data-Plane Gap) | Do not answer; open a selector ticket naming the resource class and the retention needed, and state the finding as unverifiable |
| Query run from a member account against an organization-level destination | Inconclusive (Scope Gap) | Re-run from the management or delegated-administrator scope; the empty result carries no information |
| Detector finding with no joinable audit event | Inconclusive (Uncorroborated Finding) | Locate the telemetry the detector consumed; if it is flow or DNS based, pivot there rather than treating the finding as an audit event |
| Trail delivery stopped before the incident window | Inconclusive (Telemetry Gap) | Escalate as a logging outage, not as a clean result; reconstruct from the provider's duplicated stream or resource state if it exists |
| Newly created principal performing sensitive actions minutes after creation | Confirmed Malicious / Gap | Treat as persistence: enumerate everything the principal created, then disable it after capturing state |

## Containment and Recovery

1. **Preserve before mutating:** export the audit events for the principal and resource window to immutable storage with hashes, and record the resource's current policy and key state; a deleted role takes its inline policy history with it.
2. **Contain by credential, not by name:** revoke the specific session or access key, or attach an explicit deny on the sensitive actions, rather than disabling a role that dependent workloads also use.
3. **Check the blast radius across accounts and subscriptions:** enumerate every resource the principal touched, including resources in accounts the alert did not mention, before declaring containment complete.
4. **Repair the audit plane in the same change:** a selector, retention, or delivery fix belongs to the incident record, because the next investigation depends on it and it is the cheapest control to forget.
