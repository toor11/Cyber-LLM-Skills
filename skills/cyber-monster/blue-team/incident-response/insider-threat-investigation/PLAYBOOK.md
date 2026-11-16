# Operational Triage and Response Playbook

> Sub-skill: [`insider-threat-investigation`](SKILL.md) | Family: **Incident Response**

Structured runbook for `insider-threat-investigation`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- A DLP, proxy or file-audit signal shows one user's access or egress deviating sharply from their own history.
- A line manager, HR or a colleague reports a concern about data handling or conduct.
- A departing or transferring employee's activity during notice period draws attention.
- An investigation into an external incident finds activity that an authorised account could explain.
- A legal hold or regulatory request requires preservation of a named custodian's data.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Signal crossed the documented threshold, legal review obtained, breadth deviation with destination novelty | Confirmed exfiltration pattern | Preserve under hold, continue covert collection of existing telemetry, prepare facts-only report for HR |
| High volume with destination and timing matching the subject's own history | Baseline (role change or migration) | Record the assignment, close with the explanation, and tune the threshold to breadth rather than volume |
| Concern raised but attribution impossible on a shared account | Inconclusive (Attribution Gap) | State that no individual can be identified; recommend per-user credential separation before reopening |
| Hold issued to people rather than to systems, retention jobs still running | Control Gap (hold not applied) | Suspend deletion in the retention configuration for the named categories and record the time |
| Evidence requested for a period before telemetry existed | Inconclusive (Coverage Gap) | Report the coverage start date and scope every finding to the observable window |
| Subject's activity explained by an automation client using their credentials | Baseline (automation) | Attribute by user-agent and cadence, record the client owner, and exclude it from scoring |

## Containment and Recovery

1. **Record the threshold crossing before collecting.** The signal that moved the case from monitoring to investigation, who decided, and when. Collection without that record makes the findings challengeable and the process unmanageable.
2. **Preserve before examining.** Issue the hold to the system owners, verify deletion is suspended for the named categories, and acquire only with authorisation and a recorded standard. An examination that runs before preservation is a race with the retention job, and the retention job wins quietly.
3. **Collect covertly where lawful, and only from existing telemetry.** New agents, new permissions or visible access changes on a subject's device are observable and frequently trigger destruction. Prefer the logs that already exist and record what they cannot see.
4. **Measure against the subject's own baseline.** Breadth, volume, hours, devices and destinations over their own prior period. State the observation count and the coverage exclusions with every deviation.
5. **Report facts and inferences in separate sections.** Each observed item names principal, resource, time, source and coverage. Each inference names its basis and what would disprove it. HR acts on the first section; the second is context.
6. **Close with the employment decision owned elsewhere.** Security reports evidence and limits; HR and legal decide the action. A security function that recommends termination has moved into a decision it is not constituted to make, and the case record will show it.
