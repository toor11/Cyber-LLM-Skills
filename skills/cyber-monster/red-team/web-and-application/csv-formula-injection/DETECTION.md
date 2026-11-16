# Detection Signals and Blue-Team Handoff

> Sub-skill: [`csv-formula-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Export or report generation logs where a user-controlled field value begins with `=`, `+`, `-`, or `@`.
- Generated CSV or XLSX artifacts in storage whose cells start with a formula trigger, found by a content scan.
- DLP or proxy egress alerts for spreadsheet clients issuing outbound HTTP from WEBSERVICE or HYPERLINK evaluation on a workstation.
- Office telemetry showing DDE or external-data prompts when opening an application-generated export.
- Web requests that set a field later included in an export to a value beginning with a formula operator.
- CSV libraries configured without a quoting or neutralisation option in the exporter code path, found in review.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
