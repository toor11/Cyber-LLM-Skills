# Operational Triage and Response Playbook

> Sub-skill: [`sqlite-wal-and-browser-artifact-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a database-evidence incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- Extracted browser activity contradicts other evidence (network logs, EDR telemetry).
- Hash verification fails after a query run.
- Temp cleanup reports `PermissionError [WinError 32]`.
- A report claims a high visit count against very few distinct sites.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Recent visits absent, `-wal` existed at acquisition | Incomplete copy | Re-copy DB plus sidecars, re-run against a fresh snapshot |
| Source hash changed after extraction | Evidence mutation | Stop, quarantine the derived output, and re-acquire from the original media |
| `immutable=1` present in the extractor | Stale-read defect | Replace with copy-then-`mode=ro` and re-run |
| Handle lock on cleanup | Resource leak | Wrap the connection in `contextlib.closing` and assert cleanup in the test |
| Many visits, few URLs | Query-shape defect | Aggregate by URL; do not report navigation count as site count |

## Containment and Recovery

1. **Preserve before mutating:** stop writing derived files into the evidence directory, record the manifest of every sidecar, and keep the original media read-only.
2. **Check blast radius:** determine whether the faulty extractor ran against other acquisitions; a copy-then-open defect silently affects every case processed with it.
3. **Eradicate the root cause:** fix the snapshot or query shape, re-extract from the untouched originals, and attach both manifests to the corrected report.
