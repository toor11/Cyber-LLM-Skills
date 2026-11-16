# Operational Triage and Response Playbook

> Sub-skill: [`velociraptor-vql-artifact-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a hunt-artifact incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- Endpoint CPU or disk I/O spikes during a fleet hunt.
- A hunt completes far faster than expected with uniformly empty results.
- Row counts sit exactly at `max_rows`.
- `artifacts verify` fails after an artifact edit.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| CPU spike across endpoints in one hunt | Unbounded artifact | Cancel the hunt, add `resources` limits, narrow the glob, relaunch |
| Uniformly empty results across a mixed fleet | Plugin or path defect | Check plugin availability per client version and whether `expand()` was used |
| Row count equals `max_rows` | Truncated collection | Label partial, narrow the filter, then re-run |
| Verify failure on a new artifact | Syntax/structure defect | Fix before any deployment; never bypass the gate |
| Single host fails while others succeed | Client version skew | Pin versions for the hunt and report per-host errors |

## Containment and Recovery

1. **Preserve before mutating:** keep the artifact revision, the resource settings, and the per-host result counts; "everyone is clean" is not a finding without the truncation flags.
2. **Check blast radius:** identify how many endpoints received the hunt and whether any are business-critical servers before adjusting and re-running.
3. **Eradicate the root cause:** add resource bounds or fix the path/plugin assumption, verify, then re-run on one representative host per class before the full fleet.
