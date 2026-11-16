# Operational Triage and Response Playbook

> Sub-skill: [`stix-taxii-and-misp-ioc-pipeline-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a feed-incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- Internal or partner traffic breaks immediately after an IOC update.
- A feed's indicators stop matching any telemetry.
- A domain is blocked with no record of why or until when.
- A TAXII source returns fewer objects than expected.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Internal service unreachable after update | Self-harm filter gap | Remove the block, add the range/domain to the exclusion list, add a fixture |
| Indicators stored but never match | Refang/canonicalization defect | Normalize both sides and re-test with a fixture |
| Long-lived blocks with no expiry | Missing validity window or sweeper | Add `valid_until`, run the sweeper, record removals |
| Blocklist growing with no accuracy gain | Static confidence | Apply age decay and re-evaluate the enforcement threshold |
| Partial TAXII result | Paging not used | Switch to `as_pages` and reconcile the object count |

## Containment and Recovery

1. **Preserve before mutating:** record the feed snapshot, the pipeline decision log, and the enforcement-side blocklist state; the decision log is what proves which indicator caused the break.
2. **Check blast radius:** enumerate every enforcement point that received the indicator and every affected service, then remove the block at each point rather than the most visible one.
3. **Eradicate the root cause:** fix the filter or normalization, replay the fixture set, and confirm the pipeline records a reason for every drop before re-enabling enforcement.
