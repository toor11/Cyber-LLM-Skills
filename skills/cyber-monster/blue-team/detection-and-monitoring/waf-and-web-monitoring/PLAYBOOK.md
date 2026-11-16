# Operational Triage and Response Playbook

> Sub-skill: [`waf-and-web-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `waf-and-web-monitoring`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `waf monitoring`.
- Alert, hunt outlier, or review request matching `web attack detection`.
- Alert, hunt outlier, or review request matching `waf log analysis`.
- An allowed request with a nonzero anomaly score on a sensitive path.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Allowed request with nonzero score whose origin entry shows the same payload executing, on a path belonging to one application | Confirmed Malicious | Preserve the WAF record and origin entry together, identify the vulnerable parameter, and apply a virtual patch for that path before discussing a threshold change |
| WAF records a block and the origin has no entry for the request | Benign Baseline (control working) | Record the rule IDs that fired; no containment needed, and the block is the evidence |
| WAF records a block but the origin has an entry for the same request | Control Gap | The block is not taking effect; check for a second path to the origin, a cached response, or a layer that does not enforce |
| Rule family is inert because `tx.blocking_paranoia_level` is below the level that activates it | Control Gap (configuration) | Raise the level for that vhost or accept the gap explicitly; do not report the family as coverage |
| Path-borne payload produces no rule hit while the query-borne equivalent does | Control Gap (coverage) | Confirm the engine sits before any path rewrite, then add the path to the family's targets or add a virtual patch |
| Spike in blocked volume with no corresponding change in allowed-with-score | Benign Baseline (scanner) | Attribute to scanning, record the source ranges, and keep the score-side monitoring unchanged |

## Containment and Recovery

1. **Preserve both sides of the verdict:** Capture the WAF audit record for the transaction id and the origin access entry, with the clock offset documented. One without the other cannot show whether the control worked.
2. **Prefer a virtual patch to a global threshold change:** A path-scoped rule stops the specific exploit without raising noise estate-wide. Raising paranoia level is a separate, reviewable configuration decision.
3. **Contain at the layer that failed:** If the block did not take effect, the fix belongs at the layer that let the request through, not at the origin application, unless the application is itself the vulnerable component.
4. **Re-test on staging with the same CRS release:** Confirm the virtual patch or configuration change produces the expected verdict before it reaches production, and record the release tag.
5. **Verify by reconciliation again:** After the change, re-run the WAF-to-origin join and confirm the specific path now shows blocks with no origin entries, rather than confirming that total blocked volume rose.
