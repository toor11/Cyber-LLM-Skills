# Operational Triage and Response Playbook

> Sub-skill: [`post-incident-review-and-lessons`](SKILL.md) | Family: **Incident Response**

Structured runbook for `post-incident-review-and-lessons`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- Recovery is complete and the question of what changes arises.
- An interval was unacceptable — detection, containment or recovery — and the reason is not understood.
- A prior action was marked closed and the same failure recurred.
- A regulator, board or insurer asks what the organisation learned and what it changed.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Confirmed timeline with a measured interval and a demonstrated mechanism | Root Cause Established | Write testable actions against the control, default or authority gap |
| Interval unprovable because retention ended before the window | Inconclusive - Coverage Gap | Make onboarding the action; state the interval as unprovable rather than estimating |
| Same factor as a prior incident with a closed action | Recurrence - Verification Failure | Reopen the prior action and investigate why it did not change the mechanism |
| Apparent cause is one person's decision | Systemic Condition | Ask what tooling, alert or runbook made that decision reasonable, and act on that |
| Contradiction between participant recollection and the log | Evidence Wins | Use the log, mark the recollection as superseded, and note the divergence |
| Only inferred timestamps available | Inconclusive - Timeline Weak | Capture what is certain; do not publish a trend from this case alone |
| Action has an owner and a date but no verification test | Incomplete Action | Rewrite with a test; an action without a test will close without a change |

## Containment and Recovery

1. **Capture urgent lessons during the incident and hold the formal review for stability.** NIST SP 800-61r3 treats improvement as continuous; a fix needed today should not wait for a meeting after recovery, and a review held mid-incident produces unstable findings.
2. **Measure from confirmed timestamps only, and publish the unprovable intervals as gaps.** A review that estimates a dwell time to complete a table has invented the number that drives the largest remediation decision.
3. **Test every contributing factor against a comparable case.** A factor present in both the failed and the better-handled incident is context. Without that comparison the review produces a list of everything that was true at the time, which is not a cause.
4. **Hold the blameless frame actively, not rhetorically.** When a name appears in the account, redirect the question to the system that made the action reasonable. A review that allows one role to be implicitly on trial gets defensive accounts thereafter, and the systemic cause stays hidden.
5. **Close actions only on a passing test run after deployment.** Track them in the normal engineering system with monthly leadership review, because the failure mode is not a bad action, it is an action that is reported complete on schedule and never verified.
