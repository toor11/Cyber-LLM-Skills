# Operational Triage and Response Playbook

> Sub-skill: [`denial-of-service-response`](SKILL.md) | Family: **Incident Response**

Structured runbook for `denial-of-service-response`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- Customer-facing error rate, latency or timeout volume rises with normal or falling successful throughput.
- Link utilisation, packet rate or BGP session stability degrades on a prefix serving public services.
- CDN, scrubbing provider or carrier opens a mitigation event or sends an abuse notice for your addresses.
- Origin resource consumption (workers, connections, database pool) saturates without a matching change record.
- A second incident begins within hours of the first, on a different vector.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Bits or packets per second saturate the link, source diversity collapses | Volumetric flood | Engage carrier and provider for on-path scrubbing; record the mitigation event identifier |
| Bandwidth flat, protocol counters spike, bytes per request fall | Protocol-state flood | Limit concurrent streams and control-frame rate; determine reset direction before choosing the control |
| Bandwidth flat, one endpoint's MISS ratio saturates, query-string cardinality explodes | Application-layer cache bypass | Normalise the cache key and enable a challenge class; verify origin ingress in the same minute |
| Origin answers on its public address from outside the edge | Control Gap (shielding) | Treat as primary: rotate the origin, restrict ingress to edge ranges, retest externally |
| Volume up with stable source diversity and healthy cache ratio | Benign Baseline (demand) | Confirm against the campaign calendar and tune the alert to diversity rather than volume |
| Loss and latency up, request rate flat, path shows a mid-hop fault | Not this issue (transit) | Hand to network operations with the path measurement attached |

## Containment and Recovery

1. **Measure before mitigating.** Capture the transit counter, edge analytics and origin ingress for the onset window. Without a before-and-after per action, the team cannot tell which mitigation worked and will stack rules that do nothing.
2. **Fix the path before tuning the filters.** Confirm whether traffic reaches the origin only through a control you own or rent. A shielded origin makes every later action meaningful; an exposed one makes all of them cosmetic.
3. **Apply mitigations in ascending collateral order.** Cache-key normalisation and challenge classes first, then rate classes, then ASN or geography blocks, then prefix-level blackholing. Each step needs its own measured delta and a revert decision if the delta is zero.
4. **Move capacity decisions to the incident commander.** Contracted mitigation capacity, spend commitment and customer-visible degradation are business choices. Present measured inputs — observed peak, headroom, degradation options — rather than making the choice inside the mitigation console.
5. **Confirm recovery from the origin side with mitigation still enabled.** The incident is over when origin metrics are at baseline and the mitigation remains in place, because traffic often resumes on a second vector as soon as the first is filtered.
6. **Record the permanent residue.** Which limits stayed, which endpoints remain uncacheable, what a repeat event would cost, and who owns each hardening item. That list is the deliverable; the graphs are not.
