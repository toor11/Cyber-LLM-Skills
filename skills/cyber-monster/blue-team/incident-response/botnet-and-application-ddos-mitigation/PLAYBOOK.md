# Operational Triage and Response Playbook

> Sub-skill: [`botnet-and-application-ddos-mitigation`](SKILL.md) | Family: **Incident Response**

Structured runbook for `botnet-and-application-ddos-mitigation`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- Link utilisation, packet-per-second rate or BGP session churn crosses the transit threshold on a prefix serving public services.
- Application p99 latency, 5xx rate or worker queue depth climbs while bandwidth graphs stay flat.
- CDN, scrubbing provider or carrier raises a mitigation event or an abuse notice for one of your prefixes.
- Origin access logs show a request-rate pattern with low client diversity, or the origin responds on its address outside the edge.
- Customer-facing error rate rises with normal or falling request volume, indicating back-pressure rather than load.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Bits or packets per second saturate the transit link, ASN cardinality collapses, and edge and origin both rise | Confirmed volumetric flood | Escalate to carrier and provider for on-path scrubbing; enable RTBH for the targeted prefix only after confirming the collateral list |
| Bandwidth flat, one endpoint's MISS ratio near 1.0, query-string cardinality exploding | Confirmed cache-bypass flood | Normalise the cache key, enable a challenging rule class on that endpoint, and verify origin ingress falls in the same minute |
| Bandwidth flat, HTTP/2 resets per connection above fleet p99, bytes per request falling | Confirmed stream-reset flood | Limit concurrent streams and control-frame rate at the edge; identify whether resets are client-sent or server-provoked before choosing the control |
| Origin reachable directly on its public address from an external vantage point | Control Gap (shielding) | Treat as the primary finding: rotate the origin address, restrict ingress to published edge ranges, and re-test from outside |
| Volume spike with high ASN and user-agent cardinality and a stable cache hit ratio | Benign Baseline (demand event) | Confirm against the launch or campaign calendar; do not engage scrubbing, and tune the alert threshold instead |
| Request rate normal, latency and loss elevated, traceroute shows a mid-path fault | Not this issue (transit fault) | Hand to network operations; record the provider status reference and stop DDoS procedure |

## Containment and Recovery

1. **Measure before filtering.** Capture the flow data, edge analytics and origin ingress for the onset window with hashes recorded, so the post-incident review can distinguish what the flood was from what the mitigation claimed.
2. **Close the shielding gap first.** If the origin answers outside the mitigation path, nothing applied upstream matters. Rotate the address, restrict ingress to the edge ranges, then re-test from an external vantage point and record the result.
3. **Apply mitigation in order of collateral cost.** Cache-key normalisation and challenge classes before rate limits; rate limits before ASN or geography blocks; ASN blocks before prefix RTBH. Each step needs its own before-and-after ingress number, because a step that shows no delta should be reverted rather than stacked.
4. **Protect the decision authority.** Scrubbing capacity, spend commitments and any customer-visible degradation are business decisions, not engineering ones; route them to the incident commander with the measured numbers attached.
5. **Confirm recovery from the origin side.** The incident ends when origin request rate, error rate and latency are at the pre-incident baseline with the mitigation still in place — not when the provider event closes, since traffic often resumes on a second vector immediately afterwards.
6. **Record the residual exposure.** Note which endpoints remain uncacheable, which rate limits are now permanent, and what a repeat event would cost; convert each into an owned hardening action with a date.
