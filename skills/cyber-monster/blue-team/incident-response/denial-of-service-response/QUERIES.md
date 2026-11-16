# Evidence and Attestation Queries

> Sub-skill: [`denial-of-service-response`](SKILL.md) | Family: **Incident Response**

Queries owned by `denial-of-service-response`, grouped by the availability question they answer. Each class either classifies the exhausted resource, proves the traffic traverses a control you own, or proves mitigation acted rather than the attack ending. Field names follow common CDN, flow and load-balancer schemas; confirm against your own before deployment.

## Class 1 — Resource classification

Expected hit: the family whose counter moves decisively while the others stay flat. Bandwidth and packet rate rising with link utilisation means volumetric; request rate rising with worker depth means application-layer; connection and frame counters rising with flat bytes means protocol-state.

```kusto
union
  (NetworkFlow
   | where TimeGenerated > ago(2h)
   | summarize bytes = sum(Bytes), pkts = sum(Packets) by bin(TimeGenerated, 1m)
   | extend family = "volumetric"),
  (LoadBalancerAccessLog
   | where TimeGenerated > ago(2h)
   | summarize bytes = 0.0, pkts = todouble(count()) by bin(TimeGenerated, 1m)
   | extend family = "application_or_protocol")
| sort by TimeGenerated asc, family asc
```

False-positive note: flow sampling means packet counts are estimates, not measurements; a packet-per-second figure derived from sampled flow cannot be compared with a provider's reported rate.

## Class 2 — Source diversity differential

Expected hit: volume up with source ASN and user-agent cardinality falling relative to volume. Stated as a ratio, this separates a botnet surge from a demand surge without a volume threshold.

```kusto
CloudflareAccessLog
| where TimeGenerated between (ago(7d) .. now())
| extend bucket = bin(TimeGenerated, 1h)
| summarize req = count(), asn = dcount(client_asn), ua = dcount(user_agent) by bucket, url_path
| extend asn_per_1k = (asn * 1000.0) / req
| where url_path == "/checkout"
| order by bucket asc
```

False-positive note: a single large corporate NAT or a carrier-grade NAT collapses ASN diversity for genuine traffic too; resolve the dominant ASN to its organisation before concluding botnet.

## Class 3 — Cache-bypass signature

Expected hit: MISS ratio near saturation on one endpoint while overall volume is unremarkable. This is the family that exhausts origin compute without moving a bandwidth graph.

```sql
SELECT date_trunc('minute', request_ts)          AS minute_bucket,
       count(*)                                  AS requests,
       round(avg((edge_cache_result = 'BYPASS')::int), 3) AS bypass_ratio,
       count(DISTINCT url_query_fingerprint)     AS query_fingerprints
FROM edge_request_log
WHERE request_ts > now() - interval '2 hours'
  AND request_path = '/api/v2/quote'
GROUP BY date_trunc('minute', request_ts)
HAVING count(DISTINCT url_query_fingerprint) > 500
ORDER BY date_trunc('minute', request_ts);
```

False-positive note: a cache purge or a TTL expiry produces the same ratio with flat query-fingerprint cardinality; check the cache configuration change log against the onset minute.

## Class 4 — Origin path attestation

Expected hit: zero origin requests whose source address falls outside the published edge ranges. Any non-zero count means the mitigation path is bypassed and every upstream control is decorative.

```text
classification_attestation:
  question:      does traffic reach the origin only through the mitigation path?
  evidence:      origin ingress log with client address preserved
  expected:      0 requests outside published edge CIDRs, after excluding
                 documented health checks and partner integrations
  blind_spot:    origins that rewrite client address to the edge address
                 cannot answer this question; record the limitation
```

False-positive note: a load balancer health check from an internal range is expected traffic; baseline by user-agent before declaring the range open.

## Class 5 — Mitigation effect attestation

Expected hit: a provider event record overlapping the incident window, with edge volume high and origin ingress low in the same minutes. The pair is the causation evidence.

```kusto
MitigationEvents
| where TimeGenerated > ago(6h)
| project EventId = Id, StartedAt = StartTime, PeakPps, DroppedBytes
| join kind=inner (
    AlbAccessLog
    | where TimeGenerated > ago(6h)
    | summarize ingress = count() by TimeGenerated
  ) on $left.StartedAt == $right.TimeGenerated
| where ingress < 100
| project EventId, StartedAt, PeakPps, DroppedBytes, ingress
```

False-positive note: an event created retrospectively by the provider after the traffic subsided did not cause the decline; compare the event start with the origin recovery minute before crediting it.

## Class 6 — Business-continuity threshold

Expected hit: measured numbers that let the incident commander choose degradation deliberately — current capacity, mitigated capacity, and the projected duration at current rate. This class exists because the alternative decision is made from panic.

```text
decision_inputs:
  contracted_mitigation_peak:  <provider contract value, pps or bps>
  observed_peak:               <measured, with source named>
  origin_capacity_headroom:    <current req/s vs tested saturation point>
  degradation_options:         [serve_static, disable_search, queue_writes, regional_failover]
  cost_of_each_option:         <business impact, not infrastructure cost>
  authority:                   <role empowered to choose, per the IR plan>
```

False-positive note: an observed peak measured on a sampled or aggregated interface under-reports the true rate; state the measurement method beside the number, since capacity decisions inherit its error.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record which measurement point each class reads, because a query answered from a blind point returns a confident and wrong zero.
