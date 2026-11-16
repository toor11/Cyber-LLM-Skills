# Evidence and Attestation Queries

> Sub-skill: [`botnet-and-application-ddos-mitigation`](SKILL.md) | Family: **Incident Response**

Queries owned by `botnet-and-application-ddos-mitigation`, grouped by the evidence question they answer during a live availability incident. These are attestation queries: each one either proves a mitigation is in the traffic path, proves a vantage point is blind, or proves the flood has stopped for a reason other than the attacker choosing to stop. Confirm field names against your own CDN, transit and origin schemas before deployment.

## Class 1 — Vantage-point attestation (run before any mitigation claim)

Expected hit: at least one row per vantage point — edge request analytics, transit flow, origin ingress — covering the incident window. A vantage point that is absent or whose data ends before onset means every later conclusion is conditional.

```kql
union withsource=tbl
    CloudflareAccessLog, AwsVpcFlowLog,
    AlbAccessLog
| where TimeGenerated between (ago(6h) .. now())
| summarize rows = count(), first = min(TimeGenerated), last = max(TimeGenerated) by tbl
```

False-positive note: a vantage point that is merely quiet during a low-volume incident looks identical to one that is not collected; confirm against the pipeline inventory, not against row counts.

## Class 2 — Absorption proof at the edge

Expected hit: edge request rate rising while origin ingress rate stays flat or falls inside the same UTC minute. The pair is the finding; either series alone is uninterpretable.

```kql
let edge = CloudflareAccessLog
    | where TimeGenerated between (ago(2h) .. now())
    | summarize edge_req = count() by bin(TimeGenerated, 1m);
let origin = AlbAccessLog
    | where TimeGenerated between (ago(2h) .. now())
    | summarize origin_req = count() by bin(TimeGenerated, 1m);
edge | join kind=fullouter origin on TimeGenerated
| extend ratio = origin_req * 1.0 / edge_req
| project TimeGenerated, edge_req, origin_req, ratio
```

False-positive note: if the edge and origin series rise together the mitigation path is bypassed, not working; a flat ratio near 1.0 during a "mitigated" flood is the signature of direct-to-origin traffic.

## Class 3 — Cache-bypass and cache-key abuse

Expected hit: MISS ratio on one endpoint climbing from a stable baseline toward saturation while distinct query-string cardinality rises. This separates randomised cache-key floods from genuine demand surges.

```sql
SELECT date_trunc('minute', ts) AS minute,
       count(*)                                   AS req,
       avg((cache_status = 'MISS')::int)          AS miss_ratio,
       count(DISTINCT qs_hash)                    AS qs_cardinality,
       count(DISTINCT client_asn)                 AS asn_cardinality
FROM cdn_access_log
WHERE ts > now() - interval '2 hours'
  AND path = '/api/v2/quote'
GROUP BY date_trunc('minute', ts)
ORDER BY date_trunc('minute', ts);
```

False-positive note: a cache purge, deploy or TTL change produces the same MISS ratio with flat query-string cardinality — check the cache configuration change log against the onset minute first.

## Class 4 — HTTP/2 stream-reset and control-frame exhaustion

Expected hit: `RST_STREAM` per connection and control-frame rate rising while bytes transferred stay flat. The reset direction distinguishes client-driven from server-provoked floods, and the fix differs.

```text
edge_log_fields_required:
  http2.stream_id, http2.frame_type, http2.rst_stream_direction,
  http2.settings_per_connection, connections, bytes_out, requests
decision:
  - if rst_direction=client  -> client-sent reset flood
  - if rst_direction=server  -> server-provoked reset flood (limit the trigger frames)
  - if frames dominant=PING  -> control-frame flood, count PING per connection
```

False-positive note: connection pooling clients that recycle aggressively also emit resets; require resets-per-connection to exceed the fleet 99th percentile for that client family before treating it as abuse.

## Class 5 — Provider mitigation attestation

Expected hit: a provider mitigation event record with an identifier, start time, peak packet rate and drop volume overlapping the incident window. This is the only evidence that the provider, rather than the attacker, caused the decline.

```bash
# Pull the mitigation event window from the scrubbing/CDN API, then diff it against
# your own origin ingress drop. Read-only call; no configuration is changed.
curl -sS -H "Authorization: Bearer ${CDN_TOKEN}" \
  "https://api.example-mitigation-provider.invalid/v1/events?from=${START_ISO}&to=${END_ISO}" \
  | jq -r '.result[] | [.id, .start, .peak_pps, .dropped_bytes] | @tsv'
```

False-positive note: an event record that starts after your origin recovered is a retrospective classification, not the mitigation that saved you; compare timestamps before crediting it.

## Class 6 — Origin shielding residual access

Expected hit: zero origin requests whose source address falls outside the published edge ranges, measured from the origin side. Any non-zero count is a shielding failure that survives every rule you deploy upstream.

```text
path_attestation:
  query: origin ingress logs where client_ip NOT IN published_edge_cidrs
  expected: 0 rows after shielding is enforced
  blind_spot: origins that rewrite client_ip to the edge address
              lose the ability to answer this question at all
```

False-positive note: health checks, internal load balancers and partner integrations legitimately reach the origin directly; baseline them by source address and user-agent before declaring the range open.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, next to every saved query, which vantage point it depends on and what a zero row means for that vantage point.
