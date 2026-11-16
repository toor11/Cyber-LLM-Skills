# Detection Queries and Telemetry Artifacts

> Sub-skill: [`waf-and-web-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

WAF verdict, score and reconciliation queries owned by `waf-and-web-monitoring`. Field names follow the ModSecurity/Coraza audit log or the vendor's normalised schema; confirm the mapping your shipper applies before deploying. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Verdict and score distribution

Expected hit: a distribution of actions with the score attached, not just a count of blocked requests. Allowed requests with a nonzero score are the population that matters.

```spl
index=waf sourcetype="modsecurity:json" earliest=-24h@h latest=@h
| stats count AS requests,
        count(eval(verdict_action="blocked")) AS blocked,
        count(eval(verdict_action="allowed" AND score_total > 0)) AS allowed_scored,
        max(score_total) AS peak_score
  BY host, tx_blocking_paranoia_level
| eval blocked_pct = round(100*blocked/requests, 2)
| sort - allowed_scored
```

False-positive note: a request with a nonzero score that was allowed may be below the threshold by design; compare its score against `tx.inbound_anomaly_score_threshold` before calling it a miss.

## Class 2 — Rule-family attribution

Expected hit: which rule IDs contributed the score, grouped by family prefix (for example 942 for SQL injection, 932 for remote command execution, 930 for PHP injection). Attribution separates a paranoia-level artefact from a genuine gap.

```spl
index=waf sourcetype="modsecurity:json" earliest=-7d@d
| where verdict_action IN ("blocked", "allowed") AND score_total > 0
| mvexpand rule_id
| eval family = substr(rule_id, 1, 3)
| stats count AS hits, dc(client_ip) AS clients BY family, tx_blocking_paranoia_level
| eval block_ratio = round(hits / clients, 3)
```

False-positive note: a family with zero hits at PL1 that is active at PL3 is a configuration difference, not an absence of attacks; read the paranoia column before drawing either conclusion.

## Class 3 — Origin reconciliation

Expected hit: requests present in the WAF log and absent from the origin log are effective blocks; requests present in both were allowed and served. A "blocked" request with an origin entry is the finding.

```kql
let waf = WAFLogs_CL
| where TimeGenerated between (ago(6h) .. now()) and isnotempty(RequestId_s)
| project req_id = RequestId_s, method = Method_s, path = Path_s, ts = TimeGenerated,
          action = Action_s, score = ScoreTotal_d;
let origin = AppAccessLogs_CL
| where TimeGenerated between (ago(6h) .. now()) and isnotempty(Method_s)
| project method = Method_s, path = Path_s, ts = TimeGenerated, status = Status_d;
waf
| join kind=leftouter origin on $left.path == $right.path and $left.method == $right.method
| where isnotempty(status) and action == "blocked"
| project req_id, path, method, action, status, score
```

False-positive note: time-shifted clocks between the WAF and the origin break this join; verify the offset with a known request before concluding a block failed.

## Class 4 — Allowed-with-score bypass candidates

Expected hit: allowed requests whose score exceeded zero but stayed under the threshold, grouped by path and rule family. A rising count on one path is the signal.

```spl
index=waf sourcetype="modsecurity:json" earliest=-14d@d latest=@h
| where verdict_action="allowed" AND score_total > 0
| eval phase = if(_time >= relative_time(now(), "-24h@h"), "probe", "baseline")
| stats count AS reqs BY path, phase
| stats sum(eval(if(phase="probe", reqs, 0))) AS probe,
        sum(eval(if(phase="baseline", reqs, 0))) AS baseline BY path
| eval per_day_base = round(baseline/13, 1)
| where probe > 10 AND (per_day_base == 0 OR probe > 3*per_day_base)
| sort - probe
```

False-positive note: a new feature that legitimately sends high-scoring but benign payloads raises this count; confirm with the application owner before treating the path as under attack.

## Class 5 — Coverage of path-borne payloads

Expected hit: rule families whose targets include the request path, and their hit distribution. A family that never fires on path-borne probes has no path coverage.

```text
# Probe design (send from an authorised test host against a staging deploy):
#   GET /files/x%3Bid          -> path-borne command separator
#   GET /files?f=x%3Bid        -> query-borne equivalent
# Expected: both produce a 932-family hit on a build with path targets enabled.
# A hit on the query form and silence on the path form is the coverage finding.
```

False-positive note: a reverse proxy that rewrites the path before the WAF sees it changes what arrives; confirm where the engine sits on the request path before recording a coverage gap.

## Class 6 — Layer disagreement

Expected hit: the same request recorded with different verdicts by two layers, or an origin entry for a request the edge says it blocked. Either indicates a layer that is not enforcing.

```kql
CDNLogs_CL
| where TimeGenerated > ago(1h)
| project req_id = RequestId_s, ts = TimeGenerated, edge_action = Action_s, client = ClientIp_s
| join kind=inner (WAFLogs_CL | project req_id = RequestId_s, waf_action = Action_s) on req_id
| where edge_action != waf_action
| project req_id, edge_action, waf_action, client
```

False-positive note: some CDNs log a cache outcome as their action rather than a security verdict; confirm the field's semantics before reading a disagreement as a bypass.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record `tx.blocking_paranoia_level`, the inbound threshold and the engine version beside every alert; a rule family's absence is meaningless without them.
