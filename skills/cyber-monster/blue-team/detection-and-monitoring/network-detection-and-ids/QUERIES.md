# Detection Queries and Telemetry Artifacts

> Sub-skill: [`network-detection-and-ids`](SKILL.md) | Family: **Detection and Monitoring**

Alert, flow and handshake queries owned by `network-detection-and-ids`. Field names follow the Suricata `eve.json` schema as flattened by the Splunk TA (`alert.signature_id`, `tls.ja4`, `dns.rrname`); Zeek equivalents are `conn.log`, `dns.log` and `ssl.log`. Confirm the mapping your shipper applies before deploying. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Sensor health before any interpretation

Expected hit: capture-kernel drop ratio near zero and a monotonic stats interval. A window with drops makes every absence in Classes 2-5 unproven.

```spl
index=suricata sourcetype="suricata:stats" earliest=-24h@h latest=@h
| stats sum(capture.kernel_drops) AS drops, sum(capture.kernel_packets) AS pkts BY host
| eval drop_pct = round(100*drops/pkts, 3)
| where drop_pct > 0.5
| sort - drop_pct
```

False-positive note: a mirror port that oversubscribes during a backup window shows drops with no security relevance; correlate drop intervals against bulk-transfer schedules before declaring the sensor unfit.

## Class 2 — Signature attribution with revision

Expected hit: `alert.signature_id` paired with `alert.rev` and a `flow_id` that also appears as a flow record. The `rev` is what makes the finding reproducible after a rule update.

```spl
index=suricata sourcetype="suricata:json" event_type=alert earliest=-24h@h latest=@h
| eval rule = 'alert.signature_id'.":".'alert.rev'
| stats count AS hits, dc(dest_ip) AS dsts, min(timestamp) AS first, max(timestamp) AS last BY rule, 'alert.signature'
| eventstats sum(hits) AS fleet_total
| eval share_pct = round(100*hits/fleet_total, 2)
| table rule, 'alert.signature', hits, dsts, share_pct, first, last
```

False-positive note: the same `sid` with a bumped `rev` is a different detection; grouping on `sid` alone merges a fixed rule with its noisy predecessor and makes tuning look ineffective.

## Class 3 — Flow baseline for one destination and service

Expected hit: a small set of (source, destination, service) keys whose probe-window byte count exceeds their own baseline mean by several standard deviations. Absolute volume is not the signal; the per-key delta is.

```spl
index=suricata sourcetype="suricata:json" event_type=flow flow.state=established earliest=-15d@d latest=@h
| eval k = src_ip.">".dest_ip.":".dest_port
| timechart span=1d sum(bytes) AS b, count AS sessions BY k limit=0
| eventstats avg(b) AS mu, stdev(b) AS sd BY k
| where b > mu + (3*sd) AND sessions > 20 AND _time >= relative_time(now(), "-24h@h")
| sort - b
```

False-positive note: a CDN behind a rotating IP set produces a new key every day with no baseline; key on the registered domain from `tls.sni` or `dns.rrname` rather than the IP.

## Class 4 — Encrypted-traffic handshake rarity

Expected hit: a client fingerprint paired with an SNI its peer group does not normally use, and a low host count for that pair. Prevalence is the discriminator and must be printed.

```spl
index=suricata sourcetype="suricata:json" event_type=tls earliest=-7d@d latest=@h
| eval pair = 'tls.ja4'."|".'tls.sni'
| stats dc(src_ip) AS hosts, count AS conns BY pair
| where hosts <= 2 AND conns > 5
| sort - conns
```

False-positive note: a line-of-business app on an old runtime can produce a genuinely rare fingerprint; a rare pair is a lead needing endpoint corroboration, not a verdict. JA4 derivation and prevalence method are owned by [c2-traffic-analysis](../../malware-analysis/c2-traffic-analysis/SKILL.md); do not duplicate that method here.

## Class 5 — Protocol anomaly and parser failure

Expected hit: flows the engine could not classify, or anomaly records on protocols the estate normally parses cleanly. This is where signature rules silently lose their app-layer fields.

```kql
SuricataAnomaly_CL
| where TimeGenerated between (ago(12h) .. now())
| summarize evts = count() by app_proto_s, anomaly_type_s
| where evts > 10
| order by evts desc
```

```kql
SuricataFlow_CL
| where TimeGenerated between (ago(12h) .. now()) and app_proto_s == "failed"
| summarize unclassified = count(), dsts = dcount(dest_ip_s) by dest_port_d
| where unclassified > 50
| order by unclassified desc
```

False-positive note: custom line-of-business protocols on high ports are permanently `failed`; exclude ports the asset inventory documents as non-HTTP before treating this as evasion.

## Class 6 — DNS naming shape

Expected hit: query names whose label length sits far outside the estate norm, with a low host count and a high per-host query rate.

```spl
index=suricata sourcetype="suricata:json" event_type=dns earliest=-24h@h latest=@h
| eval label_len = len('dns.rrname')
| stats count AS queries, dc(src_ip) AS hosts, avg(label_len) AS avg_len BY 'dns.rrname'
| where avg_len > 40 AND hosts <= 3 AND queries > 50
| table 'dns.rrname', queries, hosts, avg_len
```

False-positive note: antivirus and reputation lookups use long hashed names inside a small set of vendor domains; allowlist by registered domain before alerting on label length alone.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record sensor position, enabled app-layer parsers and the drop ratio beside every saved query; without them a zero cannot be distinguished from a blind spot.
