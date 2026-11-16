# Detection Queries and Telemetry Artifacts

> Sub-skill: [`dns-and-beacon-analytics-beacon-periodicity`](SKILL.md) | Family: **Detection and Monitoring**

Cadence queries need ordered timestamps, so every block below starts from a raw event or connection record and never from a pre-aggregated summary. Plane coverage and per-host baselining belong to [`dns-and-beacon-analytics`](../dns-and-beacon-analytics/SKILL.md); name-level label statistics belong to [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md).

## Class 1 — Ordered interval series per host and destination

Expected hit: one row per (host, destination) pair with the interval statistics needed for scoring. Pairs with fewer than ten observations are listed separately because they cannot be scored.

```spl
index=netflow sourcetype="conn:summary" earliest=-7d@d latest=@d
| sort 0 + src_host, dst_ip, _time
| streamstats current=f window=1 values(_time) AS prev_time by src_host, dst_ip
| eval interval = _time - prev_time
| where isnotnull(interval)
| stats count AS intervals, median(interval) AS med, p25(interval) AS q1, p75(interval) AS q3
        by src_host, dst_ip
| eval mad_proxy = round((q3 - q1)/2, 1)
| eval bowley = if((q3 - q1) >= 10, round((q1 + q3 - 2*med)/(q3 - q1), 3), null())
| where intervals >= 10
| sort - intervals
```

False-positive note: `streamstats` orders on `_time` after sorting, but events indexed late can still arrive out of order; confirm by comparing `_indextime` ordering on the highest-volume pair.

## Class 2 — Resolution sweep for one series

Expected hit: a dispersion score that holds across neighbouring bin widths. A score that appears at exactly one width and collapses on either side is an artefact of the binning, not a period.

```spl
index=netflow sourcetype="conn:summary" src_host="WS-0421" dst_ip="203.0.113.44" earliest=-7d@d latest=@d
| sort 0 + _time
| streamstats current=f window=1 values(_time) AS prev_time
| eval interval = _time - prev_time
| where isnotnull(interval)
| eval bin5 = round(interval/5)*5, bin15 = round(interval/15)*15, bin30 = round(interval/30)*30
| stats count AS n, stdev(bin5) AS sd5, stdev(bin15) AS sd15, stdev(bin30) AS sd30,
        median(bin5) AS m5
| eval disp5 = round(1 - sd5/nullif(m5,0), 3), disp15 = null, disp30 = null
| table n, m5, sd5, disp5
```

False-positive note: rounding to a bin is not the same as re-binning the raw series; a rounded standard deviation understates dispersion for jittered beacons, so read the sweep as a stability check rather than as the final score.

## Class 3 — Byte-series regularity, scored separately

Expected hit: a byte series whose dispersion is either very tight (unpadded implant) or near random (padded implant). Reporting it separately from the interval score is what lets a padded beacon show up as a strong-interval, weak-size case.

```kql
let series = CommonSecurityLog
| where TimeGenerated > ago(7d) and isnotempty(DestinationIP)
| where DeviceAction == "allowed"
| where DestinationIP == "203.0.113.44"
| project TimeGenerated, SourceIP, SentBytes=tolong(SentBytes), ReceivedBytes=tolong(ReceivedBytes);
series
| summarize n=count(), med_out=percentile(SentBytes,50), p25=percentile(SentBytes,25),
            p75=percentile(SentBytes,75), med_in=percentile(ReceivedBytes,50)
            by SourceIP
| extend mad_out = (p75-p25)/2
| extend size_disp = iif(med_out>0, 1 - mad_out/med_out, 0.0)
| where n >= 10
| order by size_disp desc
```

False-positive note: TLS record overhead and retransmissions add several hundred bytes of variance to small check-ins, which makes an unpadded beacon look padded; compare series of similar total size before reading the dispersion.

## Class 4 — Peer comparison for the destination

Expected hit: the number of distinct hosts contacting the destination with a similar cadence. A peer group larger than a handful usually indicates a service; a single-host series against a rare destination is the candidate.

```spl
index=netflow sourcetype="conn:summary" earliest=-7d@d latest=@d
| stats count AS conns, dc(src_host) AS hosts, sum(bytes_out) AS bytes by dst_ip
| where conns >= 10
| eval per_host = round(conns/hosts, 1)
| where hosts <= 2 AND per_host >= 10
| sort - per_host
```

False-positive note: a destination reached through a NAT gateway shows few source hosts because the gateway aggregates them; resolve the flow record's pre-NAT source before concluding rarity.

## Class 5 — Retransmit de-duplication check

Expected hit: the ratio of raw connections to logical sessions. A high ratio means the interval series contains transport noise and must be de-duplicated before scoring.

```spl
index=netflow sourcetype="conn:summary" src_host="WS-0421" dst_ip="203.0.113.44" earliest=-24h@h latest=@h
| eval session = src_host."|".dst_ip."|".dst_port
| stats count AS raw_conns, dc(session) AS sessions, min(_time) AS first, max(_time) AS last by src_host
| eval dup_ratio = round(raw_conns/nullif(sessions,0), 2)
| where dup_ratio > 1.5
```

False-positive note: a keep-alive connection that reconnects on a fixed timeout legitimately produces multiple raw connections per session; check the destination port and protocol before treating the ratio as noise.

## Class 6 — Observation-count and duration floor

Expected hit: series that meet both the ten-observation and ten-period floors, listed separately from those that do not. Only the qualifying list should be scored.

```spl
index=netflow sourcetype="conn:summary" earliest=-7d@d latest=@d
| stats count AS conns, min(_time) AS first, max(_time) AS last by src_host, dst_ip
| eval span_h = round((last-first)/3600, 1)
| eval qualifying = if(conns >= 10 AND span_h >= 1, "yes", "no")
| stats count AS pairs by qualifying
| eventstats sum(count) AS total
| eval share = round(count/total, 3)
```

False-positive note: a genuinely low-frequency beacon (one check-in per hour) needs a window longer than a day to reach ten observations; widen the window before concluding the series is too short.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the resolution sweep, the normalisation, and the covered sleep band beside every deployed periodicity rule; a score without those three cannot be reviewed.
