# Detection Queries and Telemetry Artifacts

> Sub-skill: [`dns-and-beacon-analytics`](SKILL.md) | Family: **Detection and Monitoring**

Blocks are grouped by the plane that carries the evidence: resolver, endpoint DNS, and flow. Each class states its expected hit and the false-positive note that must be cleared before the hit becomes a finding. The interval-scoring internals live in [`dns-and-beacon-analytics-beacon-periodicity`](../dns-and-beacon-analytics-beacon-periodicity/SKILL.md) and the label-statistics internals in [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md); do not duplicate those blocks here. Base-search mechanics are in [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md).

## Class 1 — Resolver coverage per host

Expected hit: one row per host that queried in the window, with a query count comparable to its normal level. Hosts on the asset inventory with no rows are resolver bypasses and any later absence claim excludes them.

```spl
index=dns sourcetype="dns:query" earliest=-24h@h latest=now
| stats count AS queries, dc(query) AS distinct_names by src_host
| eventstats median(queries) AS fleet_median
| where queries < fleet_median * 0.1
| sort queries
```

False-positive note: a host that is powered off, travelling, or on a network segment with its own resolver legitimately appears here; reconcile against the endpoint agent's online state before filing a bypass.

## Class 2 — Endpoint-plane attribution for a domain

Expected hit: the process image and `ProcessGuid` that issued the query, paired with the query name. This is the only plane that can name a process, and the join to the resolver view is what turns a name into a host-plus-process finding.

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 earliest=-24h@h latest=@h
| eval qname = lower(QueryName)
| where like(qname, "%.example-cdn.test") OR like(qname, "%.storage.example.test")
| stats count AS queries, dc(qname) AS names, values(Image) AS images, dc(ProcessGuid) AS procs
        by host, Image
| sort - queries, distinct_names
```

False-positive note: a browser resolves through a broker process, so the image that queries is not always the tab's process; correlate the `ProcessGuid` to the process tree (event 1) before attributing the query to a user action.

## Class 3 — Per-host unique-subdomain ratio

Expected hit: hosts whose ratio of distinct subdomains to total queries for one registrable domain approaches 1, against a baseline near zero. A tunnel that sends each chunk under a fresh name produces exactly this shape.

```spl
index=dns sourcetype="dns:query" earliest=-7d@d latest=@d
| eval regdom = replace(lower(query), "^.*?([^.]+\.[^.]+)$", "\1")
| stats count AS q, dc(query) AS uniq by src_host, regdom
| eval uniq_ratio = round(uniq/q, 4)
| where q >= 50 AND uniq_ratio > 0.9
| sort - uniq_ratio, q
```

False-positive note: certificate-transparency lookups, telemetry pingbacks with GUID paths, and CDN hostnames all produce high ratios; exclude by registrable domain only after confirming the excluded parent cannot host attacker-registered names.

## Class 4 — Response-code profile per host

Expected hit: a host whose NXDOMAIN share for one registrable domain is far above its own baseline, or a domain that returns NOERROR for every query while carrying large answers. The first shape suggests name guessing, the second a query-only channel.

```spl
index=dns sourcetype="dns:response" earliest=-14d@d latest=@d
| eval regdom = replace(lower(query), "^.*?([^.]+\.[^.]+)$", "\1")
| eval nx = if(rcode=="NXDOMAIN", 1, 0)
| bin _time span=86400s
| stats sum(nx) AS nx, count AS total by _time, src_host, regdom
| eventstats avg(eval(nx/total)) AS base_nx by src_host, regdom
| where _time >= relative_time(now(), "-1d@d") AND (nx/total) > base_nx * 3 AND total > 20
| sort - total
```

False-positive note: search-suffix resolution generates NXDOMAIN bursts whenever a client probes short names; group on the registrable domain so the probe candidates collapse into one row.

## Class 5 — Plane join rate

Expected hit: a high join rate between resolver rows and endpoint DNS events for the same host and minute. A low rate is a visibility statement about the estate, and it bounds every attribution you can make.

```kql
let resolver = DnsEvents
| where TimeGenerated > ago(60m)
| summarize r=count() by Computer, bin(TimeGenerated, 1m);
let endpoint = DeviceEvents
| where TimeGenerated > ago(60m)
| where ActionType == "DnsQueryResponse"
| summarize e=count() by DeviceName=Computer, bin(TimeGenerated, 1m);
resolver
| join kind=leftouter endpoint on Computer, TimeGenerated
| extend joined = isnotnull(e)
| summarize rate=avg(iff(joined, 1.0, 0.0)), rows=count() by Computer
| where rate < 0.5 and rows > 150
| order by rate asc
```

False-positive note: the two tables can use different host-identity fields (NetBIOS name versus device ID) and different minute boundaries; normalise the key before treating a low rate as a sensor gap.

## Class 6 — Sanctioned-domain exclusion audit

Expected hit: the exclusion list's own coverage, showing which domains are excluded and how much traffic each excludes. An exclusion that suppresses a large share of a host's DNS is a coverage decision that needs an owner.

```spl
index=dns sourcetype="dns:query" earliest=-7d@d latest=@d
| eval regdom = replace(lower(query), "^.*?([^.]+\.[^.]+)$", "\1")
| lookup sanctioned_domains regdom OUTPUT sanctioned
| stats count AS queries, dc(src_host) AS hosts by regdom, sanctioned
| where sanctioned=="true"
| sort - hosts
```

False-positive note: a sanctioned SaaS parent domain can also host tenant-specific subdomains created by an attacker with a free account; excluding the parent silently covers those, so the exclusion should name the tenant subdomain where the provider allows it.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Store the per-host baseline table used by every scored rule; a rule whose baseline is recomputed differently on each run cannot be reviewed or reproduced.
