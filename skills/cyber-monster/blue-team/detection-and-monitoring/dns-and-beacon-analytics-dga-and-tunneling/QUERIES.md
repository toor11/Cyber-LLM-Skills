# Detection Queries and Telemetry Artifacts

> Sub-skill: [`dns-and-beacon-analytics-dga-and-tunneling`](SKILL.md) | Family: **Detection and Monitoring**

Blocks below separate the two hypotheses: DGA (many candidates, few resolve) and tunnelling (successful lookups carrying payload). Plane coverage and per-host baselining belong to [`dns-and-beacon-analytics`](../dns-and-beacon-analytics/SKILL.md); interval scoring belongs to [`dns-and-beacon-analytics-beacon-periodicity`](../dns-and-beacon-analytics-beacon-periodicity/SKILL.md).

## Class 1 — Parent-domain aggregation baseline

Expected hit: one row per (host, registrable parent) with the feature set every later block scores against. Without this table, each class below is an absolute threshold.

```spl
index=dns sourcetype="dns:query" earliest=-14d@d latest=@d
| eval qname = lower(query)
| rex field=qname "^(?<leftmost>[^.]+)\.(?<rest>.+)$"
| rex field=rest "^(?:.*\.)?(?<parent>[^.]+\.[^.]+)$"
| stats count AS q, dc(qname) AS uniq, avg(len(leftmost)) AS avg_label,
        p95(len(leftmost)) AS p95_label, sum(answer_bytes) AS bytes
        by src_host, parent
| eval uniq_ratio = round(uniq/q, 3), bytes_per_q = round(bytes/nullif(q,0), 1)
| where q >= 20
| table src_host, parent, q, uniq, uniq_ratio, avg_label, p95_label, bytes_per_q
```

False-positive note: `rex` on the parent fails for single-label internal names and for public suffixes such as `co.uk`; validate the parent extraction against a known list before scoring anything.

## Class 2 — DGA hypothesis: NXDOMAIN share and candidate volume

Expected hit: a host with a high NXDOMAIN share under one parent and a high count of distinct candidate names. A host with many NXDOMAINs spread across many parents is more likely a misconfigured client.

```spl
index=dns sourcetype="dns:response" earliest=-24h@h latest=@h
| eval qname = lower(query)
| rex field=qname "^(?:.*\.)?(?<parent>[^.]+\.[^.]+)$"
| eval nx_flag = if(rcode=="NXDOMAIN", 1, 0)
| stats sum(nx_flag) AS nx, count AS total, dc(qname) AS candidates by src_host, parent
| eval nx_share = round(nx/total, 3)
| where nx_share >= 0.5 AND candidates >= 50
| sort - candidates
```

False-positive note: a client configured with a wrong search suffix produces thousands of NXDOMAINs under one parent; the tell is that the candidate names are human-readable dictionary words rather than machine-generated, so sample a few labels before escalating.

## Class 3 — Tunnel hypothesis: unique-subdomain ratio and label length

Expected hit: a parent domain where nearly every lookup carries a distinct, long leftmost label. This is the strongest single shape for encoded payload carriage.

```spl
index=dns sourcetype="dns:query" earliest=-24h@h latest=@h
| eval qname = lower(query)
| rex field=qname "^(?<leftmost>[^.]+)\.(?<rest>.+)$"
| rex field=rest "^(?:.*\.)?(?<parent>[^.]+\.[^.]+)$"
| stats count AS q, dc(qname) AS uniq, p95(len(leftmost)) AS p95_label,
        dc(src_host) AS hosts by parent
| eval uniq_ratio = round(uniq/q, 3)
| where uniq_ratio >= 0.9 AND p95_label >= 40 AND hosts <= 3
| sort - uniq_ratio, hosts
```

False-positive note: a CDN parent serving hashed object names matches this shape exactly; the distinguishing field is `hosts`, since CDN parents are contacted by many hosts while a tunnel endpoint usually has one or two clients.

## Class 4 — Record-type mix

Expected hit: parents whose TXT, NULL, or rarely-used record queries form a meaningful share of their traffic. Legitimate TXT use concentrates on a small set of well-known parents.

```kql
DnsEvents
| where TimeGenerated between (ago(26h) .. now())
| summarize total=count(), txt=countif(QueryType == "TXT"),
            null_q=countif(QueryType == "NULL"), other=countif(QueryType !in ("A","AAAA","CNAME","TXT","NULL"))
            by ParentDomain=extract(@"([^.]+\\.[^.]+)$", 1, Name)
| extend txt_share = round(1.0*txt/total, 3)
| where txt_share >= 0.2 or null_q > 0
| order by txt_share desc
```

False-positive note: SPF, DKIM, DMARC, and ACME validation queries are TXT by design and concentrate on mail and certificate parents; exclude those parents explicitly rather than lowering the share threshold.

## Class 5 — Query-to-byte correlation

Expected hit: a parent where answer bytes per query rise with unique-name count, the signature of data transfer. Ordinary resolution grows names without a proportional byte increase.

```spl
index=dns sourcetype="dns:response" earliest=-7d@d latest=@d
| rex field=query "^(?:.*\.)?(?<parent>[^.]+\.[^.]+)$"
| bin _time span=60m
| stats count AS q, dc(query) AS uniq, sum(answer_bytes) AS bytes by _time, src_host, parent
| eventstats median(bytes/q) AS med_bpq by src_host
| where (bytes/q) > med_bpq * 2 AND uniq >= 30
| sort - bytes, parent
```

False-positive note: a caching resolver answers from cache, so the recorded answer size is the cached copy's size rather than what the host requested; compute this on endpoint or egress records where available.

## Class 6 — Fleet rarity of the parent

Expected hit: parent domains contacted by one or two hosts while carrying volume. This is the feature that separates a tunnel endpoint from infrastructure, and it is cheap to compute on the baseline table.

```spl
index=dns sourcetype="dns:query" earliest=-30d@d latest=@d
| rex field=query "^(?:.*\.)?(?<parent>[^.]+\.[^.]+)$"
| stats dc(src_host) AS hosts, count AS q, sum(answer_bytes) AS bytes by parent
| eval q_per_host = round(q/hosts, 1)
| where hosts <= 2 AND q >= 100
| sort - q_per_host
```

False-positive note: hosts behind a NAT gateway or a shared proxy appear as one source; check whether the resolver sees pre-NAT addresses before treating `hosts` as the true client count.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Store the parent-domain baseline table and the enrichment source used for registration age; a score whose inputs cannot be reproduced is not reviewable.
