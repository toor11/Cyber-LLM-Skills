# Detection Queries and Telemetry Artifacts

> Sub-skill: [`data-loss-prevention-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Queries below join three evidence families — content verdicts, byte volumes, and endpoint file access — and each block states which family it reads. Field names follow a normalised DLP verdict index (`sourcetype=dlp:verdict`), a proxy access log (`sourcetype=proxy:http`), and an EDR file-event index. Substitute your own names after confirming extraction; the SPL base-search rules in [`siem-query-and-log-analysis-splunk-spl`](../siem-query-and-log-analysis-splunk-spl/SKILL.md) apply to every block.

## Class 1 — Channel coverage assertion (run first)

Expected hit: one row per egress channel with a rule count and a last-verdict timestamp. A channel with `rules=0` cannot produce a verdict and any "no DLP alerts" conclusion about it is meaningless.

```spl
index=dlp sourcetype="dlp:policy_inventory" earliest=-7d@d latest=@d
| stats dc(rule_id) AS rules, max(_time) AS last_verdict, count AS verdicts by channel, policy_version
| eval hours_since = round((now() - last_verdict)/3600, 1)
| where rules == 0 OR hours_since > 72
| sort rules
```

False-positive note: a channel can be licensed and configured but carry no traffic on a quiet weekend, so `hours_since` alone is not a gap; pair it with the channel's traffic volume before escalating.

## Class 2 — Per-identity deviation against own baseline

Expected hit: a small set of identities whose probe-window bytes exceed their own median by several robust standard deviations, in the unsanctioned destination class. Rank by deviation and read absolute size beside it.

```spl
index=proxy sourcetype="proxy:http" earliest=-30d@d latest=@d
| eval dclass = case(match(lower(url), "(dropbox|box\.com|mega\.nz|wetransfer|pastebin|transfer\.sh)"), "unrecognised-external",
                      match(lower(url), "(sharepoint|onedrive.*contoso|drive\.google.*contoso)"), "sanctioned-tenant",
                      true(), "other-external")
| bin _time span=1440m
| stats sum(bytes_out) AS bytes by _time, user, dclass
| eventstats median(bytes) AS med, median(abs(bytes - median(bytes))) AS mad by user, dclass
| where _time >= relative_time(now(), "-1d@d") AND dclass=="unrecognised-external"
| eval score = if(mad > 0, round((bytes - med)/(1.4826*mad), 2), null())
| where score >= 6
| sort - score
```

False-positive note: a first transfer to a new destination class has a baseline dominated by zero-byte days, inflating the score; require at least seven non-zero baseline days for the identity before scoring.

## Class 3 — Verdict-to-transfer join

Expected hit: DLP verdicts whose `transfer_id` or message identifier matches a proxy request or mail gateway record, with the destination in the unsanctioned class. An unmatched verdict is a policy-scope question rather than an exfiltration.

```spl
index=dlp sourcetype="dlp:verdict" earliest=-7d@d latest=@d
| where severity IN ("high","critical") AND isnotnull(data_class)
| join type=left transfer_id
    [ search index=proxy sourcetype="proxy:http" earliest=-7d@d latest=@d
      | eval transfer_id=coalesce(x_request_id, message_id)
      | fields transfer_id, dest_host, url, bytes_out, user ]
| where isnull(dest_host)
| stats count AS orphan_verdicts by data_class, policy_version, channel
```

False-positive note: the join key is frequently absent because proxy logs omit request IDs for CONNECT tunnels; an orphan verdict on an HTTPS upload is a join limitation, not proof the content stayed inside.

## Class 4 — Endpoint process attribution for the flagged file

Expected hit: a file-read or file-open event for the flagged document by the process that also carried the transfer, inside the transfer window. A browser upload with no corresponding file read suggests the content was staged earlier and the read record may sit outside the window.

```spl
index=edr sourcetype="edr:file_event" earliest=-2h latest=now
| search file_path="*\\Finance\\Exports\\*" OR file_path="*\\Q4-forecast*"
| stats values(action) AS actions, dc(process_name) AS readers, min(_time) AS first_touch, max(_time) AS last_touch by host, user, file_path
| where readers > 0
| sort - last_touch
```

False-positive note: the endpoint agent logs file opens by indexers, backup agents, and antivirus scans as well as the user; filter on the interactive session or the process lineage before attributing the read to the person.

## Class 5 — Alternate egress channel check

Expected hit: removable-media writes, print-spool events, or personal-sync-client activity for the same identity in the same window. These channels have no DLP verdict at all in many estates, so the check is the only evidence available.

```spl
index=edr sourcetype="edr:usb_event" OR sourcetype="edr:print_event"
| eval channel = if(sourcetype=="edr:usb_event", "removable", "print")
| stats count AS events, values(file_name) AS files by user, host, channel
| where events > 0
| sort - events, user
```

False-positive note: a docking station re-enumerating a known corporate drive generates removable-media events with no data written; require a write action and a non-zero byte count before treating it as egress.

## Class 6 — First-seen destination novelty

Expected hit: identities contacting a domain or IP that is new to the fleet in the last seven days and outside the sanctioned set. Novelty is significant even at low volume because established business relationships are rarely new.

```spl
index=proxy sourcetype="proxy:http" earliest=-7d@d latest=@d
| eval host=lower(dest_host)
| stats min(_time) AS first_seen, dc(user) AS users, sum(bytes_out) AS bytes by host
| where first_seen >= relative_time(now(), "-7d@d") AND users <= 3
| sort - bytes, sender
```

False-positive note: CDN hostnames rotate continuously and will always appear new; normalise to the registrable domain and exclude the organisation's own delivery domains before ranking.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Publish the channel coverage matrix and the destination-class map with every deployment; a rule that compares against an undefined destination class cannot be reviewed.
