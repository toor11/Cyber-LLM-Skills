# Evidence Queries and Attestation Artifacts

> Sub-skill: [`ransomware-response`](SKILL.md) | Family: **Incident Response**

Queries owned by `ransomware-response`. Each class answers a question the incident cannot be reported without: when did encryption start on each host, which entry branch precedes it, was recovery capability sabotaged first, and can the estate still be recovered without the actor. Field names follow ECS or WinEventLog conventions. This file is victim-side only — no actor communication, payment or negotiation content belongs here.

## Class 1 — Encryption onset and per-host bound

Expected hit: a write burst whose extension set is disjoint from that host's prior inventory, with a first-write timestamp per host and no further writes after the containment timestamp. That pair of timestamps is the onset and the containment proof.

```spl
index=edr sourcetype="edr:file" earliest=-48h@h latest=@h
| eval ext=lower(replace(file.name,"^.*\.","."))
| bin _time span=10m
| stats count as writes, dc(file.path) as files by _time, host.name, ext
| eventstats avg(writes) as mu, stdev(writes) as sd by host.name, ext
| where writes > mu + (4*sd) AND writes > 200
| table _time, host.name, ext, writes, files
```

False-positive note: a backup agent, deduplication job or content migration writes far more than this threshold with no new extension. Require the extension to be absent from that host's 14-day inventory before scoring the burst, and check the job scheduler for the same window.

## Class 2 — Recovery-capability sabotage before impact

Expected hit: shadow-copy deletion, backup-agent stop, recovery-service configuration change or VSS writer removal occurring before the first encryption write on the same host. Because this stage precedes impact, it is the strongest pre-impact anchor in the whole timeline.

```spl
(index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688)
  OR (index=edr sourcetype="edr:process")
  earliest=-7d@d latest=@h
| eval sabotageCmd=lower(coalesce(process.command_line,CommandLine))
| where match(sabotageCmd,"vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog")
     OR match(sabotageCmd,"bcdedit.*recoveryenabled\s+no|bcdedit.*bootstatuspolicy")
     OR match(sabotageCmd,"net\s+stop\s+(vss|backup|sql|msexchange)")
| stats min(_time) as first_seen, values(sabotageCmd) as commands by host, user
```

False-positive note: an approved storage migration or a scheduled reclamation task runs the same commands from a documented service account. Confirm the executing principal and the change record; a signed-in human account running these on a server at an unusual hour is the finding.

## Class 3 — Entry-vector branch attestation

Expected hit: one of three shapes inside the days before onset — an edge-appliance management login from an untrusted source, a successful VPN or webmail sign-in from a new ASN followed by a new MFA factor, or a new local account on an appliance. Whichever appears earliest decides whether containment starts with tokens or hosts.

```kql
let lookback = 7d;
let edgeLogins = CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where DeviceAction in ("allow","accept") and DestinationPort in (443,10443,8443)
    | where RequestURL has_any ("/remote/login","/api/v1/auth","/admin","/cgi-bin/")
    | project T=TimeGenerated, Kind="edge-login", Actor=SourceUserName, Src=SourceIP, Detail=RequestURL;
let idpRisk = SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == 0 and RiskLevelDuringSignIn in ("high","medium")
    | project T=TimeGenerated, Kind="idp-signin", Actor=UserPrincipalName, Src=IPAddress, Detail=strcat("risk=",RiskLevelDuringSignIn);
union edgeLogins, idpRisk
| summarize Candidates=count(), Earliest=min(T), Latest=max(T) by Kind, Actor, Src, Detail
| order by Earliest asc
```

False-positive note: travelling staff and corporate egress changes produce high-risk sign-ins from new ASNs every week. Require the follow-on action — a new MFA method, a token grant, a mailbox rule — before treating the sign-in as the entry.

## Class 4 — Pre-onset staging evidence (transfer attestation is owned elsewhere)

Expected hit: archive creation and staging-directory growth inside the days before the first encryption write, which bounds what could have left. The completed-transfer question belongs to [`raas-extortion-and-negotiation-triage`](../raas-extortion-and-negotiation-triage/QUERIES.md); this class only establishes that collection happened here.

```spl
index=edr sourcetype="edr:file" earliest=-48h@h latest=@h
| eval ext=lower(replace(file.name,"^.*\.","."))
| where ext IN (".7z",".rar",".zip",".tar",".gz")
| bucket _time span=6h
| stats count as archives, sum(size) as bytes, dc(file.path) as distinct_paths by _time, host.name
| eval staged_mb=round(bytes/1048576,1)
| where staged_mb > 100
| table _time, host.name, archives, staged_mb, distinct_paths
```

False-positive note: routine log rotation, build caching and database maintenance dump archives on a schedule. Compare against the host's own archive cadence and check whether the archive's source paths are data repositories rather than build outputs. Staging proves collection; only a completion record proves transfer.

## Class 5 — Backup job continuity (sabotage and silent failure)

Expected hit: a backup job that stopped succeeding, ran unusually short, or changed repository inside the days before onset. Restore-point provenance and immutability attestation are owned by [`ransomware-response-recovery-and-restore`](../ransomware-response-recovery-and-restore/QUERIES.md); this class only asks whether the jobs were healthy before the incident.

```spl
index=backup sourcetype="backup:job" earliest=-21d@d latest=@h
| eval ok=if(status IN ("Success","Completed"),1,0)
| bucket _time span=1d
| stats sum(ok) as successes, count as runs, sum(bytes_written) as bytes by _time, job_name
| eventstats avg(successes) as mu, stdev(successes) as sd by job_name
| where successes < mu - (2*sd) OR successes == 0
| table _time, job_name, runs, successes, bytes
```

False-positive note: a job legitimately skipped by a maintenance window, a retention change or a repository migration produces the same dip. Confirm the change record before treating a failed run as sabotage, and note that a job can report success while writing a backup of an already-compromised host.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Record the containment timestamp beside every onset timestamp; an onset without a containment proof cannot be used to state that spread stopped.
- Treat actor claims, note text and leak-site content as unverified input. They may be quoted as claims; they must never be merged into the evidence table as findings.
