# Evidence Queries and Attestation Artifacts

> Sub-skill: [`web-application-incident-response-webshell-discovery`](SKILL.md) | Family: **Incident Response**

Queries owned by `web-application-incident-response-webshell-discovery`. Each class answers a distinct question that discovery must close before a shell can be called found, executed or contained: what the deployment did not write, whether the path was requested, whether the worker spawned a child, what the response shape says, and whether the shell reached the network. Map field names to your web server, EDR and proxy schema.

## Class 1 — File population versus the release manifest

Expected hit: a short list of untracked or hash-mismatched files under the served root, ranked so executable extensions in writable directories come first. This is the differential that makes the rest of the investigation finite.

```bash
set -euo pipefail; shopt -s globstar
WEBROOT="${WEBROOT:-/var/www/app}"
MANIFEST="${MANIFEST:?path to release manifest (path<TAB>sha256)}"

# Untracked files, restricted to extensions the runtime can execute.
find "$WEBROOT" -type f -printf '%P\n' | sort > /tmp/present.txt
cut -f1 "$MANIFEST" | sort > /tmp/released.txt
comm -23 /tmp/present.txt /tmp/released.txt |
  grep -E '\.(php|phtml|phar|jsp|jspx|aspx|ashx|asmx|cfm|cgi|pl|py|rb)$' |
  sed "s|^|$WEBROOT/|" |
  xargs -r ls -l --time-style=+%Y-%m-%dT%H:%M:%SZ
```

False-positive note: runtime-writable directories legitimately accumulate files — compiled templates, session stores, thumbnail caches. Exclude those from the untracked set and inspect each with its own content-type expectation, rather than assuming everything there is hostile.

## Class 2 — Whether the path was requested, and by whom

Expected hit: requests to the exact candidate path, with first and last timestamps per client, status and response size. Repeated small 200s to one client is the signature of interactive use; a single 404 is a scanner.

```spl
index=web sourcetype="access_combined" earliest=-14d@d latest=@h
| eval path=lower(uri_path)
| where match(path,"/(uploads|files|images|cache|tmp|vendor|assets)/.*\.(php|phtml|jsp|aspx|ashx|cgi)$")
| stats count as hits, min(_time) as first_seen, max(_time) as last_seen,
        avg(bytes) as avg_bytes, values(status) as statuses,
        values(http_user_agent) as agents by clientip, path
| where hits > 1 OR statuses == "200"
| table clientip, path, hits, first_seen, last_seen, avg_bytes, statuses, agents
```

False-positive note: legitimate applications do serve PHP from upload directories in some frameworks, and monitoring probes hit these paths routinely. Verify the user agent and source against the monitoring inventory before treating the pattern as interactive shell use.

## Class 3 — Whether the worker spawned a child process

Expected hit: a web worker process — `apache2`, `httpd`, `nginx`, `php-fpm`, `w3wp.exe`, `tomcat`, `node` — spawning a shell, downloader, archive tool or scripting host inside the request window. This is the execution proof.

```kql
DeviceProcessEvents
| where Timestamp between (ago(14d) .. now())
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd","apache2","nginx","php-fpm","php-cgi","tomcat","node","java")
| where FileName in~ ("cmd.exe","powershell.exe","sh","bash","dash","curl","wget","certutil.exe","bitsadmin.exe","whoami.exe","net.exe","nc","socat","python","perl")
| project Timestamp, DeviceName, Parent=InitiatingProcessFileName, Child=FileName,
          Cmd=ProcessCommandLine, Account=InitiatingProcessAccountName
| sort Timestamp asc
```

False-positive note: legitimate applications spawn `whoami`, `curl` and even `sh` for health checks, PDF rendering, image conversion and cron-like work. Require the child's command line to include attacker-shaped content — a base64 blob, a download URL, a shell flag — or the child to occur inside a request to a file that Class 1 flagged.

## Class 4 — Response shape and command channel

Expected hit: responses whose size or timing pattern matches command execution — very small consistent responses to repeated requests from one client, or a response size that tracks the request parameter length.

```spl
index=web sourcetype="access_combined" earliest=-7d@d latest=@h
| eval shell_path=uri_path
| where match(shell_path,"\.(php|phtml|aspx|ashx|jsp)$")
| eval minute_key=strftime(_time, "%Y-%m-%dT%H:%M")
| stats count as reqs, avg(bytes) as avg_bytes, stdev(bytes) as sd_bytes,
        dc(http_user_agent) as agents by minute_key, clientip, shell_path
| where reqs >= 3 AND avg_bytes < 4096 AND (isnull(sd_bytes) OR sd_bytes < 256)
| table minute_key, clientip, shell_path, reqs, avg_bytes, sd_bytes, agents
```

False-positive note: AJAX polling endpoints, progress bars and beacon endpoints produce exactly this shape. Confirm the path is not a known application endpoint, and cross-reference with Class 1 before acting.

## Class 5 — Egress from the web tier after the request

Expected hit: an outbound connection from the web host to a destination absent from its 14-day history, occurring after the first request to a candidate path. That is the shell fetching a second stage or returning output to an external collector.

```kql
let firstReq = datetime(2026-11-12T08:00:00Z);
let tierProcs = dynamic(["w3wp.exe","httpd","apache2","nginx","php-fpm","php-cgi","node","java"]);
let priorEgress = DeviceNetworkEvents
    | where Timestamp between (firstReq - 14d .. firstReq)
    | where InitiatingProcessFileName in~ (tierProcs)
    | summarize seen_dests = make_set(RemoteIP, 5000);
DeviceNetworkEvents
| where Timestamp between (firstReq .. firstReq + 48h)
| where ActionType == "ConnectionSuccess" and InitiatingProcessFileName in~ (tierProcs)
| where RemoteIP !in (priorEgress)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| sort Timestamp asc
```

False-positive note: package updates, licensing checks, telemetry endpoints and CDN callbacks legitimately originate from the web tier and are frequently new after an application upgrade. Maintain a sanctioned egress list for the tier and subtract it before scoring.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Store the release manifest and its timestamp as configuration; every class above degrades to a keyword scan without it.
- State the three blind spots in every report: in-memory shells are invisible to file telemetry, appended code is invisible to file-creation monitoring, and request bodies are invisible to access logs that do not log them.
