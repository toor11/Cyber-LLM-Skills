# Evidence Queries and Attestation Artifacts

> Sub-skill: [`web-application-incident-response`](SKILL.md) | Family: **Incident Response**

Queries owned by `web-application-incident-response`. Each class answers one question the parent class must settle before it hands work to a leaf: did the tier match what was deployed, did the worker execute something, did it reach the network, did it read data, and did the edge appliance mediate the entry. File-level discovery lives in the webshell leaf and request reconstruction in the access-log leaf; this file covers the cross-cutting planes.

## Class 1 — Deployment baseline versus served tree

Expected hit: a count of untracked and hash-mismatched files under the served root, with the manifest's build time stated. This is the parent-level integrity check; the leaf does the per-file analysis.

```bash
set -Eeuo pipefail
APP_ROOT="${WEBROOT:-/var/www/app}"
MANIFEST="${MANIFEST:?release manifest (path<TAB>sha256)}"

find "$APP_ROOT" -type f -printf '%P\n' | sort > /tmp/present
cut -f1 "$MANIFEST" | sort > /tmp/released
printf 'untracked\t%s\n' "$(comm -23 /tmp/present /tmp/released | wc -l)"

mismatch=0
while IFS=$'\t' read -r rel want; do
  [ -f "$APP_ROOT/$rel" ] || continue
  [ "$(sha256sum "$APP_ROOT/$rel" | cut -d' ' -f1)" = "$want" ] || mismatch=$((mismatch+1))
done < "$MANIFEST"
printf 'modified\t%s\n' "$mismatch"
printf 'manifest_built\t%s\n' "$(stat -c %y "$MANIFEST")"
```

False-positive note: runtime-writable directories — cache, sessions, compiled templates — legitimately accumulate files the manifest never lists. Exclude them here and examine each against its own content expectations in the leaf skill.

## Class 2 — Worker process lineage across the tier

Expected hit: web workers spawning shells, downloaders, archive tools or credential-access utilities, with the request window attached. This is the parent-level execution check that decides whether the incident is capability or compromise.

```kql
DeviceProcessEvents
| where Timestamp between (ago(21d) .. now())
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd","apache2","nginx","php-fpm","php-cgi","tomcat","catalina.sh","node","java","uwsgi","gunicorn")
| extend Bucket = bin(Timestamp, 1h)
| summarize Children = make_set(FileName, 25), Cmds = make_set(substr(ProcessCommandLine, 0, 200), 5)
    by DeviceName, Parent = InitiatingProcessFileName, Account = InitiatingProcessAccountName, Bucket
| where array_length(Children) > 0
| sort Bucket desc
```

False-positive note: health checks, PDF rendering, image conversion and log rotation all spawn children from workers. Rank by whether the child is a shell, downloader or archive tool, and by whether its command line carries encoded or downloaded content.

## Class 3 — Tier egress against its own history

Expected hit: a destination contacted by the web tier that is absent from that tier's prior 14 days, occurring after the earliest placement candidate.

```kql
let probeStart = datetime(2026-11-11T00:00:00Z);
let tier = dynamic(["WEB01","WEB02","WEB03"]);
let priorTierEgress = DeviceNetworkEvents
    | where Timestamp between (probeStart - 14d .. probeStart) and DeviceName in (tier)
    | summarize prior_dests = make_set(RemoteIP, 5000);
DeviceNetworkEvents
| where Timestamp > probeStart and DeviceName in (tier)
| where ActionType == "ConnectionSuccess" and RemoteIP !in (priorTierEgress)
| summarize Hits=count(), First=min(Timestamp), Last=max(Timestamp) by DeviceName, RemoteIP, RemotePort
| sort First asc
```

False-positive note: licensing, telemetry and package repositories are contacted by the tier legitimately and change whenever the application is upgraded. Maintain a sanctioned tier-egress list; the finding is an off-list destination, not a new one.

## Class 4 — Application identity data access

Expected hit: reads by the application identity against a data store or object bucket outside its own baseline — new tables, new prefixes, or a volume far above its norm. This is the data-loss question, which is separate from the execution question.

```kql
let appId = "svc-web-prod";
let identityLookback = 7d;
let sqlReads = AzureDiagnostics
    | where TimeGenerated > ago(identityLookback)
    | where Category == "SQLSecurityAuditEvents" and database_principal_name_s == appId
    | project T=TimeGenerated, Plane="sql", Target=strcat(database_name_s,"/",statement_s), Bytes=0;
let appBlobReads = StorageBlobLogs
    | where TimeGenerated > ago(identityLookback)
    | where tostring(parse_json(Authentication).identity) == appId
    | project T=TimeGenerated, Plane="blob", Target=Uri, Bytes=ResponseBodySize;
union sqlReads, appBlobReads
| summarize Reads=count(), TotalBytes=sum(Bytes), First=min(T), Last=max(T) by Plane, Target
| order by TotalBytes desc
```

False-positive note: the application identity performs the same reads as part of normal operation, at a volume that tracks user traffic. Compare against the same hour on prior days before treating a volume change as data access; a new target with low volume can matter more than a large volume on a known target.

## Class 5 — Edge appliance mediation and state

Expected hit: whether the request reached the origin directly or through the appliance, and whether the appliance's own configuration or sessions changed during the window. An edge entry means the appliance is evidence and must be preserved before any firmware change.

```kql
let edgeWindow = 7d;
CommonSecurityLog
| where TimeGenerated > ago(edgeWindow)
| where DeviceVendor has_any ("F5","Fortinet","Palo Alto","Citrix","Imperva","Cloudflare")
| summarize Events=count(), Actions=make_set(DeviceAction, 10),
            Srcs=dcount(SourceIP), Destinations=dcount(DestinationIP)
    by DeviceProduct, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

False-positive note: an appliance that logs nothing for a day looks identical to an appliance that was bypassed. Check the device's own health and log-forwarding state before drawing a conclusion from an empty result.

## Class 6 — Source integrity for the deployment pipeline itself

Expected hit: whether the build or deploy credential was used outside its normal pattern during the window. If the pipeline was the entry, the tier's file state is a downstream symptom.

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName in ("Update application","Add service principal credentials","Add member to role.")
| where tostring(InitiatedBy.app.displayName) has "ci-"
| project TimeGenerated, OperationName, Actor=tostring(InitiatedBy.app.displayName),
          Target=tostring(TargetResources[0].displayName), Result
| order by TimeGenerated desc
```

False-positive note: pipelines legitimately rotate their own credentials and update applications on every release. The signal is an operation outside the release calendar or from an unexpected source range.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Keep the release manifest under version control with its build timestamp; every class above degrades to a heuristic without it.
- Record which blind spot applied to each conclusion: in-memory code, appended content, unlogged bodies, or an appliance that did not forward.
