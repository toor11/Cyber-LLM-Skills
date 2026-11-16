# Evidence Queries and Attestation Artifacts

> Sub-skill: [`supply-chain-incident-response`](SKILL.md) | Family: **Incident Response**

Queries owned by `supply-chain-incident-response`. Each class answers one of three separate questions — what was resolved, was it fetched, and did it execute — plus the two follow-ups: what could the executing identity reach, and did the payload leave persistence behind. Field names are generic; map them to your package proxy, CI platform and EDR schema.

## Class 1 — Resolution: what the repository actually pinned

Expected hit: per repository, the exact version in the lockfile and its resolve timestamp. A manifest range is not a resolution and must never be reported as one.

```bash
set -euo pipefail; umask 077
AFFECTED="${AFFECTED:-keyv@6.0.0 flat-cache@6.1.24 file-entry-cache@11.1.6}"
REPO_ROOT="${REPO_ROOT:-.}"

find "$REPO_ROOT" -maxdepth 4 -type f \
  \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \
     -o -name 'npm-shrinkwrap.json' \) -print |
while IFS= read -r f; do
  for pkg in $AFFECTED; do
    if grep -Fq -- "$pkg" "$f"; then
      printf 'RESOLVED\t%s\t%s\n' "$f" "$pkg"
    fi
  done
done | sort -u
```

False-positive note: lockfiles retain entries for optional and platform-specific dependencies that were never installed on the machine doing the build. A hit here is resolution only; Class 2 decides whether the artifact was fetched.

## Class 2 — Fetch: did the artefact proxy serve it, to whom, and when

Expected hit: a proxy record with package name, resolved version, the requesting identity and a timestamp inside the campaign window. This is the record that converts a repository-level concern into an environment-level one.

```kql
let campaignStart = datetime(2026-08-04T00:00:00Z);
let campaignEnd   = datetime(2026-08-12T00:00:00Z);
PackageProxyLogs
| where TimeGenerated between (campaignStart .. campaignEnd)
| where PackageName in ("keyv","flat-cache","file-entry-cache","cacheable-request")
| where PackageVersion in ("6.0.0","6.1.24","11.1.6","13.0.20")
| summarize Fetches=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
    by PackageName, PackageVersion, RequestingIdentity, ClientIp, Repository
| order by First asc
```

False-positive note: a warm artifact cache can serve a package long after the registry removed it, so a hit after the campaign window can still be a genuine exposure. Conversely a cache may serve a previously fetched clean copy of the same version string only if the version was immutable — which is exactly what this campaign violated. Treat any same-version fetch as requiring hash comparison against the advisory's published hash.

## Class 3 — Execution: did an install-time hook run

Expected hit: a process record where the package manager's lifecycle phase spawned a script host, a shell or a downloader on a runner or workstation. This is the boundary between exposure and compromise.

```spl
index=endpoint sourcetype="edr:process" earliest=-30d@d latest=@h
| eval parent=lower(coalesce(parent_process_name,ParentImage))
| eval child=lower(coalesce(process_name,Image))
| eval hookCmd=lower(coalesce(process.command_line,CommandLine))
| where match(parent,"node|npm|yarn|pnpm|bun")
| where match(child,"node|sh|bash|powershell|cmd|curl|wget|python")
| where match(cmd,"setup\.mjs|math_init|math_symbol|preinstall|postinstall|--ignore-scripts|bun ")
| stats min(_time) as first_seen, count as n, values(hookCmd) as commands
    by host.name, parent, child, user.name
| sort by first_seen, child asc
```

False-positive note: legitimate packages with build steps spawn compilers and script hosts during install every day. The discriminator is the specific script filename or an unexpected downloader under the package manager, not the parent-child shape alone.

## Class 4 — Identity reach: what could the executing identity read

Expected hit: a list of credentials, roles and secret paths readable by the affected runner or workstation identity, with the last successful use of each inside the window. This list is the rotation set, and it is the real work.

```kql
let ids = dynamic(["ci-runner-04", "ci-runner-07", "gha-runner-prod-2"]);
let reachLookback = 30d;
let spSignins = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(reachLookback)
    | where ServicePrincipalName has_any (ids)
    | project T=TimeGenerated, Kind="entra-sp", Who=ServicePrincipalName, Target=ResourceDisplayName, Result=ResultType;
let cloudCalls = AWSCloudTrail
    | where TimeGenerated > ago(reachLookback)
    | where UserIdentityArn has_any (ids)
    | project T=TimeGenerated, Kind="aws", Who=UserIdentityArn, Target=EventName, Result=errorCode;
let userSignins = SigninLogs
    | where TimeGenerated > ago(reachLookback)
    | where UserPrincipalName has_any (ids)
    | project T=TimeGenerated, Kind="entra-user", Who=UserPrincipalName, Target=AppDisplayName, Result=tostring(ResultType);
union spSignins, cloudCalls, userSignins
| summarize Uses=count(), First=min(T), Last=max(T), Failures=countif(Result != "0" and isnotempty(Result))
    by Who, Kind, Target
| order by Uses desc, Last desc
```

False-positive note: shared runner identities sign in to the same resources constantly, so a high use count proves nothing. The signal is a resource accessed for the first time, or access from a location inconsistent with the runner's egress range.

## Class 5 — Persistence left behind by the payload

Expected hit: a modification to an IDE, editor or coding-agent configuration file that introduces a command execution path, with the writing process identified. Removal of the package does not undo this.

```powershell
# Read-only: look for command-execution keys in agent/editor config paths.
$paths = @(
    "$env:USERPROFILE\.claude\settings.json",
    "$env:USERPROFILE\.vscode\tasks.json",
    "$env:USERPROFILE\.cursor\mcp.json"
)
foreach ($p in $paths) {
    if (-not (Test-Path $p)) { continue }
    $item = Get-Item $p
    $persistenceHit = [ordered] @{
        AgentConfigPath = $p
        Modified = $item.LastWriteTimeUtc
        Sha256   = (Get-FileHash $p -Algorithm SHA256).Hash
        HasExec  = [bool](Select-String -Path $p -Pattern 'command|args|shell' -Quiet)
    }
} | ConvertTo-Json -Depth 3
```

False-positive note: developers legitimately configure tasks and MCP servers, and every configuration file contains command keys. The finding is a config write whose timestamp falls inside the install window and whose writing process is the package manager, not a human editor session.

## Class 6 — Detection continuity for long-window hunts

Expected hit: a stated answer to whether the hunt ran against a table that actually existed for the whole window. Where Defender XDR tables stream only to a data lake, a long-window query against the workspace returns nothing at all, which is easily misread as absence of activity.

```kql
// Confirm table existence and coverage before trusting any long-window result.
union withsource=TableName DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents
| summarize First=min(Timestamp), Last=max(Timestamp), Rows=count() by TableName
| extend Coverage = case(Rows == 0, "EMPTY - investigate lake vs workspace routing",
                         First > ago(90d), "PARTIAL - history shorter than hunt window",
                         "OK")
```

False-positive note: a genuinely quiet table and a table routed only to the lake both return zero. Distinguish them by querying the lake endpoint directly and comparing counts, and record which endpoint produced the answer.

## Deployment Gates

- Validate against at least one positive replay and a seven-day benign production baseline before enabling any alert.
- Record the proxy, CI and endpoint coverage windows beside every exposure conclusion; a hunt that cannot reach the campaign window must be reported as inconclusive rather than negative.
- Pin the clean replacement version by hash from a source you read, never by "latest available".
