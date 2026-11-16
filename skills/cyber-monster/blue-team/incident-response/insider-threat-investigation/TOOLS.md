# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`insider-threat-investigation`](SKILL.md) | Family: **Incident Response**

Verified read-only entry points for an insider investigation. Everything here queries existing telemetry; none of it deploys new collection on a subject's device, which is deliberate, because new tooling on a subject's machine is observable and can tip the person into destroying evidence. Confirm flags with `<cmd> --help` before use, and confirm with counsel that the platform's use is permitted under the applicable monitoring notice.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Microsoft Purview / eDiscovery | `New-ComplianceSearch -Name "case-1114" -ExchangeLocation j.doe@contoso.com -ContentMatchQuery "<terms>"` then `Get-ComplianceSearch` | Bounded, auditable mailbox and site search with a retained result set | Cloud only |
| Purview audit log | `Search-UnifiedAuditLog -UserIds j.doe@contoso.com -StartDate <iso> -EndDate <iso> -RecordType SharePointFileOperation -ResultSize 5000` | File-access and download records with operation and object identity | Cloud only |
| Microsoft Graph (read) | `Get-MgUserDriveRootChildren` and `Get-MgAuditLogSignIn` with a bounded filter | Drive inventory and sign-in records for baseline construction | Any host with Graph access |
| `Get-WinEvent` | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=<iso>} -MaxEvents 2000` | Object-access auditing from a preserved export, on a copy rather than the subject's live host | Windows |
| Splunk / SIEM export | `index=proxy user=j.doe earliest=<iso> latest=<iso>` then aggregate with a `stats sum(bytes_out) by dest_host` clause | Destination and volume baseline from existing proxy telemetry | SIEM search head |
| `dc3dd` / `ewfacquire` | `ewfacquire -t /evidence/subject-laptop -C "case-1114" -d sha256 /dev/sdb` | Evidentiary acquisition of the subject's device, only with a write blocker and an authorisation record | Linux, Windows |
| `sha256sum` | `sha256sum -c /evidence/case-1114/SHA256SUMS` | Re-verify preserved artefacts at each access | Linux, macOS |

## Minimal Script Shape

The shape below builds a subject baseline report from telemetry that already exists, and refuses to emit a deviation score when the observation period is too short. It collects nothing new and writes only a report.

```bash
#!/usr/bin/env bash
# subject-baseline.sh - read-only. Refuses to score a thin baseline.
set -euo pipefail

SUBJECT="${SUBJECT:?subject principal}"
OUT="${OUT_DIR:?output directory}"
SIEM="${SIEM_URL:?search endpoint}"

mkdir -p "$OUT"
prior="$OUT/${SUBJECT//[@.]/_}-prior.tsv"
probe="$OUT/${SUBJECT//[@.]/_}-probe.tsv"

# 1. Prior-period weekly aggregates from existing telemetry only.
curl -sS --fail -G "${SIEM}/search" \
  --data-urlencode "q=index=file_audit principal=${SUBJECT} earliest=-180d latest=-28d | bucket _time span=1w | stats count AS events dc(object_id) AS breadth by _time" \
  --data-urlencode "output_mode=csv" > "$prior"

weeks=$(($(wc -l < "$prior") - 1))
echo "observed weeks: ${weeks}"
if [ "$weeks" -lt 8 ]; then
  echo "REFUSE: fewer than 8 baseline weeks; a deviation score here would be unsupported" >&2
  echo "record the observation count and the gap instead of a ratio" >&2
  exit 2
fi

# 2. Probe period, same aggregation.
curl -sS --fail -G "${SIEM}/search" \
  --data-urlencode "q=index=file_audit principal=${SUBJECT} earliest=-7d | stats count AS events dc(object_id) AS breadth" \
  --data-urlencode "output_mode=csv" > "$probe"

# 3. Report both, with the source and window named, and no conclusion drawn.
cat > "$OUT/${SUBJECT//[@.]/_}-report.json" <<JSON
{
  "subject": "${SUBJECT}",
  "source": "file_audit index (existing telemetry, no new collection)",
  "prior_window": "180d..28d before report date",
  "probe_window": "last 7d",
  "observed_weeks": ${weeks},
  "coverage_exclusions": ["personal cloud sync not logged", "print via direct IP not logged"],
  "prior_file": "$(basename "$prior")",
  "probe_file": "$(basename "$probe")",
  "conclusion": "none - deviation scoring is a separate, reviewed step"
}
JSON

echo "report: $OUT/${SUBJECT//[@.]/_}-report.json"
```

## Notes That Prevent Wrong Runs

- `Search-UnifiedAuditLog` returns up to 5,000 records per page and honours `-ResultSize` as a cap. A full page means more records exist; page with `-SessionId`/`-SessionCommand ReturnLargeSet` and record the total retrieved.
- Compliance search results are retained, but the underlying mailbox retention is not automatically suspended by creating a search. A legal hold is a separate action and must be recorded separately.
- `Get-WinEvent` against the subject's live host is itself observable in the security log and may be visible to the subject. Export the log or use a preserved copy.
- Proxy and DLP logs systematically miss print-to-IP, clipboard and screenshot channels. State the channel coverage beside every finding, or the report implies more completeness than the sources support.
- `ewfacquire` requires a write blocker and an authorisation record; an acquisition performed without either creates a finding that cannot be used and cannot be repeated.
- A shared or generic account cannot be attributed to a person. If the principal is shared, the investigation's first finding is that attribution is unavailable, not that the subject did something.
