# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`data-loss-prevention-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Read-only entry points for the three evidence families. None of these commands changes a DLP policy or blocks a destination; verify flags against the installed version, since the Microsoft 365 CLI and `tcpdump` filter syntax both change between releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tcpdump` | `tcpdump -ni eth0 -s 0 -w egress.pcap 'tcp port 443 and host 203.0.113.10'` | Capture egress for one destination to size a transfer when proxy logs were sampled | Linux, macOS |
| `tshark` | `tshark -r egress.pcap -q -z conv,tcp` | Summarise bytes per conversation from the capture, independent of proxy logging | Cross-platform |
| `zeek` | `zeek -r egress.pcap local` then read `conn.log` fields `orig_bytes`, `resp_bytes`, `id.resp_h` | Protocol-aware byte accounting with a session record you can join to endpoint events | Linux, macOS |
| Microsoft 365 audit search | `Search-UnifiedAuditLog -RecordType Dlp -StartDate 2026-11-07 -EndDate 2026-11-14 -ResultSize 5000` | Pull DLP verdict events for the tenant, including the policy that matched | Windows PowerShell with Exchange Online module |
| Microsoft 365 audit search | `Search-UnifiedAuditLog -RecordType SharePointFileOperation -Operations FileDownloaded -StartDate 2026-11-13` | Read the file-level download record that pairs with a verdict | Windows PowerShell |
| `purview` PowerShell | `Get-DlpCompliancePolicy` and `Get-DlpComplianceRule` | Enumerate which channels and sensitive information types each rule actually covers | Windows PowerShell with Purview module |
| `curl` against a DLP or CASB API | `curl -sS -H "Authorization: Bearer $TOKEN" "https://api.example-casb.test/v1/events?since=2026-11-13T00:00:00Z"` | Export verdicts from a vendor API when no SIEM feed exists | Cross-platform |
| `jq` | `jq -r` over the vendor JSON with an array-to-`@tsv` filter, producing `user`, `policy`, `data_class`, `bytes` columns | Normalise vendor JSON into a tabular fixture for replay | Cross-platform |

## Minimal Script Shape

The script sizes an egress transfer from packet data when the proxy log is sampled, and refuses to attribute content it never saw a verdict for.

```bash
#!/usr/bin/env bash
# egress-size.sh — independent byte accounting for one destination and window.
set -euo pipefail

PCAP="${PCAP:?set PCAP to an existing capture file}"
DEST="${DEST:?set DEST to the destination IP}"
OUT="${OUT:-/tmp/egress-summary.tsv}"

# 1. Conversation-level byte counts straight from the capture, no proxy sampling.
tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null \
  | awk -v d="$DEST" 'NR>1 && $1 ~ d {print $1"\t"$3"\t"$7"\t"$11}' \
  | sort -k4,4nr > "$OUT"

# 2. Refuse to report a content conclusion from byte data alone.
python3 - "$OUT" <<'PY'
import csv, sys
rows = list(csv.reader(open(sys.argv[1]), delimiter="\t"))
if not rows:
    sys.exit("INCONCLUSIVE (No Capture Rows): destination absent from capture")
total = sum(int(r[3]) for r in rows if r[3].isdigit())
print(f"sessions={len(rows)} bytes_to_dest={total}")
print("NOTE: this is size evidence only. A content finding requires a DLP verdict")
print("      joined on the transfer identifier; do not report one from this output.")
PY
```

## Notes That Prevent Wrong Runs

- Conversation bytes include TLS record overhead and retransmissions, so capture-derived totals run a few percent above proxy `bytes_out`; never mix the two sources inside one comparison.
- `Search-UnifiedAuditLog` returns a capped page and requires paging on `ResultIndex`; a single call is not a complete record set and must not be treated as one.
- Purview rule enumeration shows which sensitive information types a rule covers, not which files matched; the verdict store is the only place a match is recorded.
- A capture taken after the fact cannot recover a transfer that already completed; if no capture exists for the window, say the size is unavailable rather than deriving it from proxy totals that were sampled.
- Record the policy version and rule identifiers beside every verdict count; a classifier update changes counts without any change in user behaviour.
