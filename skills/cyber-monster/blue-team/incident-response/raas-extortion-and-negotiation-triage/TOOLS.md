# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`raas-extortion-and-negotiation-triage`](SKILL.md) | Family: **Incident Response**

Verified read-only inspection for the exfiltration and obligation questions. Every command reads audit state; none interacts with actor infrastructure, none contacts an external party, none alters retention. Confirm flags with `<tool> --help` — cloud CLIs change option names between major versions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `aws s3api` | `aws s3api list-objects-v2 --bucket <b> --prefix <p> --query "Contents[].{K:Key,S:Size,L:LastModified}"` | Enumerate what exists in a bucket at a point in time | Cross-platform |
| `aws cloudtrail lookup-events` | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject --start-time <iso> --end-time <iso>` | Data-plane reads by principal inside the window | Cross-platform |
| `tshark` | `tshark -r capture.pcap -q -z conv,tcp` | Per-conversation byte counts from a preserved capture, as a corroborating plane | Cross-platform |
| `zeek` | `zeek -r capture.pcap` then `zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes < conn.log` | Flow-level byte accounting without payload inspection | Linux / macOS |
| `Get-DlpCompliancePolicy` | `Get-DlpCompliancePolicy`, `Get-DlpComplianceRule` | Whether DLP was actually evaluating the channels involved | Windows (M365) |
| `logcli` / SIEM export | `logcli query '{app="proxy"}' --since=96h --output=jsonl` | Export proxy records for offline completion-status analysis | Cross-platform |

## Minimal Script Shape

The shape below answers the exfiltration question with a verdict per destination and refuses to convert an absent plane into a negative finding. It is read-only and never contacts an external host.

```bash
#!/usr/bin/env bash
# egress-attest.sh — completion-status analysis with an explicit plane-availability gate.
set -euo pipefail

CASE="${CASE:?set CASE to a case directory}"
ONSET="${ONSET:?set ONSET to the encryption onset in UTC}"
SANCTIONED="${SANCTIONED:-sanctioned-destinations.txt}"   # one host per line
LOOKBACK_H="${LOOKBACK_H:-96}"

mkdir -p "$CASE"

# Gate 1: does the proxy plane even exist for this window? Absence is a finding.
if ! logcli query '{app="proxy"}' --since="${LOOKBACK_H}h" --limit=1 --output=jsonl 2>/dev/null | grep -q .; then
  echo "GAP: no proxy records in window -> exfiltration question is INCONCLUSIVE, not negative" | tee "$CASE/plane-status.txt"
  exit 3
fi

# Gate 2: export and subtract sanctioned destinations; keep completion status on every row.
logcli query '{app="proxy"}' --since="${LOOKBACK_H}h" --output=jsonl > "$CASE/proxy.jsonl"
python3 - "$CASE/proxy.jsonl" "$SANCTIONED" "$CASE/egress-verdict.csv" <<'PY'
import json, sys, csv, collections
src, san_file, out = sys.argv[1], sys.argv[2], sys.argv[3]
sanctioned = {l.strip().lower() for l in open(san_file) if l.strip()}
agg = collections.defaultdict(lambda: {"attempts":0,"completed":0,"bytes":0,"first":None,"last":None})
for line in open(src):
    try: r = json.loads(line)
    except Exception: continue
    dest = (r.get("dest_host") or r.get("dest_ip") or "").lower()
    if not dest or dest in sanctioned: continue
    k = (r.get("src_ip",""), dest, r.get("url","")[:120])
    a = agg[k]
    a["attempts"] += 1
    if str(r.get("action","")).lower() in ("allow","accept"): a["completed"] += 1
    a["bytes"] += int(r.get("sent_bytes") or 0)
with open(out,"w",newline="") as f:
    w = csv.writer(f); w.writerow(["src","dest","url","attempts","completed","bytes","verdict"])
    for (s,d,u),a in sorted(agg.items(), key=lambda x:-x[1]["bytes"]):
        v = ("completed - assess content" if a["completed"] and a["bytes"]>10_000_000
             else "completed small - assess plausibility" if a["completed"]
             else "attempt only - not exfiltration")
        w.writerow([s,d,u,a["attempts"],a["completed"],a["bytes"],v])
print(f"wrote {out}")
PY
```

## Notes That Prevent Wrong Runs

- `s3api list-objects-v2` and `cloudtrail lookup-events` read audit state. Anything that copies an object out of the bucket changes the evidence and the access log; inspect, do not retrieve, until scope is agreed with counsel.
- A `GetObject` event proves a read was authorised and executed. It does not prove the object was sensitive, complete, or that the same principal took it elsewhere — pair it with the classification join.
- `tshark -z conv,tcp` counts bytes per conversation from a preserved capture. Capture truncation (`-s`) silently understates large transfers; check the snaplen before quoting any number.
- Zeek `conn.log` records both directions; `orig_bytes` for the estate host is the outbound figure, `resp_bytes` is inbound. Reversing them in a report inverts the finding.
- Never resolve "no completion record" into "no exfiltration". The only defensible outputs are `transfer completed`, `attempt only`, or `plane absent - inconclusive`.
