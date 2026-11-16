# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-detection-and-ids`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for running a sensor, replaying a capture and reading the resulting records. Never invent flags — check `suricata --build-info` and the app-layer section of your own `suricata.yaml` before trusting a rule's preconditions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `suricata` (config test) | `suricata -T -c /etc/suricata/suricata.yaml -S local.rules` | Load the real config and rule set, surfacing syntax and unmet `requires` before deployment | Linux, macOS |
| `suricata` (replay) | `suricata -r sample.pcap -c /etc/suricata/suricata.yaml -l ./out` | Replay a capture through the same rules to reproduce an alert deterministically | Linux, macOS |
| `suricata` (live, read-only) | `suricata -i eth1 -c /etc/suricata/suricata.yaml -l /var/log/suricata` | Start IDS mode on an interface without any drop action | Linux |
| `eve.json` inspection | `jq -c 'select(.event_type=="alert")' eve.json` for alert identity, `jq -s 'map(select(.event_type=="stats"))' eve.json` for the last interval's `stats.capture` drop counters | Alert identity with flow linkage, and whether the window is complete | Linux, macOS, Windows |
| `snort` | `snort -c /etc/snort/snort.conf -T` then `snort -r sample.pcap -c /etc/snort/snort.conf -A alert_fast -l ./out` | Validate then replay against a Snort rule set | Linux, Windows |
| `zeek` | `zeek -r sample.pcap local` | Produce `conn.log`, `dns.log`, `ssl.log` for flow-side baselining | Linux, macOS |

## Minimal Script Shape

The shape below is the minimum defensible network check: prove the sensor is not dropping, replay a known-good capture to confirm the rule loads and fires, then emit the alert with its revision.

```bash
#!/usr/bin/env bash
# ids-gate.sh — sensor health, then a deterministic rule replay.
set -euo pipefail

PCAP="${PCAP:?path to a known-positive capture}"
RULES="${RULES:-./local.rules}"
YAML="${YAML:-/etc/suricata/suricata.yaml}"
OUT="$(mktemp -d)"
MAX_DROP_PCT="${MAX_DROP_PCT:-0.5}"

# 0. Config and rules must load before anything else is interpreted.
suricata -T -c "$YAML" -S "$RULES"

# 1. Sensor health from the live stats interval, if a log dir is supplied.
if [ -n "${LOG_DIR:-}" ]; then
  drop=$(jq -s 'map(select(.event_type=="stats")) | last | .stats.capture' "$LOG_DIR/eve.json")
  pct=$(printf '%s' "$drop" | jq -r 'if .kernel_packets>0
        then (100*.kernel_drops/.kernel_packets) else 0 end')
  awk -v p="$pct" -v m="$MAX_DROP_PCT" 'BEGIN { exit (p+0 <= m+0) ? 0 : 1 }' \
    || { echo "GAP: kernel drop ${pct}% -> INCONCLUSIVE (Sensor Drop)"; exit 2; }
fi

# 2. Deterministic replay; the alert must carry sid and rev.
suricata -r "$PCAP" -c "$YAML" -S "$RULES" -l "$OUT" >/dev/null 2>&1
jq -c 'select(.event_type=="alert")
       | {sid:.alert.signature_id, rev:.alert.rev, flow:.flow_id}' "$OUT/eve.json"
```

## Notes That Prevent Wrong Runs

- `suricata -T` validates configuration and rules but does not exercise app-layer parsing; a rule matching `http.uri` can pass `-T` and still never fire if HTTP is not enabled for that port.
- Stats counters are cumulative per process lifetime. On a long-running sensor, take two reads and subtract, or a restart will look like a recovery.
- Replaying the same PCAP twice is only deterministic if the ruleset and `rev` are unchanged; record both with any reproduction you publish.
- `snort -A alert_fast` writes a compact text log, not full packet data. Use it to confirm a match, then re-run with `-A full` only if you need the triggering packet.
- Rule authoring, `sid` lint and PCAP regression harnesses are owned by [suricata-lua-and-rule-qa-tooling](../../security-automation-and-tool-development/suricata-lua-and-rule-qa-tooling/SKILL.md); this file covers the detection-reading side only.
