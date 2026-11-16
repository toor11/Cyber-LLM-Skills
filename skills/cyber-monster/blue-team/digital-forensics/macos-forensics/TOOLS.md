# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`macos-forensics`](SKILL.md) | Family: **Digital Forensics**

Collection and parsing entry points for macOS evidence. Never invent undocumented flags — confirm with `log help show` or `<tool> --help` on the installed build, because `log show` options and the parsers' archive handling change between macOS releases. Nothing here disables SIP, alters a configuration profile, or executes a suspect binary.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `log` (Apple) | `log show --start <t> --end <t> --style json --predicate '<expr>'` | Query the unified log by field and time window | macOS |
| `log collect` (Apple) | `log collect --start <t> --output <file.logarchive>` | Archive a log window before it rolls | macOS |
| `sysdiagnose` | `sudo sysdiagnose -f <dir>` | One-shot diagnostic bundle including logs and system state | macOS |
| `mac_apt` | `mac_apt -s <source> -o <out> -t MOUNTED` | Parse unified logs, FSEvents, knowledgeC and plists from an image or mount | Cross-platform |
| `APOLLO` | `python3 apollo.py <module> --input <db>` | Extract TCC, knowledgeC and quarantine records with correct epochs | Cross-platform |
| `tmutil` | `tmutil listlocalsnapshots /` | Enumerate APFS local snapshots that may hold earlier state | macOS |

## Minimal Script Shape

The shape below fixes the two mistakes that most often ruin a macOS log review — querying message text instead of predicate fields, and treating a rolled store as a clean one — and it records the anchor for every FSEvents-derived time.

```bash
#!/usr/bin/env bash
# macos-log-gate.sh — coverage first, then predicate-based export; no host mutation.
set -euo pipefail

CASE="${1:?usage: macos-log-gate.sh <case-dir>}"; START="${2:?}"; END="${3:?}"
mkdir -p "$CASE"

# 1. Coverage: how far back does this store reach?
oldest=$(log show --last 30d --style syslog 2>/dev/null | head -1 || true)
printf 'oldest_visible=%s\n' "${oldest:-UNKNOWN (store may be shorter than 30d)}" | tee "$CASE/coverage.txt"

# 2. Snapshot inventory: an APFS snapshot can hold pre-incident state.
tmutil listlocalsnapshots / 2>/dev/null | tee -a "$CASE/coverage.txt" || true

# 3. Export the window by predicate, JSON, timestamps preserved.
log show --start "$START" --end "$END" --style json \
  --predicate 'process == "launchd" OR process == "runningboardd" OR process == "tccd"' \
  > "$CASE/window.json" 2>/dev/null || echo "GAP: predicate returned nothing"

jq -r '.[] | [.timestamp, .processImagePath, .subsystem, .eventMessage] | @tsv' \
  "$CASE/window.json" 2>/dev/null | head -20 || true

# 4. On-disk artifacts that outlive the log, read from copies.
for db in "$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" \
          "$HOME/Library/Application Support/com.apple.TCC/TCC.db"; do
  [ -f "$db" ] || continue
  cp "$db" "$CASE/$(basename "$db").copy" 2>/dev/null || echo "GAP: cannot copy $db"
  sha256sum "$CASE/$(basename "$db").copy"
done
echo "coverage.txt records what this host actually retains; cite it in the report"
```

## Notes That Prevent Wrong Runs

- `--predicate` fields are the reliable filter; grepping `eventMessage` finds only what was logged as public text, and many security-relevant fields are marked private by default.
- `--style json` preserves the raw timestamp and subsystem fields. `--style syslog` renders a human format that is easy to mis-copy.
- `log collect` before anything else on a live host: the unified log's retention is policy-driven and a long-running collection can outlive the records you wanted.
- `LSQuarantineTimeStamp` is Mac absolute time (seconds since 2001-01-01 UTC, offset `978307200`), while the quarantine xattr's second field is hex Unix epoch. Converting both with the same constant is a classic error.
- FSEvents records carry an event ID and flags, not a wall clock. Anchor them to an external time and say which anchor you used.
- macOS protects several of these paths with SIP and TCC; reading them may require Full Disk Access on the analysis host. Record when a read failed for permission reasons rather than concluding the artifact was absent.
