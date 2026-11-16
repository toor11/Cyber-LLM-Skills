# Artifacts and Queries

> Sub-skill: [`macos-forensics`](SKILL.md) | Family: **Digital Forensics**

Artifact-location and extraction commands owned by `macos-forensics`, grouped by artifact family. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Queries run against a copy or a read-only mount; nothing here disables SIP, modifies a profile, or boots a suspect Mac into a modified environment.

## Class 1 — Coverage and integrity gate

Expected hit: a statement of what this host retains and where the artifacts live. Without it, an empty result cannot be distinguished from an artifact that was never collected.

```bash
ls -la /private/var/db/diagnostics/*.tracev3 2>/dev/null | head -5
ls -la /.fseventsd/ 2>/dev/null | head -5
ls -la /System/Volumes/Data/.fseventsd/ 2>/dev/null | head -5
ls -la ~/Library/Application\ Support/com.apple.TCC/TCC.db \
       /Library/Application\ Support/com.apple.TCC/TCC.db 2>/dev/null
tmutil listlocalsnapshots / 2>/dev/null | head -10
```

False-positive note: on APFS the data volume lives under `/System/Volumes/Data`, so `.fseventsd` may appear in either location depending on how the volume was mounted. Checking one path and concluding "no FSEvents" is a scope error.

## Class 2 — Unified log by predicate

Expected hit: entries in the incident window from the subsystems that matter, filtered on fields rather than message text, with timestamps preserved for correlation.

```bash
log show --start "$START" --end "$END" --style json \
  --predicate 'process == "launchd" OR process == "runningboardd"' \
  > /cases/41/launch.json
jq -r '.[] | [.timestamp, .processImagePath, .subsystem, .eventMessage] | @tsv' \
  /cases/41/launch.json | head -30

# Retention check: how far back does this store actually reach?
log show --last 7d --style syslog --predicate 'process == "logd"' 2>/dev/null | head -3
```

False-positive note: `log show` on a live host reads only what the store still holds. A silent subsystem usually means the subsystem was never configured or its records have already rolled, not that nothing happened.

## Class 3 — Quarantine pairing (xattr plus database)

Expected hit: an xattr whose UUID has a matching row, with both timestamps converted — the xattr's hex field is Unix epoch, the database column is Mac absolute time.

```bash
xattr -p com.apple.quarantine /Users/bob/Downloads/invoice.app 2>/dev/null
sqlite3 "file:$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2?immutable=1" \
  "SELECT datetime(LSQuarantineTimeStamp + 978307200,'unixepoch') AS utc,
          LSQuarantineAgentName, LSQuarantineOriginURLString, LSQuarantineDataURLString
   FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 25;"
```

False-positive note: a file fetched with `curl`, `git` or `scp` never receives a quarantine xattr, and Gatekeeper approval rewrites the flag without removing it. A missing xattr is only interesting when another artifact shows the file arrived through a browser or Mail.

## Class 4 — FSEvents order without a clock

Expected hit: path changes with event IDs, anchored to a time from another source. The event ID provides order; it does not provide time.

```bash
# Parse the gzip batches; keep the batch file's own mtime as the anchor.
python3 - <<'PY_FSEVENTS'
import glob, gzip, os, struct, datetime
for p in sorted(glob.glob("/Volumes/case/.fseventsd/*")):
    if not p.split("/")[-1][:1].isdigit():
        continue
    raw = gzip.open(p, "rb").read() if p.endswith(".gz") else open(p, "rb").read()
    i = 0
    while i + 12 <= len(raw):
        eid, flags = struct.unpack_from("<QI", raw, i)
        i += 12
        end = raw.find(b"\x00", i)
        path = raw[i:end].decode("utf-8", "replace")
        i = end + 1
        print(eid, hex(flags), path, "| batch_mtime=", datetime.datetime.utcfromtimestamp(os.path.getmtime(p)))
PY_FSEVENTS
```

False-positive note: FSEvents batches are flushed in groups and coalesce rapid changes, so several events share one batch time. Reporting a per-event clock from the batch mtime overstates precision by however long the batch accumulated.

## Class 5 — TCC grants and their consent trail

Expected hit: grants whose `last_modified` has a matching consent prompt in the unified log, and grants that do not.

```bash
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
          "/Library/Application Support/com.apple.TCC/TCC.db"; do
  [ -f "$db" ] || continue
  echo "== $db"
  sqlite3 "file:$db?immutable=1" \
    "SELECT datetime(last_modified,'unixepoch') AS utc, service, client, auth_value
     FROM access ORDER BY last_modified DESC LIMIT 20;" 2>/dev/null
done
```

```bash
log show --start "$START" --end "$END" --style syslog \
  --predicate 'eventMessage CONTAINS "Update Access Record"' 2>/dev/null | head -40
```

False-positive note: MDM-deployed PPPC profiles create grants with no user prompt by design, and a grant inherited from a template looks identical to one written by a tool. Check the installed configuration profiles before calling an unprompted grant suspicious.

## Class 6 — Launch persistence and installer ownership

Expected hit: launch items that a package receipt owns. An item with no receipt, or one whose `ProgramArguments` points into a temp or user-writable path, is the candidate.

```bash
ls -la /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents 2>/dev/null
for f in /Library/LaunchDaemons/*.plist ~/Library/LaunchAgents/*.plist; do
  [ -f "$f" ] || continue
  echo "== $f"; plutil -p "$f" | grep -E 'Label|Program|RunAtLoad|StartInterval' | head -6
done
pkgutil --file-info /Library/LaunchDaemons/com.example.agent.plist 2>/dev/null
```

False-positive note: `pkgutil --file-info` reports the receipt that wrote the file, not that the file is unmodified. Compare the file's hash against the receipt's payload listing, or the detection becomes "an installer once touched this path".

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, for every macOS finding, which of unified log, FSEvents, knowledgeC/Biome, TCC and quarantine supplied the evidence, and what each one's retention was.
