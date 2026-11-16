---
name: sqlite-wal-and-browser-artifact-scripting
description: "Writes forensic SQLite3, Write-Ahead Log (`-wal`), and rollback-journal (`-journal`) artifact extractors in Python for Chromium/Firefox history, cookies, and downloads: hashing originals in chunks, copying DB + `-wal`/`-journal` to an isolated snapshot so evidence hashes never mutate while replaying un-checkpointed WAL visits, closing handles via `contextlib.closing`, and converting integer WebKit/Unix epochs accurately. Use when scripting browser or SQLite DB forensics."
family: security-automation-and-tool-development
tier: core
triggers: ["forensic sqlite python", "history-wal sqlite", "webkit timestamp python", "browser history parser", "sqlite wal snapshot"]
cwe: [CWE-345, CWE-200]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Sqlite WAL and Browser Artifact Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A live SQLite database is three files, not one: the main database, the Write-Ahead Log (`-wal`), and the rollback journal (`-journal`). In WAL mode, committed transactions live in the `-wal` file until a checkpoint folds them into the main database, so the newest evidence — the visit that happened five seconds ago — exists only in the log. Opening the original file directly is therefore doubly wrong: a write-mode connection may checkpoint and rewrite the evidence, and an `immutable=1` URI is worse because SQLite then ignores the `-wal` entirely and returns a stale view while presenting itself as authoritative. The forensically sound sequence is to hash every sidecar while the file is still untouched, copy the database plus its `-wal`/`-journal` into an isolated directory, query the copy, and re-hash the originals to prove nothing moved. Two secondary traps follow from the browser schemas: WebKit/Chromium stores visit times as microseconds since 1601-01-01 UTC in a signed integer (so integer arithmetic on the epoch, never float division), and `visits` holds one row per navigation, so "recent URLs" requires a `GROUP BY u.url` rather than a raw scan of repeat visits.

- **CWE-345 (Insufficient Verification of Data Authenticity):** a parser that does not hash the input before and after cannot prove the artifact it reports on is the artifact it received.
- **CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor):** browser history and cookies expose user activity; extraction must stay scoped and the raw values must not be logged beyond need.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are extracting from a browser or app database that may be live **THEN** hash DB + `-wal` + `-journal`, copy all present sidecars into a temp directory, and query only the copy with `contextlib.closing(sqlite3.connect(...))`; never query the original and never use `immutable=1` while sidecars exist.
2. **IF** the timestamps are WebKit/Chromium microseconds **THEN** convert with integer arithmetic against a `1601-01-01T00:00:00Z` epoch (`WEBKIT_EPOCH + timedelta(microseconds=value)`), not `value / 1e6 - 11644473600`.
3. **IF** the request asks for "recent URLs" or "sites visited" **THEN** aggregate with `GROUP BY u.url` and take the last visit per URL, so the answer is distinct sites rather than repeat navigations.
4. **IF** the artifact is a non-browser SQLite app (chat, notes, mobile app) **THEN** apply the same copy-then-open discipline and read that app's schema; the WAL handling transfers, the Chromium table names do not.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `sqlite-wal-and-browser-artifact-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable extraction and hash-verification shapes | [`QUERIES.md`](QUERIES.md) | Snapshot-and-query skeleton, WAL replay check, timestamp conversions |
| Need CLI syntax, flags, and SDK references | [`TOOLS.md`](TOOLS.md) | `sqlite3` URI options, hash tooling, version pins |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Evidence-mutation and missing-visit incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Chain-of-custody handoff for database evidence |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11+ Copy-Then-Open Forensic SQLite Snapshot (`pathlib.Path.as_uri()`, streaming 1MB SHA-256 on DB + `-wal`/`-journal` -> temp copy -> explicit `contextlib.closing` -> `GROUP BY u.url` -> integer WebKit UTC math)
- **Mandatory Self-Validation Command:** `python -m py_compile parse_browser_db.py`

1. **Confirm the inputs.** Enumerate the database file and every sidecar actually present (`-wal`, `-journal`, `-shm`), record each file's size and SHA-256 before touching anything, and identify the schema family (Chromium `urls`/`visits`, Firefox `moz_places`/`moz_historyvisits`, or an application schema). Confirm whether the source volume is mounted read-only.
2. **Choose the branch.** Live-profile artifact → copy DB plus sidecars to a temp directory and query the copy. Already-acquired single-file database with no sidecars → still copy, then open read-only with `mode=ro`. Journal present but no `-wal` → copy the journal too and open read-write on the copy so SQLite can roll it back, because a rollback journal is applied on open, not appended.
3. **Define how to validate the script.** Re-hash the originals after the query and assert equality with the pre-query manifest; assert the query returned at least one row per table it claims to read; assert each converted timestamp maps to a plausible instant (not 1601-01-01 and not a year past the acquisition date); and assert distinct-URL queries return distinct URLs.
4. **Name the stop condition.** Stop when any original file's hash changed, when the copy lacks a sidecar the original had, when a timestamp converts to the WebKit epoch or to a future date, or when a Windows `PermissionError` on temp cleanup indicates an unclosed handle.
5. **State what counts as a working tool.** A working extractor exits `0` only when both hash manifests match, every claimed table produced rows, and every timestamp is plausible; exits `1` on hash drift or an implausible timestamp; exits `2` on a missing database or an unreadable snapshot directory.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Pre- and post-query SHA-256 manifest over DB + `-wal` + `-journal` | Proves the evidence files were never mutated by the extraction |
| `contextlib.closing(sqlite3.connect(uri, uri=True))` on the temp copy | Proves the handle is closed deterministically, so Windows temp cleanup and the evidence lock both behave |
| `GROUP BY u.url` with `MAX(v.visit_time)` | Proves "distinct recent sites" rather than repeat navigations of one URL |
| Integer WebKit epoch math from 1601-01-01 UTC | Proves no microsecond drift from float division and no off-by-century error |
| Presence of `History-wal` in the temp directory | Proves un-checkpointed commits were replayed instead of silently omitted |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: queries the live evidence in place, ignores the -wal sidecar, leaks the handle, and
# returns one row per navigation instead of one row per site.
import sqlite3

def recent(history_path):
    conn = sqlite3.connect(f"file:{history_path}?immutable=1", uri=True)   # skips un-checkpointed WAL frames
    rows = conn.execute("SELECT visit_time, url FROM visits ORDER BY visit_time DESC LIMIT 50").fetchall()
    return [(t / 1e6 - 11644473600, u) for t, u in rows]                  # float drift, wrong epoch for WebKit
```

**Production-Grade Starter Skeleton (USE):**

```python
# parse_browser_db.py — Preserves History + sidecar SHA-256, replays WAL/journal on temp copy, closes handle cleanly
import contextlib, datetime as dt, hashlib, pathlib, shutil, sqlite3, tempfile

WEBKIT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)

def stream_sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def webkit_us_to_iso(us_val: int | None) -> str | None:
    if not us_val or int(us_val) <= 0:
        return None
    return (WEBKIT_EPOCH + dt.timedelta(microseconds=int(us_val))).isoformat().replace("+00:00", "Z")

def extract_recent_urls(history_db: pathlib.Path, limit: int = 50) -> list[dict]:
    wal = history_db.with_name(history_db.name + "-wal")
    journal = history_db.with_name(history_db.name + "-journal")
    evidence = [p for p in (history_db, wal, journal) if p.is_file()]
    before = {p.name: stream_sha256(p) for p in evidence}
    work = pathlib.Path(tempfile.mkdtemp(prefix="forensic_sqlite_"))
    try:
        for src in evidence:
            shutil.copy2(src, work / src.name)
        snap = work / history_db.name
        mode = "mode=rw" if journal.is_file() else "mode=ro"
        with contextlib.closing(sqlite3.connect(f"{snap.as_uri()}?{mode}", uri=True, timeout=10.0)) as conn:
            rows = conn.execute(
                "SELECT MAX(v.visit_time) AS last_us, u.url, COALESCE(u.title, '') "
                "FROM visits v JOIN urls u ON u.id = v.url WHERE v.visit_time > 0 AND u.url <> '' "
                "GROUP BY u.url ORDER BY last_us DESC, u.url ASC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    after = {p.name: stream_sha256(p) for p in evidence}
    if before != after:
        raise RuntimeError(f"Forensic hash drift detected: {before} != {after}")
    return [{"visit_utc": webkit_us_to_iso(vt), "url": u, "title": t} for vt, u, t in rows]
```

**Why this matters:** both manifests are computed over the untouched originals and compared after the query, so hash drift is a hard failure rather than a footnote; the temp copy is what replays the `-wal`, and `GROUP BY u.url` collapses repeat visits into one row per site.

## When It Is NOT This Issue

- **A recent visit is missing from the report** — check whether `-wal` was copied; a database opened from a single file without its sidecar legitimately lacks un-checkpointed visits.
- **The report shows 50 rows for one site** — that is a query-shape defect (`visits` is per navigation), not missing evidence; `GROUP BY u.url` fixes it.
- **Timestamps land in 1601** — a zero or negative `visit_time` reached the converter; those rows are real records with no timestamp, so filter them rather than converting them.
- **`PermissionError [WinError 32]` on cleanup** — the connection was left open; Python's `sqlite3` context manager commits but does not close, so `contextlib.closing` (or explicit `close()`) is required.
- **The browser was closed and the sidecar is absent** — a clean shutdown checkpoints the WAL, so the visits are already in the main database; absence of `-wal` is not evidence of tampering.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER open original evidence directly with `sqlite3.connect(evidence)` (mutates DB via WAL checkpoint!), and NEVER use `immutable=1` when `-wal` or hot `-journal` sidecars exist (`immutable=1` skips un-checkpointed `-wal` visits AND can surface uncommitted rows from a hot `-journal`!). Always hash originals, copy DB + `-wal`/`-journal` to a temp dir, and query the copy!
- NEVER use `with sqlite3.connect(...) as conn:` alone to close a handle — Python's `sqlite3` context manager commits/rolls back without closing, causing `PermissionError [WinError 32]` on Windows temp cleanup! Always wrap with `contextlib.closing(sqlite3.connect(...))` or `try/finally: conn.close()`.
- NEVER convert WebKit microseconds with float division (`us / 1e6 - 11644473600` drifts microseconds) or query raw `visits` without `GROUP BY u.url` when distinct recent URLs are requested.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Database path, every sidecar present (`-wal`, `-journal`, `-shm`), and the schema family for `sqlite-wal-and-browser-artifact-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The copy-then-open extractor or hash gate is specific and runnable (no generic 'preserve evidence' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: sqlite-wal-and-browser-artifact-scripting
- **Target Stack & Schema**: Python 3.11+ Copy-Then-Open Forensic SQLite Snapshot (`pathlib.Path.as_uri()`, streaming 1MB SHA-256 on DB + `-wal`/`-journal` -> temp copy -> explicit `contextlib.closing` -> `GROUP BY u.url` -> integer WebKit UTC math)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile parse_browser_db.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-forensic-artifact-parser-development`](../windows-forensic-artifact-parser-development/SKILL.md) - Same evidence-integrity discipline for registry, MFT, and Prefetch artifacts
- [`super-timeline-and-plaso-postprocessing-scripting`](../super-timeline-and-plaso-postprocessing-scripting/SKILL.md) - Merges browser visit timestamps into a super-timeline
- [`windows-evtx-and-powershell-audit-scripting`](../windows-evtx-and-powershell-audit-scripting/SKILL.md) - Host-side execution evidence that correlates with browser activity
- [`pcap-and-netflow-beacon-analysis-scripting`](../pcap-and-netflow-beacon-analysis-scripting/SKILL.md) - Network-side proof for the URLs recovered here
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - Scans browser-downloaded payloads by hash

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sqlite-wal-and-browser-artifact-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345, CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
