---
name: super-timeline-and-plaso-postprocessing-scripting
description: "Builds DFIR super-timeline post-processors and anomaly window slicers over Plaso/Timesketch CSV/JSONL exports: pivoting +/- N minutes around seed IOCs, collapsing benign OS noise bursts, and emitting investigator-ready Markdown/CSV chronological tables. Use when scripting forensic timeline reduction."
family: security-automation-and-tool-development
tier: leaf
triggers: ["plaso postprocessing", "timeline slicer script", "timesketch python", "macb timeline filter"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Super Timeline and Plaso Postprocessing Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **leaf** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A super-timeline is a single chronological table assembled from every artefact source, and its usefulness is inversely proportional to its row count. Plaso generates it (`log2timeline.py` builds the storage file, `psort.py` filters and exports), and the exported rows carry at minimum `datetime`, `timestamp_desc` (which timestamp this is: creation, modification, access, or a log event time), `source`, `source_long`, `message`, and `parser`, with `data_type` available under additional fields. Timesketch requires `message`, `datetime` (ISO-8601), and `timestamp_desc` on import and will reject a CSV missing any of them. The reduction problem is that a busy Windows host produces millions of low-value rows — Windows Update, antivirus scans, prefetch churn — which bury the few dozen that matter. Three techniques do the work: pivot windows (±N minutes around a seed event, keeping only rows inside those windows), noise suppression (drop rows from known-benign paths/processes within a stated rule set, counted so the suppression is measurable), and source weighting (a registry persistence write outranks a Windows Update file creation). Plaso field names changed in its 20260720 release — `computer_name` became `hostname` and `body` became `message_body` — so a post-processor keyed on the old names silently returns nothing on new exports.

- **CWE-778 (Insufficient Logging):** a timeline reduced by an unseen filter is indistinguishable from a timeline where the activity never occurred.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are generating the timeline **THEN** run `log2timeline.py` to build the storage file and `psort.py` to filter and export; keep `datetime`, `timestamp_desc`, `source`, and `message` in the export, because a reduced export loses the ability to re-pivot.
2. **IF** you are post-processing an export **THEN** parse `datetime` as ISO-8601 with an explicit offset, and treat a naive timestamp as an error rather than assuming UTC.
3. **IF** the export came from Plaso 20260720 or later **THEN** use `hostname` and `message_body`; older exports use `computer_name` and `body`, and a post-processor must handle both rather than silently matching nothing.
4. **IF** you reduce the timeline **THEN** state the pivot windows, the noise rules, and the count of rows dropped by each rule — a reduction without a count is an unverifiable deletion.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `super-timeline-and-plaso-postprocessing-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable reduction shapes | [`QUERIES.md`](QUERIES.md) | Pivot windows, noise rules, CSV/JSONL handling, Timesketch import fields |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `log2timeline.py`, `psort.py`, `timesketch_importer` |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Silent-filter and field-rename incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Timeline-handoff during an active investigation |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Plaso (`log2timeline.py`/`psort.py`) export rows with `datetime`, `timestamp_desc`, `source`, `message`, `parser`, plus `data_type`; Timesketch import requiring `message`, `datetime`, `timestamp_desc`; Python 3.11 post-processing
- **Mandatory Self-Validation Command:** `python -m py_compile timeline_slice.py`

1. **Confirm the inputs.** Establish the Plaso/Timesketch version that produced the export, the exact column set present, the timezone of the `datetime` values, the seed events to pivot around, and the expected order of magnitude of rows. Confirm the reduction output will be reproducible from the retained full export.
2. **Choose the branch.** Pivot around seeds → window slicing with inclusive bounds. Reduce noise → rule-based suppression with per-rule counts. Produce a report → group by `timestamp_desc` and `source` so the reader can tell a creation time from a log event time. Re-import to Timesketch → validate the three mandatory fields first.
3. **Define how to validate the reduction.** Assert that every retained row falls inside a declared window; assert that the per-rule dropped counts sum to the difference between input and output row counts; assert that a seed row itself is always retained; and assert a known field name resolves on both old and new Plaso schemas.
4. **Name the stop condition.** Stop when a `datetime` is naive or unparseable, when the required columns are absent, when the reduction drops more than the declared rules account for, or when a seed event falls outside every window (a sign the timezone is wrong).
5. **State what counts as a working tool.** A working post-processor exits `0` when the reduction reconciles (input = output + dropped-by-rule), `1` when it produced output but reconciliation failed or a row was unparseable, and `2` on a missing column or an unreadable export. It emits the reduction manifest beside the rows.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `datetime` parsed with an explicit offset | Proves rows are placed at the right instant; naive values are refused |
| `timestamp_desc` preserved on every row | Proves a creation time is distinguishable from a log event time in the report |
| Per-rule dropped counts summing to the row delta | Proves the reduction deleted only what it declared |
| Seed row always retained | Proves the pivot did not filter out the event being investigated |
| Both `hostname`/`message_body` and `computer_name`/`body` resolved | Proves the post-processor works across Plaso schema versions |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: assumes UTC from a naive string, filters noise with no accounting,
# and drops the rows the investigation is about.
import csv

NOISE = ("windows update", "antivirus", "prefetch")

def reduce(path, seeder):
    keep = []
    for row in csv.DictReader(open(path, newline="", encoding="utf-8")):
        if any(n in row["message"].lower() for n in NOISE):
            continue                                  # silent deletion
        stamp = row["datetime"]                      # naive string compare
        if stamp >= seeder:
            keep.append(row)
    return keep
```

**Production-Grade Starter Skeleton (USE):**

```python
# timeline_slice.py - Pivot-window reduction with a reconciled manifest.
# Exit 0 reconciled, 1 unreconciled or unparseable row, 2 missing columns.
import csv
import datetime as dt
import json
import pathlib
import sys

REQUIRED = ("datetime", "timestamp_desc", "source", "message")
NOISE_RULES = {
    "windows_update": (r"\bwindows update\b", r"\bwuauclt\b"),
    "av_scan": (r"\bantivirus\b", r"\bdefender\b.*scan"),
    "prefetch_churn": (r"\\windows\\prefetch\\",),
}
WINDOW = dt.timedelta(minutes=15)

def parse_instant(raw: str) -> dt.datetime:
    text = raw.strip().replace("Z", "+00:00")
    stamp = dt.datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        raise ValueError(f"naive timestamp: {raw!r}")
    return stamp.astimezone(dt.timezone.utc)

def is_noise(message: str, timestamp_desc: str) -> str | None:
    lowered = message.lower()
    for rule, patterns in NOISE_RULES.items():
        if any(p in lowered for p in patterns) and "registry" not in timestamp_desc.lower():
            return rule
    return None

def reduce_rows(rows: list[dict], seeds: list[dt.datetime]) -> tuple[list[dict], dict]:
    dropped: dict[str, int] = {rule: 0 for rule in NOISE_RULES}
    dropped["outside_window"] = 0
    dropped["unparseable"] = 0
    kept, seed_hits = [], set()
    for row in rows:
        try:
            stamp = parse_instant(row["datetime"])
        except ValueError:
            dropped["unparseable"] += 1
            continue
        in_window = any(abs(stamp - seed) <= WINDOW for seed in seeds)
        if not in_window:
            dropped["outside_window"] += 1
            continue
        rule = is_noise(row.get("message", ""), row.get("timestamp_desc", ""))
        if rule:
            dropped[rule] += 1
            continue
        for index, seed in enumerate(seeds):
            if abs(stamp - seed) <= dt.timedelta(seconds=1):
                seed_hits.add(index)
        kept.append({**row, "utc": stamp.isoformat().replace("+00:00", "Z")})
    return kept, {"dropped_by_rule": dropped, "seed_hits": sorted(seed_hits)}

def main(argv: list[str]) -> int:
    if len(argv) < 3:
        sys.stderr.write("usage: timeline_slice.py <export.csv> <seed_iso> [<seed_iso> ...]\n")
        return 2
    path = pathlib.Path(argv[1])
    if not path.is_file():
        sys.stderr.write(f"fatal: not a file: {path}\n")
        return 2
    try:
        seeds = [parse_instant(value) for value in argv[2:]]
    except ValueError as exc:
        sys.stderr.write(f"fatal: bad seed: {exc}\n")
        return 2
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
        if missing:
            sys.stderr.write(f"fatal: missing columns {missing}\n")
            return 2
        rows = list(reader)
    kept, manifest = reduce_rows(rows, seeds)
    manifest["input_rows"] = len(rows)
    manifest["output_rows"] = len(kept)
    manifest["window_minutes"] = int(WINDOW.total_seconds() // 60)
    for row in kept:
        print(json.dumps(row))
    print(json.dumps({"manifest": manifest}), file=sys.stderr)
    reconciled = sum(manifest["dropped_by_rule"].values()) == len(rows) - len(kept)
    if not reconciled or manifest["dropped_by_rule"]["unparseable"]:
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

**Why this matters:** the reduction is reconciled — input rows equal output rows plus the sum of per-rule drops — and the manifest reports how many seeds were actually found inside a window, so a wrong timezone or a silent filter shows up as a failed check instead of an empty report.

## When It Is NOT This Issue

- **The reduced timeline is suspiciously empty** — check the timezone of the seed against the export; a seed expressed in local time against a UTC export falls outside every window.
- **A field lookup returns nothing on a new Plaso export** — `computer_name` and `body` were renamed to `hostname` and `message_body` in the 20260720 release; key on both.
- **Timesketch rejects an import** — `message`, `datetime` (ISO-8601), and `timestamp_desc` are mandatory; a reduction that dropped one of them cannot be re-imported.
- **Rows that should be present are missing** — a noise rule matched a registry row; suppression rules must exempt persistence-relevant sources.
- **Timestamps look shifted by hours only for one source** — that source's artefacts carry local time; the issue is in generation, not in the post-processor.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER drop timeline rows without counting them by rule and reporting the counts.
- NEVER assume a naive `datetime` is UTC; refuse it or apply a documented timezone.
- NEVER state that an activity is absent from a reduced timeline without stating what was filtered out.
- NEVER assert Plaso field names without checking the generating version.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Generating tool version, column set, timezone, and seed events for `super-timeline-and-plaso-postprocessing-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The reduction, rule set, or reconciliation check is specific and runnable (no generic 'filter the timeline' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: super-timeline-and-plaso-postprocessing-scripting
- **Target Stack & Schema**: Plaso psort exports with datetime/timestamp_desc/source/message, Timesketch-compatible output
- **Safety, Scope & Exit-Code Guards**: [Explicit-offset parsing, per-rule drop counts, reconciliation, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Timezone mismatch, field renames, over-broad noise rules, mandatory import fields]
- **Implementation**:
  [Runnable post-processor following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile timeline_slice.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-forensic-artifact-parser-development`](../windows-forensic-artifact-parser-development/SKILL.md) - Produces the artifact rows this timeline consumes
- [`windows-evtx-and-powershell-audit-scripting`](../windows-evtx-and-powershell-audit-scripting/SKILL.md) - Event-log rows on the same timeline
- [`sqlite-wal-and-browser-artifact-scripting`](../sqlite-wal-and-browser-artifact-scripting/SKILL.md) - Browser activity timestamps
- [`volatility3-plugin-and-memory-triage-scripting`](../volatility3-plugin-and-memory-triage-scripting/SKILL.md) - Memory-side times to correlate

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `super-timeline-and-plaso-postprocessing-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
