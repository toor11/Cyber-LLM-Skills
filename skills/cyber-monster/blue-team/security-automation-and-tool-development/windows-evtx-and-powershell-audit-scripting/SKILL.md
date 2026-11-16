---
name: windows-evtx-and-powershell-audit-scripting
description: "Writes fast Windows Event Log (`.evtx`) parsers in Python (`evtx` / `python-evtx`) and PowerShell (`Get-WinEvent -FilterHashtable`): reassembling fragmented Event ID 4104 ScriptBlocks by `ScriptBlockId`, extracting Sysmon/Security XML `EventData` fields, and emitting normalized JSONL. Use when automating offline EVTX triage or live Windows audit collection."
family: security-automation-and-tool-development
tier: core
triggers: ["python evtx parser", "get-winevent script", "event 4104 reassembly", "evtx to jsonl"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Windows EVTX and Powershell Audit Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

An `.evtx` file is a chunked binary structure: 64 KB blocks of BinXML records, with the renderer inflating each record into the `<Event><System/><EventData/></Event>` document that tools reason about. That inflation is why binary parsing is fast and text scanning is wrong — the strings in the payload are UTF-16 fragments, so grepping an `.evtx` as text finds neither the event ID nor the script. Two parser families exist: the Rust-backed `evtx` package (`PyEvtxParser`, yields `records()` as XML or `records_json()` as a JSON string) and pure-Python `python-evtx` (`Evtx.Evtx`, `record.xml()`), which is portable but markedly slower on large logs. PowerShell 4104 script-block logging fragments long scripts: each record carries `ScriptBlockId`, `MessageNumber`, and `MessageTotal`, and the analyst only has the script once all fragments are joined in `MessageNumber` order. `MessageTotal` is the field that breaks naive implementations — it is absent or zero on some records, and defaulting it to `1` declares the first fragment of a multi-part script "complete". A correct reassembler keeps fragments keyed by `(Computer, ScriptBlockId)`, treats a missing/zero total as unknown rather than as `1`, bounds how many blocks stay open at once, and flushes every residual block at end-of-file with an explicit incompleteness marker.

- **CWE-778 (Insufficient Logging):** an unparsed or partially reassembled 4104 record silently removes the script text that would explain the execution.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are parsing offline `.evtx` at volume **THEN** use the Rust-backed `evtx` package (`PyEvtxParser(...).records()`), guard every `ET.fromstring()` call, and emit JSONL; reach for `python-evtx` only when you need a dependency-free pure-Python drop-in.
2. **IF** you are collecting live data on a Windows host **THEN** use `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}` rather than reading the `.evtx` file, which the service holds open.
3. **IF** the target is Event ID 4104 **THEN** key fragments by `(Computer, ScriptBlockId)`, order by `MessageNumber`, treat `MessageTotal` of `0`/absent as unknown, and flush incomplete blocks at EOF with `complete: false`.
4. **IF** the detection content is the goal rather than the parser **THEN** hand the normalized JSONL to [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md); do not embed detection logic in the parser.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `windows-evtx-and-powershell-audit-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable parser and collector command shapes | [`QUERIES.md`](QUERIES.md) | EVTX-to-JSONL pipeline, `Get-WinEvent` filters, 4104 group-by |
| Need CLI syntax, flags, and package references | [`TOOLS.md`](TOOLS.md) | `evtx` vs `python-evtx`, `Get-WinEvent` parameters |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Fragment-reassembly and truncation incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Chain-of-custody handoff for log evidence |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python `evtx` (`PyEvtxParser` binary `.evtx` streamer; note `python-evtx` `Evtx.Evtx` is a separate slower pure-Python package) + guarded XML parsing + bounded `ScriptBlockId` reassembly with EOF flush
- **Mandatory Self-Validation Command:** `python -m py_compile evtx_4104_reassemble.py`

1. **Confirm the inputs.** Identify the log file or live channel, the event IDs in scope, whether the file is a live (service-held) log or a copy, and the expected record count from `Get-WinEvent -FilterHashtable ... | Measure-Object`. Confirm the parser package actually installed — `evtx` and `python-evtx` expose different classes and are not interchangeable.
2. **Choose the branch.** Offline bulk parse → `PyEvtxParser.records()`. Live collection → `Get-WinEvent` (PowerShell), never a direct file read. Multi-fragment 4104 → reassembly keyed on `(Computer, ScriptBlockId)`. Single-record extraction → direct XML field lookup with no fragment state at all.
3. **Define how to validate the script.** Parse one known log, compare the emitted record count against the independent `Get-WinEvent` count, and assert the 4104 differential: every block either reaches `complete: true` with `fragments == total`, or exits at EOF with `complete: false` and a reason. A parser that reports zero incomplete blocks on a truncated log is wrong, not clean.
4. **Name the stop condition.** Stop when a record's XML fails to parse (skip and count it, never abort the file), when open-fragment count exceeds the cap (evict oldest with reason `evicted`), when `MessageTotal` disagrees with the highest `MessageNumber` seen, or when the emitted count differs from the independent count by more than the corrupt-record count.
5. **State what counts as a working tool.** A working parser exits `0` only when every record was either emitted or explicitly counted as corrupt, the 4104 blocks reconcile against their totals, and the JSONL is valid one-object-per-line; exits `1` on a reconciliation mismatch; exits `2` on a missing file or unreadable parser package.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `PyEvtxParser(path).records()` with `event_record_id` and `timestamp` | Proves records stream in file order without loading the log into memory, and gives the record count for reconciliation |
| `MessageTotal` of `0`/absent treated as unknown (never `1`) | Proves a multi-fragment script is not declared complete after its first fragment |
| `(Computer, ScriptBlockId)` composite key | Proves fragments from different hosts sharing a GUID are not merged into one script |
| `complete: false` + `reason: incomplete-at-eof` on residual blocks | Proves truncation is reported rather than silently dropped |
| `Get-WinEvent -FilterHashtable @{LogName=...; Id=...}` count | Proves an independent record count for reconciliation against the parser |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: totals defaulted to 1, one global dict, no corrupt-record guard, no EOF flush
import xml.etree.ElementTree as ET
from evtx import PyEvtxParser

blocks = {}

def collect(path):
    for rec in PyEvtxParser(path).records():
        root = ET.fromstring(rec["data"])                    # one corrupt chunk aborts the whole scan
        eid = root.findtext(".//EventID")
        if eid != "4104":
            continue
        data = {d.get("Name"): d.text for d in root.iter("Data")}
        total = int(data.get("MessageTotal") or 1)           # absent total becomes "complete after 1"
        blocks.setdefault(data["ScriptBlockId"], {})[int(data["MessageNumber"])] = data["ScriptBlockText"]
        if len(blocks[data["ScriptBlockId"]]) >= total:
            print("".join(blocks[data["ScriptBlockId"]][k] for k in sorted(blocks[data["ScriptBlockId"]])))
```

**Production-Grade Starter Skeleton (USE):**

```python
# evtx_4104_reassemble.py — Bounded binary EVTX 4104 reassembler with corrupt-chunk guard & EOF flush
import json, pathlib, sys
import xml.etree.ElementTree as ET
from evtx import PyEvtxParser

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def _pos_int(val, default: int = 0) -> int:
    try:
        n = int(str(val).strip())
        return n if n > 0 else default
    except (TypeError, ValueError):
        return default

def reassemble_4104(evtx_path: pathlib.Path, max_open: int = 5000):
    blocks, order = {}, []
    def emit(key, reason: str) -> dict:
        b = blocks.pop(key)
        order.remove(key)
        have, want = len(b["frags"]), b["total"]
        return {
            "computer": b["comp"], "script_block_id": b["sbid"] or None,
            "fragments": f"{have}/{want or '?'}", "complete": bool(want) and have >= want,
            "reason": reason, "script": "".join(b["frags"][i] for i in sorted(b["frags"])),
        }
    for rec in PyEvtxParser(str(evtx_path)).records():
        try:
            root = ET.fromstring(rec.get("data") or "")
        except ET.ParseError:
            continue
        if (root.findtext("./e:System/e:EventID", "", NS) or "").strip() != "4104":
            continue
        comp = (root.findtext("./e:System/e:Computer", "", NS) or "").strip()
        data = {d.get("Name"): (d.text or "") for d in root.findall("./e:EventData/e:Data", NS)}
        sbid = (data.get("ScriptBlockId") or "").strip()
        num, tot = _pos_int(data.get("MessageNumber"), 1), _pos_int(data.get("MessageTotal"), 0)
        key = (comp, sbid or f"unkeyed:{rec.get('event_record_id')}")
        blk = blocks.setdefault(key, {"comp": comp, "sbid": sbid, "total": tot, "frags": {}})
        if key not in order:
            order.append(key)
        if tot:
            blk["total"] = max(blk["total"], tot)
        if num in blk["frags"] or (blk["total"] and num > blk["total"]):
            continue
        blk["frags"][num] = data.get("ScriptBlockText", "")
        if blk["total"] and len(blk["frags"]) >= blk["total"]:
            yield emit(key, "complete")
        while len(order) > max_open:
            yield emit(order[0], "evicted")
    for rem in list(order):
        yield emit(rem, "incomplete-at-eof")

if __name__ == "__main__":
    for row in reassemble_4104(pathlib.Path(sys.argv[1])):
        sys.stdout.write(json.dumps(row) + "\n")
```

**Why this matters:** `_pos_int(..., 0)` keeps "unknown total" distinguishable from "total is 1", so a multi-fragment script is never emitted as complete after its first fragment, and every block that never reached its total still exits at EOF with an explicit reason.

## When It Is NOT This Issue

- **4104 records exist for a script but the text is empty** — script-block logging can be configured to log only the first block (`ScriptBlockLogging` options), so the fragments were never written; that is a policy gap, not a parser defect.
- **The record count from the parser is lower than `Get-WinEvent`** — count corrupt records separately; a difference exactly equal to the corrupt count is expected, a larger difference means blocks were skipped by a filter.
- **A long script appears twice with different `ScriptBlockId`** — the same content executed twice legitimately produces two IDs; do not deduplicate by script text.
- **`Get-WinEvent` returns nothing for a channel that has records** — the channel may be disabled or the caller lacks read rights; a filtered parse of the file can still succeed, so treat the empty result as a collection problem.
- **An `.evtx` copy parses fine but a live channel read fails** — the EventLog service holds the active file; copy it or query the channel, never open the live file for reading.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER treat the `evtx` package and `python-evtx` as interchangeable — `PyEvtxParser` and `Evtx.Evtx` are different APIs with different performance profiles.
- NEVER default a missing `MessageTotal` to `1`; `0`/absent means unknown and must stay distinguishable.
- NEVER fabricate a `ScriptBlockId` from `event_record_id` to force grouping — an invented key merges unrelated fragments.
- NEVER leave `ET.fromstring()` unguarded in a bulk scan, and never drop incomplete blocks without an explicit reason field.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Log source (file vs live channel), event IDs in scope, and the installed parser package for `windows-evtx-and-powershell-audit-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The parser, reassembler, or collection command is specific and runnable (no generic 'parse the log' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: windows-evtx-and-powershell-audit-scripting
- **Target Stack & Schema**: Python `evtx` PyEvtxParser (pure-Python `python-evtx` only as a portable fallback) + guarded XML parsing + bounded ScriptBlockId reassembly
- **Safety, Scope & Exit-Code Guards**: [Read-only source handling, corrupt-record counting, fragment cap, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Unknown MessageTotal, truncated logs, duplicate ScriptBlockId content, live channel locks]
- **Implementation**:
  [Runnable parser or reassembler following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile evtx_4104_reassemble.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md) - Consumes this JSONL as rule fixtures and telemetry
- [`windows-forensic-artifact-parser-development`](../windows-forensic-artifact-parser-development/SKILL.md) - Sibling parser work for registry, MFT, and Prefetch artifacts
- [`super-timeline-and-plaso-postprocessing-scripting`](../super-timeline-and-plaso-postprocessing-scripting/SKILL.md) - Merges these events into a super-timeline
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - Scans recovered payloads the scripts reference
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Normalizes this output for search

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `windows-evtx-and-powershell-audit-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
