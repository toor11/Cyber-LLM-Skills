---
name: ocsf-and-ecs-log-normalizer-development
description: "Engineers streaming security log ETL and schema normalizers (Python, Vector VRL, or Logstash) mapping raw vendor events into OCSF v1.x or Elastic Common Schema (ECS): strict timestamp/timezone UTC normalization, schema validation, dead-letter queues for malformed events, and original-raw preservation. Use when building log ingestion and normalization pipelines."
family: security-automation-and-tool-development
tier: flagship
triggers: ["ocsf normalizer", "ecs log parser", "vector vrl security", "security log etl", "schema normalization"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# OCSF and ECS Log Normalizer Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **flagship** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Normalization maps a vendor's event onto a shared schema so that one detection or dashboard works across sources. OCSF and ECS answer the same question with different machinery. OCSF is class-based: every event carries a required `class_uid` (the event class) and `category_uid` (its category), plus enum siblings such as `activity_id`/`activity_name` and `severity_id`. ECS is field-path based: `@timestamp`, `event.category`/`event.type`/`event.kind` arrays carry the same semantic role that `class_uid` carries in OCSF, and there is no numeric class identifier. A normalizer therefore does three things that must never be conflated: it classifies the event (picks the class or the `event.*` triple), it projects vendor fields onto schema paths, and it preserves the untouched original so a mapping mistake is recoverable. Two failure modes dominate real pipelines. First, a silently wrong timestamp — a naive local time, a seconds-versus-milliseconds epoch mix, or a lost offset — which puts events in the wrong hour and makes every time-window detection lie. Second, a malformed record that aborts the batch, dropping the well-formed events behind it, which is why an explicit dead-letter path is part of the schema contract rather than an operational nicety.

- **CWE-778 (Insufficient Logging):** a record dropped by the parser, or written with a wrong timestamp, is as absent as a record never collected.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the destination is class-based (OCSF consumers, a SIEM with OCSF onboarding) **THEN** emit `class_uid` + `category_uid` + `activity_id` + `severity_id` + `time` and keep the raw event in an unmapped or `unmapped`-style field; validate `class_uid` against the class list for the target OCSF version.
2. **IF** the destination is Elasticsearch/OpenSearch with ECS mappings **THEN** emit `@timestamp` in UTC ISO-8601 plus the `event.category`/`event.type`/`event.kind` triple; there is no OCSF `class_uid` equivalent, so do not invent one.
3. **IF** you are implementing in Vector **THEN** handle the fallible `parse_json` explicitly (`parsed, err = parse_json(.message)`, then `abort`) and set `reroute_dropped = true` so malformed events reach a dead-letter sink instead of vanishing.
4. **IF** the only change is field renaming for one SIEM **THEN** this may belong in a Sigma/pySigma pipeline instead — open [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md) before building ETL.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `ocsf-and-ecs-log-normalizer-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable normalizer shapes and validation commands | [`QUERIES.md`](QUERIES.md) | Python and VRL skeletons, dead-letter wiring, schema assertions |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | Vector commands, schema validators, version pins |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Timestamp and batch-abort incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Pipeline handoff when a feed goes dark |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** OCSF 1.8 class/category identifiers with `class_uid`/`category_uid`/`activity_id`/`severity_id`, or ECS 9.x `@timestamp` + `event.category`/`event.type`/`event.kind`; Vector VRL or Python 3.11 streaming implementation
- **Mandatory Self-Validation Command:** `vector validate --no-environment vector.toml; python -m py_compile normalize_events.py`

1. **Confirm the inputs.** Enumerate the source feeds, the exact schema version the destination enforces (OCSF minor version, ECS major), the timestamp formats actually present in the raw events, and whether the original event can be retained alongside the projection. Confirm the classification rule for each feed before writing field mappings.
2. **Choose the branch.** Class-based destination → OCSF identifiers plus the raw payload. Path-based destination → ECS `@timestamp` and `event.*`. Streaming engine already deployed (Vector) → VRL with explicit fallible-parse handling. Batch Python → per-record try/except with a dead-letter writer, never a whole-file abort.
3. **Define how to validate the script.** Validate the pipeline config (`vector validate`) or the Python module (`py_compile`); then run a fixture set containing at least one well-formed record per feed, one record with a naive timestamp, and one deliberately malformed record, and assert: correct UTC instant, correct class or `event.category`, and exactly one dead-lettered record with the original bytes preserved.
4. **Name the stop condition.** Stop when a record cannot be classified (unknown vendor event), when a timestamp has no timezone and the feed's offset is undocumented, when the dead-letter rate exceeds the agreed threshold, or when the schema validator rejects the output. Never coerce an unclassifiable event into a default class to keep the pipeline green.
5. **State what counts as a working tool.** A working normalizer exits `0` only when every fixture classified, every timestamp resolved to a correct UTC instant, and the malformed fixture landed in the dead-letter path with its raw payload intact; exits `1` on a mapping or differential failure; exits `2` on a missing schema/config. Output is deterministic: re-running over the same input produces byte-identical normalized records.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `class_uid` + `category_uid` present and consistent (e.g. `3004` with category `3`) | Proves the OCSF classifier picked a real class, not a placeholder, and that category matches the class |
| `@timestamp` with explicit `Z`/offset and `event.category`/`event.type`/`event.kind` | Proves the ECS projection carries both the instant and the semantic triple the detections query |
| `parsed, err = parse_json(.message)` + `abort` + `reroute_dropped = true` | Proves a malformed line is routed, not silently discarded, so the loss is measurable |
| Dead-letter record containing the original bytes plus the parse error | Proves the mapping mistake is recoverable without re-collecting from the source |
| `vector validate --no-environment vector.toml` exit status | Proves the VRL program type-checks, which catches unhandled fallible functions before deployment |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: locale-dependent timestamp, no timezone handling, whole-batch abort, raw event dropped
import datetime
import json

def normalize(lines):
    out = []
    for line in lines:
        event = json.loads(line)                                  # one bad line kills the batch
        ts = datetime.datetime.strptime(event["ts"], "%Y-%m-%d %H:%M:%S")   # naive local time
        out.append({
            "time": ts.isoformat(),                               # no UTC, no offset
            "class": "authentication",                            # invented, not a class_uid
            "user": event["user"],
        })
    return out
```

**Production-Grade Starter Skeleton (USE):**

```python
# normalize_events.py - Exit 0 all classified, 1 mapping failure, 2 bad config
import datetime as dt
import json
import pathlib
import sys

OCSF_AUTHENTICATION = 3002      # class_uid: Authentication
OCSF_IAM_CATEGORY = 3           # category_uid: Identity & Access Management

def parse_instant(raw: str) -> dt.datetime:
    """Accept only timestamp shapes with an explicit offset; refuse naive local time."""
    text = raw.strip().replace("Z", "+00:00")
    stamp = dt.datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        raise ValueError(f"timestamp has no timezone: {raw!r}")
    return stamp.astimezone(dt.timezone.utc)

def normalize(record: dict) -> dict:
    instant = parse_instant(record["ts"])
    outcome = str(record.get("result", "")).lower()
    return {
        "class_uid": OCSF_AUTHENTICATION,
        "category_uid": OCSF_IAM_CATEGORY,
        "activity_id": 1 if outcome == "success" else 2,
        "severity_id": 1 if outcome == "success" else 3,
        "time": int(instant.timestamp() * 1000),
        "actor": {"user": {"name": record.get("user", "")}},
        "src_endpoint": {"ip": record.get("src_ip", "")},
        "unmapped": {"original": record},
    }

def run(src: pathlib.Path, dead_letter: pathlib.Path) -> int:
    failures = 0
    with src.open(encoding="utf-8") as fh, dead_letter.open("a", encoding="utf-8") as dl:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                print(json.dumps(normalize(json.loads(line))), flush=True)
            except (ValueError, KeyError, json.JSONDecodeError) as exc:
                failures += 1
                dl.write(json.dumps({"line": n, "error": str(exc), "raw": line}) + "\n")
    return 1 if failures else 0

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.stderr.write("usage: normalize_events.py <raw.jsonl> <dead_letter.jsonl>\n")
        raise SystemExit(2)
    raise SystemExit(run(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])))
```

**Why this matters:** a naive timestamp raises instead of silently landing in the wrong hour, and a malformed record is preserved verbatim in the dead-letter file while the rest of the batch still normalizes.

## When It Is NOT This Issue

- **Events land in the wrong hour only for one feed** — check that feed's documented offset before touching the parser; a source emitting local time without an offset cannot be fixed by guessing.
- **`class_uid` present but the SIEM shows the event under the wrong category** — the category must match the class (OCSF derives `category_uid` from the class); an inconsistent pair passes schema presence checks and fails semantic queries.
- **A normalizer "losing" events with no dead-letter entries** — the collector's own buffer, not the normalizer, is usually the loss point; compare source-side counts before and after the collector.
- **ECS pipelines complaining about `class_uid`** — ECS has no such field; carrying OCSF identifiers into an ECS mapping requires them to live in a custom/unmapped location, not on a schema path.
- **A malformed-JSON rate spike after a vendor change** — that is an upstream format change; alert on the dead-letter growth rate rather than relaxing the parser.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER invent an OCSF `class_uid` for a vendor event; use a documented class or leave the event unclassified in the dead-letter path.
- NEVER claim ECS has an equivalent of `class_uid`/`category_uid` — the mapping is semantic, onto `event.category`/`event.type`/`event.kind`.
- NEVER write a normalizer that discards the original raw event; the projection is the derived artifact, not the record of truth.
- NEVER use `parse_json!` in a VRL pipeline carrying mixed vendor logs — the abort takes the event with it unless `reroute_dropped` is configured.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Feed list, destination schema version, and real timestamp formats for `ocsf-and-ecs-log-normalizer-development` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The normalizer, VRL program, or schema assertion is specific and runnable (no generic 'map the fields' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: ocsf-and-ecs-log-normalizer-development
- **Target Stack & Schema**: OCSF 1.8 class/category identifiers or ECS 9.x event triple, implemented in Python or Vector VRL
- **Safety, Scope & Exit-Code Guards**: [Feed scope, UTC-only timestamps, dead-letter path, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Naive timestamps, unclassifiable events, malformed JSON, raw preservation]
- **Implementation**:
  [Runnable normalizer following the Starter Skeleton]
- **Self-Validation Command**: `vector validate --no-environment vector.toml; python -m py_compile normalize_events.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md) - Owns field-name portability above this schema layer
- [`syslog-and-cloudtrail-stream-parsers`](../syslog-and-cloudtrail-stream-parsers/SKILL.md) - Produces the raw cloud and syslog records this normalizer consumes
- [`zeek-script-and-notice-development`](../zeek-script-and-notice-development/SKILL.md) - Native network log producer
- [`suricata-lua-and-rule-qa-tooling`](../suricata-lua-and-rule-qa-tooling/SKILL.md) - `eve.json` producer for the same pipeline
- [`siem-query-transpiler-and-enrichment-scripting`](../siem-query-transpiler-and-enrichment-scripting/SKILL.md) - Queries the normalized index

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ocsf-and-ecs-log-normalizer-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
