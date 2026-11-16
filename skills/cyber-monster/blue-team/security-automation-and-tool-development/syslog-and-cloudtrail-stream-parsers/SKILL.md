---
name: syslog-and-cloudtrail-stream-parsers
description: "Builds memory-bounded streaming parsers for AWS CloudTrail, Azure Activity/SignIn, GCP Audit Logs, and RFC 5424/CEF syslog: handling gzipped S3/Blob batches, flattening `userIdentity`/`requestParameters` safely, and flagging control-plane anomalies (`StopLogging`, `AssumeRole`, policy edits). Use when writing cloud audit log processors."
family: security-automation-and-tool-development
tier: core
triggers: ["cloudtrail parser python", "cef syslog parser", "gcp audit log script", "azure signin parser"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Syslog and CloudTrail Stream Parsers - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Cloud audit feeds and syslog feeds share a shape but not a contract. CloudTrail delivers JSON documents whose payload sits under `Records[]` (an S3 batch can hold many files, each a document with its own array), with `eventSource`, `eventName`, `userIdentity`, `requestParameters`, `sourceIPAddress`, and — critically — `eventTime` in ISO-8601 UTC. Azure and GCP deliver their own envelopes with different nesting and different time fields. RFC 5424 syslog is a header-priority-version-timestamp-hostname-app-procid-msgid framing with a structured-data block, while CEF embeds pipe-delimited extension fields inside a syslog message, so a naive split on `|` breaks as soon as a field contains an escaped pipe. The engineering consequence is that a "cloud log parser" must be explicit about three things per feed: the envelope path to the record array, the timestamp field and its format, and which nested fields are attacker-influenced. That last point drives safety: `userIdentity` and `requestParameters` are attacker-supplied JSON of unbounded shape, so they must be flattened into a bounded, typed projection rather than copied wholesale, and any parser that recurses without depth or size limits lets a crafted log line control memory. The second half of the design is the detection surface: control-plane events that disable or weaken logging (`StopLogging`, `DeleteTrail`, `UpdateTrail`, policy edits, `AssumeRole` chains) are the ones that must be parsed correctly even when the rest of the pipeline degrades.

- **CWE-778 (Insufficient Logging):** the attacker's first control-plane action is usually the one that stops the log this parser depends on, so a parser that cannot distinguish "no events" from "logging disabled" misses the attack.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are parsing CloudTrail **THEN** open the `.json` or `.json.gz` file, read `Records[]`, and pull `eventTime`, `eventSource`, `eventName`, `userIdentity.arn`, `sourceIPAddress`, `awsRegion`, `errorCode`; never assume one file equals one event.
2. **IF** the feed is RFC 5424 syslog **THEN** parse header fields positionally only up to the structured-data block, and treat the message body as opaque bytes beyond that; a body containing spaces or brackets defeats a naive split.
3. **IF** the feed is CEF **THEN** split the header on unescaped pipes only, then parse the extension as `key=value` pairs honoring backslash escapes; a plain `split("|")` corrupts any field containing an escaped delimiter.
4. **IF** you flatten `userIdentity` or `requestParameters` **THEN** project a fixed whitelist of fields into typed columns and keep the untouched original as a raw string, with a size cap.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `syslog-and-cloudtrail-stream-parsers` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable parser and detection shapes | [`QUERIES.md`](QUERIES.md) | CloudTrail/CEF/RFC 5424 handling, control-plane watch list |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `gzip`, `json`, `ausearch`-style tooling, `jq` equivalents |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Logging-disabled and CEF-splitting incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Cloud-audit handoff during an active incident |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11 streaming parsers: `gzip.open` + `json` for CloudTrail `.json`/`.json.gz`, positional header parsing for RFC 5424, escape-aware CEF extension parsing, with a fixed projection for attacker-controlled nested objects
- **Mandatory Self-Validation Command:** `python -m py_compile cloud_audit_parse.py`

1. **Confirm the inputs.** Establish the feed(s) in scope, the envelope path to the record array, the exact timestamp field and format, whether files arrive gzipped and in batches, and which control-plane event names the detector must never miss. Confirm the destination schema so the projection is decided before parsing.
2. **Choose the branch.** CloudTrail batch → `Records[]` iteration per file with a per-file record count. Syslog → positional header then opaque body. CEF → escape-aware header split plus `key=value` extension. Mixed feed → one parser per format, dispatched on a detected prefix, never one regex that tries to handle both.
3. **Define how to validate the parser.** Assert per-file record counts against an independent count (e.g. `jq '.Records | length'`), assert that every record's timestamp converts to a plausible UTC instant, assert that a crafted line with an escaped pipe or a deeply nested `requestParameters` does not raise or balloon memory, and assert that a fixture containing `StopLogging` produces exactly one control-plane finding.
4. **Name the stop condition.** Stop when a record has no timestamp or an unparseable one, when a file yields zero records (a gzip or envelope error, not an empty batch), when nesting depth or field size exceeds the cap, or when a control-plane event name is unknown to the watch list.
5. **State what counts as a working tool.** A working parser exits `0` when every file's record count reconciles and all timestamps are plausible, `1` when a control-plane finding is present (if used as a detector) or a record was rejected and counted, and `2` on an unreadable or corrupt batch. Rejected records are counted and reported, never silently skipped.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Records[]` per file with a reconciled count | Proves no batch was dropped between download and parse |
| `eventTime` converted to UTC with an explicit offset | Proves the event is placed at the right instant, not the collector's local time |
| `eventName` in a control-plane watch list (`StopLogging`, `DeleteTrail`, `UpdateTrail`) | Proves the parser surfaces the events that disable visibility |
| Fixed projection of `userIdentity`/`requestParameters` plus raw copy | Proves attacker-shaped JSON cannot dictate the output schema or memory use |
| Escape-aware CEF header split | Proves an escaped pipe inside a field does not shift every subsequent field |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: one file assumed to be one event, naive pipe split, whole nested
# objects copied into the output, and no timestamp validation.
import json

def parse(path):
    doc = json.load(open(path))
    event = doc["Records"][0]                       # silently drops the rest of the batch
    return {
        "time": event["eventTime"],                 # no format validation
        "user": event["userIdentity"],              # unbounded attacker-controlled shape
        "params": event["requestParameters"],
    }

def parse_cef(line):
    parts = line.split("|")                          # breaks on any escaped pipe
    return {"name": parts[5], "severity": parts[6], "ext": parts[7]}
```

**Production-Grade Starter Skeleton (USE):**

```python
# cloud_audit_parse.py - Exit 0 reconciled, 1 control-plane finding or rejected record, 2 unreadable batch
import datetime as dt
import gzip
import json
import pathlib
import sys

CONTROL_PLANE = {
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "DeleteDetector", "DisableSecurityHub", "DeleteFlowLogs",
}
MAX_NESTED_BYTES = 32_000
IDENTITY_FIELDS = ("type", "arn", "accountId", "userName", "invokedBy")

def open_any(path: pathlib.Path):
    return gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz" else path.open(encoding="utf-8")

def parse_instant(raw: str) -> dt.datetime:
    stamp = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError(f"naive timestamp: {raw!r}")
    return stamp.astimezone(dt.timezone.utc)

def project_identity(identity) -> dict:
    if not isinstance(identity, dict):
        return {}
    return {k: identity.get(k) for k in IDENTITY_FIELDS if k in identity}

def parse_batch(path: pathlib.Path) -> tuple[list[dict], int]:
    with open_any(path) as fh:
        doc = json.load(fh)
    records = doc.get("Records")
    if not isinstance(records, list):
        raise ValueError(f"{path.name}: no Records[] array")
    out, rejected = [], 0
    for record in records:
        try:
            params = json.dumps(record.get("requestParameters") or {})
            if len(params) > MAX_NESTED_BYTES:
                params = params[:MAX_NESTED_BYTES]
            out.append({
                "event_time": parse_instant(record["eventTime"]).isoformat().replace("+00:00", "Z"),
                "event_source": record.get("eventSource", ""),
                "event_name": record.get("eventName", ""),
                "aws_region": record.get("awsRegion", ""),
                "source_ip": record.get("sourceIPAddress", ""),
                "error_code": record.get("errorCode", ""),
                "identity": project_identity(record.get("userIdentity")),
                "request_parameters_raw": params,
            })
        except (KeyError, ValueError, TypeError):
            rejected += 1
    return out, rejected

def parse_cef_header(line: str) -> list[str]:
    fields, current, escaped = [], [], False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "|":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields

def main(paths: list[str]) -> int:
    total, rejected, findings = 0, 0, 0
    for raw in paths:
        path = pathlib.Path(raw)
        try:
            events, bad = parse_batch(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"fatal: {path.name}: {exc}\n")
            return 2
        total += len(events)
        rejected += bad
        for event in events:
            if event["event_name"] in CONTROL_PLANE:
                findings += 1
                print(json.dumps({**event, "finding": "control_plane_visibility_change"}))
    sys.stderr.write(f"records={total} rejected={rejected} findings={findings}\n")
    if total == 0:
        sys.stderr.write("warning: zero records - check gzip/envelope, not emptiness\n")
        return 2
    return 1 if (findings or rejected) else 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("usage: cloud_audit_parse.py <file.json[.gz] | file.cef> [...]\n")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1:]))
```

**Why this matters:** every record in the batch is emitted (not just the first), the timestamp must carry an offset, attacker-controlled objects are projected to a fixed whitelist with a size cap, and rejected records are counted so a parsing failure cannot look like a quiet account.

## When It Is NOT This Issue

- **A CloudTrail file parses to zero records** — the object is gzipped or the envelope differs; treat zero records as a read error before concluding the account had no activity.
- **Only the first event of each file appears downstream** — the parser read `Records[0]`; a single S3 object routinely carries many events, and this is the most common silent data-loss bug in cloud parsing.
- **CEF fields are shifted by one** — a header field contained an escaped pipe and a plain split shifted everything after it; the fix is escape-aware tokenization, not remapping column names.
- **`sourceIPAddress` is a service name rather than an IP** — AWS includes service principals for some events; treating it as an IP yields null geo data but is not a parser defect.
- **Sign-in or audit events seem missing but the trail is healthy** — check the data-event vs management-event selector configuration on the trail; the parser can only see what was delivered.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER assume one file equals one event for CloudTrail, Azure, or GCP exports.
- NEVER copy `userIdentity` or `requestParameters` wholesale into the output schema; project a whitelist and cap size.
- NEVER parse CEF with an unescaped `split("|")` and present the shifted result as field-accurate.
- NEVER use a record's local wall-clock string as the event time; require an offset or apply the feed's documented timezone.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Feed formats, envelope paths, timestamp fields, and control-plane watch list for `syslog-and-cloudtrail-stream-parsers` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The parser or watch list is specific and runnable (no generic 'ingest the logs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: syslog-and-cloudtrail-stream-parsers
- **Target Stack & Schema**: Python 3.11 streaming parsers for CloudTrail Records[], RFC 5424, and CEF with fixed projections
- **Safety, Scope & Exit-Code Guards**: [Record-count reconciliation, size/depth caps, rejected-record counting, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Gzipped batches, escaped CEF pipes, service-principal source IPs, missing data-event selectors]
- **Implementation**:
  [Runnable parser following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile cloud_audit_parse.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Normalizes this output into a shared schema
- [`siem-query-transpiler-and-enrichment-scripting`](../siem-query-transpiler-and-enrichment-scripting/SKILL.md) - Queries the indexed result and enriches principals
- [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) - Tracks whether each cloud log source is actually onboarded
- [`soar-playbook-and-webhook-connector-development`](../soar-playbook-and-webhook-connector-development/SKILL.md) - Consumes control-plane findings as response triggers

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `syslog-and-cloudtrail-stream-parsers` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
