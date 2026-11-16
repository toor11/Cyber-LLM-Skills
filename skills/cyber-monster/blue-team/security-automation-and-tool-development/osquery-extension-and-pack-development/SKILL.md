---
name: osquery-extension-and-pack-development
description: "Develops osquery query packs and Python/Go `osquery-python` table extensions: differential vs snapshot scheduling, `file_events`/`process_events` FIM configuration, query watchdog memory/CPU budgets, and fleet pack regression testing. Use when building cross-platform endpoint visibility packs or custom osquery tables."
family: security-automation-and-tool-development
tier: core
triggers: ["osquery pack", "osquery extension python", "osquery table plugin", "osquery differential query"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# osquery Extension and Pack Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

osquery exposes the host as a relational database: tables are virtual, queries are SQL, and the scheduler polls them on an interval. That polling model makes the differential-versus-snapshot distinction the single most consequential configuration choice. A normal scheduled query diffs each run against the previous result set and emits only `added` and `removed` rows, which is what makes a low-frequency interval usable for state that changes rarely. A `snapshot: true` query emits the entire result set on every interval instead, which is correct only when you need the full state at a point in time (e.g. a compliance inventory) and is a log-volume hazard otherwise. Native `*_events` tables (`file_events`, `process_events`, `bpf_process_events`) are different again: they stream from an event publisher, so the interval controls flush cadence rather than sample frequency, and they require the publisher to be enabled (`--enable_file_events=true`, `--disable_events=false`) plus a `file_paths` category for FIM. Custom tables come from extensions: a separate process speaking Thrift over a socket, registering a `TablePlugin` with `name()`, `columns()`, and `generate(context)`. The watchdog is the safety mechanism — a query exceeding its memory or CPU budget is denylisted and stopped — and it is also a silent coverage loss if nobody notices the denylist.

- **CWE-778 (Insufficient Logging):** a pack whose query was denylisted by the watchdog, or whose publisher flag is off, produces no rows and no error at the consumer.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the state changes slowly and you need transitions **THEN** use a scheduled differential query (default `snapshot: false`) and let the diff emit `added`/`removed`; do not raise frequency to compensate for a wrong mode.
2. **IF** you need the complete state each interval (inventory, drift baseline) **THEN** set `snapshot: true` and expect full-volume output on every run; size retention accordingly.
3. **IF** you are monitoring file changes **THEN** enable the publisher (`--enable_file_events=true`, `--disable_events=false`), declare a `file_paths` category, and query `file_events`; without the category the table is empty by design.
4. **IF** you need platform data osquery lacks **THEN** write an extension `TablePlugin` with `name()`, `columns()`, and `generate(context)`, register it, and load it with `osqueryi --extension <path>`; keep the plugin's own work bounded because it runs inside the watchdog's budget.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `osquery-extension-and-pack-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable pack and extension shapes | [`QUERIES.md`](QUERIES.md) | Pack JSON, FIM config, extension skeleton |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `osqueryi`/`osqueryd` flags, `osquery-python` API |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Watchdog denylist and empty-`file_events` incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Fleet-visibility handoff when a pack goes dark |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** osquery 5.20.x pack/config JSON (`packs.<name>.queries.<q>` with `query`, `interval`, `snapshot`, `removed`, `platform`, `denylist`) and `osquery-python` `TablePlugin` extensions
- **Mandatory Self-Validation Command:** `osqueryi --json "SELECT * FROM <table> LIMIT 1"; python -m py_compile osquery_ext.py`

1. **Confirm the inputs.** Establish the osquery version on the fleet, which tables the pack depends on, whether the required publishers are enabled, and the log destination's retention. Confirm the table exists on every target platform in scope — a pack query referencing a platform-specific table fails on the others.
2. **Choose the branch.** State transitions → differential. Point-in-time inventory → snapshot. Native event stream → `*_events` table plus publisher flags. Missing data → extension. Each branch has a different volume and failure profile, and mixing them in one pack makes the volume unpredictable.
3. **Define how to validate the pack.** Run each query interactively first (`osqueryi --json "<query>"`) and confirm column names and types; then run the pack against a test config and confirm results appear in the expected log; then confirm the watchdog did not denylist the query (check for denylist entries after the run).
4. **Name the stop condition.** Stop when a query returns zero rows on a host where the table should be populated (usually a disabled publisher), when the watchdog denylists a query, when a snapshot query's row count implies unacceptable log volume, or when a pack query references a table absent on one target platform.
5. **State what counts as a working tool.** A working pack produces the expected result shape on every platform in scope, with each query's mode justified by its change rate, and no watchdog denylist entries after a full interval; a working extension registers its table, returns rows matching the declared column types, and stays inside the watchdog budget.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `"snapshot": false` with `"removed": true` | Proves the query emits transitions rather than full state on every interval |
| `file_paths` category plus `--enable_file_events=true` | Proves FIM has both the path scope and the publisher; either alone yields an empty table |
| `TablePlugin.name()`, `columns()`, `generate(context)` | Proves the extension declares a stable schema and returns rows for it |
| Watchdog denylist entry for a query name | Proves the query exceeded its memory/CPU budget and stopped producing data |
| Per-platform row counts for one pack | Proves the pack is valid on every target OS, not just the test host |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```json
{
  "packs": {
    "fim": {
      "queries": {
        "ssh_keys": {
          "query": "SELECT * FROM file WHERE path LIKE '/home/%/.ssh/%';",
          "interval": 30
        }
      }
    }
  }
}
```

**Production-Grade Starter Skeleton (USE):**

```json
{
  "options": {
    "disable_events": "false",
    "enable_file_events": "true"
  },
  "file_paths": {
    "ssh_authorized_keys": [
      "/home/%/.ssh/authorized_keys",
      "/root/.ssh/authorized_keys"
    ]
  },
  "packs": {
    "endpoint_fim": {
      "platform": "posix",
      "queries": {
        "ssh_authorized_keys_written": {
          "query": "SELECT * FROM file_events WHERE category = 'ssh_authorized_keys';",
          "interval": 300,
          "removed": false,
          "snapshot": false,
          "denylist": true
        },
        "listening_ports_snapshot": {
          "query": "SELECT pid, port, protocol, address, family FROM listening_ports;",
          "interval": 3600,
          "snapshot": true
        }
      }
    }
  }
}
```

**Why this matters:** the FIM query uses the event publisher with a declared category (so `file_events` actually has rows) and emits only transitions, while the port inventory is explicitly a snapshot at a much longer interval — the two modes are chosen per query instead of applied uniformly.

## When It Is NOT This Issue

- **`file_events` returns nothing on a host that clearly has file changes** — the publisher is disabled or the path has no `file_paths` category; the table is empty by design, not broken.
- **A query produced data yesterday and nothing today** — check the watchdog denylist before editing SQL; a denylisted query stops running entirely.
- **A snapshot query produces enormous log volume** — that is the mode working as configured; switch to differential or raise the interval rather than trimming the SELECT list arbitrarily.
- **A pack query fails on Windows but works on Linux** — the referenced table is platform-specific; add `"platform": "posix"` (or the appropriate value) instead of rewriting the query.
- **`process_events` is sparse on Linux** — it depends on the audit/eBPF publisher configuration; enabling it is a host change, not a pack change.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER claim `file_events` works without the publisher flag and a `file_paths` category.
- NEVER present a snapshot query as equivalent to a differential one; they differ in volume and in what the log means.
- NEVER invent an osquery table or column name; verify against the target version's schema with `.schema <table>`.
- NEVER treat a watchdog-denylisted query as "no findings".

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** osquery version, target platforms, publisher flags, and log retention for `osquery-extension-and-pack-development` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The pack, FIM config, or extension is specific and runnable (no generic 'query more tables' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: osquery-extension-and-pack-development
- **Target Stack & Schema**: osquery 5.20.x pack/config JSON plus osquery-python TablePlugin extensions
- **Safety, Scope & Exit-Code Guards**: [Publisher flags, per-query intervals, watchdog awareness, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Empty file_events, denylisted queries, platform-specific tables, snapshot volume]
- **Implementation**:
  [Runnable pack JSON or extension following the Starter Skeleton]
- **Self-Validation Command**: `osqueryi --json "SELECT * FROM <table> LIMIT 1"; python -m py_compile osquery_ext.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`velociraptor-vql-artifact-development`](../velociraptor-vql-artifact-development/SKILL.md) - The other fleet-visibility surface, with explicit resource ceilings
- [`auditd-and-ebpf-telemetry-collector-scripting`](../auditd-and-ebpf-telemetry-collector-scripting/SKILL.md) - Linux event sources that back `process_events`
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Normalizes the result log for search
- [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) - Tracks which packs are actually enrolled

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `osquery-extension-and-pack-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
