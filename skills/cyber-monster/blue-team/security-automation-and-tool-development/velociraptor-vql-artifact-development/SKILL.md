---
name: velociraptor-vql-artifact-development
description: "Authors custom Velociraptor VQL client and server artifacts (YAML): `glob`, `parse_pe`, `yara`, `read_reg_key`, and `parse_evtx` plugins, CPU/IOPS client throttling, parameter validation, and offline collector pack compilation. Use when writing fleet-wide DFIR hunting or triage artifacts."
family: security-automation-and-tool-development
tier: core
triggers: ["velociraptor vql", "write velociraptor artifact", "vql query", "velociraptor yaml"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Velociraptor VQL Artifact Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A Velociraptor artifact is a YAML envelope around one or more VQL queries: `name`, `description`, typed `parameters`, one or more `sources` each with a `query`, and an optional `resources` block. VQL is a lazy, row-oriented query language — `SELECT ... FROM plugin(...)` streams rows and the engine evaluates each plugin lazily, which is why `LET` bindings that name subqueries compose cheaply while eager materialization into a large in-memory list does not. The plugin set is the real capability surface: `glob` enumerates paths, `parse_evtx`/`parse_mft`/`parse_prefetch` decode artifacts, `parse_pe` and `yara` inspect binaries, `read_reg_key` reads registry values, and `parse_csv`/`parse_jsonl` handle exported text. Two constraints separate a hunt artifact from a fleet-wide outage. Resource limits — `ops_per_second`, `cpu_limit`, `iops_limit`, `timeout`, `max_rows`, `max_upload_bytes` — bound what one artifact can do to one endpoint, and an artifact that parses every `.evtx` on a busy server without them will starve the host it is investigating. Parameter validation is the second: an unvalidated glob or regex parameter becomes a path that reads outside the intended scope, or a regex that backtracks for minutes per file. `velociraptor artifacts verify` performs static analysis and sets a non-zero exit code, which is what makes artifact QA scriptable in CI.

- **CWE-778 (Insufficient Logging):** a hunt that silently collects partial data — because of an unset time bound or an aborted query — produces the same blind spot as a missing sensor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are writing a new artifact **THEN** declare every input as a typed `parameters` entry with a `default`, and include a `resources` block (`ops_per_second`, `cpu_limit`, `timeout`, `max_rows`) so a fleet-wide run cannot saturate a host.
2. **IF** the collection reads event logs **THEN** combine `glob()` for path discovery with `parse_evtx(filename=...)` per file, filter by channel and event ID inside VQL, and bound the time range rather than parsing the whole log.
3. **IF** the artifact will run on endpoints without a server **THEN** build an offline collector pack and pin the artifact version; a hunt that depends on server-side notebooks cannot be delivered that way.
4. **IF** you are unsure whether a plugin exists **THEN** check the VQL reference for the installed version and use `velociraptor artifacts verify` as the gate; never invent a plugin name.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `velociraptor-vql-artifact-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable artifact and verify commands | [`QUERIES.md`](QUERIES.md) | Full YAML artifact, `verify` invocation, offline-pack notes |
| Need CLI syntax, flags, and VQL references | [`TOOLS.md`](TOOLS.md) | `velociraptor` subcommands, plugin names, resource keys |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Host-saturation and partial-collection incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Hunt-scope handoff when an artifact misbehaves |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Velociraptor VQL artifacts (YAML with `parameters`, `sources[].query`, `resources`), validated by `velociraptor artifacts verify`
- **Mandatory Self-Validation Command:** `velociraptor artifacts verify ./artifacts/*.yaml`

1. **Confirm the inputs.** Establish the Velociraptor server/client version, whether the artifact runs as a hunt, a notebook, or an offline collector, which artifact families already exist (reuse rather than duplicate), and the endpoints' roles — a domain controller and a developer laptop need different resource ceilings.
2. **Choose the branch.** Single-file extraction → one `glob` plus one parser. Directory-wide sweep → `glob` recursion with a time bound and `ops_per_second`. Binary inspection → `parse_pe`/`yara` with a `max_upload_bytes` cap. Cross-host aggregation → server-side artifact that reads client results rather than one artifact doing both.
3. **Define how to validate the artifact.** `velociraptor artifacts verify` must exit `0`; then run the source query against a collected snapshot or a single test endpoint and confirm the column set is what the notebook expects; then confirm the run completes within `timeout` with `ops_per_second` in place. A query that returns rows but blows the timeout has failed.
4. **Name the stop condition.** Stop when `artifacts verify` reports an issue, when a hunt exceeds `timeout` on any host, when `max_rows` truncates results (partial data must be labelled, not silently accepted), or when a parameter is used unvalidated in a path or regex.
5. **State what counts as a working tool.** A working artifact verifies clean, declares resource limits, returns a stable column set, and either completes within its timeout or reports truncation explicitly; parameters have defaults and are validated before use. Artifact name follows the `Vendor.Category.Name` convention so it sorts and routes predictably.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `resources: {ops_per_second, cpu_limit, timeout, max_rows}` | Proves the artifact is bounded per endpoint; without it a hunt can starve the host under investigation |
| `glob(globs=expand(path=...), accessor="auto")` then `parse_evtx(filename=OSPath)` | Proves path discovery and parsing are separated, so a filter can be applied before expensive decoding |
| `parameters` with `type: regex` / `type: timestamp` and a `default` | Proves inputs are typed, so the GUI validates them and the query can rely on format |
| `SELECT ... FROM parse_pe(file=...)` with `max_upload_bytes` set | Proves binary inspection cannot upload an unbounded file |
| `velociraptor artifacts verify` exit code | Proves YAML structure and VQL syntax before the artifact reaches a fleet |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```yaml
name: EvtxEverything
description: Parse every event log on the host
sources:
  - query: |
      SELECT * FROM parse_evtx(filename=expand(path="C:/Windows/System32/winevt/Logs/*.evtx"))
```

**Production-Grade Starter Skeleton (USE):**

```yaml
name: Custom.Windows.EventLogs.PowerShellScriptBlock
author: detection-engineering
description: |
  Reassemble PowerShell 4104 script blocks from bounded event logs. Filters by
  channel and event ID inside VQL, and caps work per endpoint.

type: CLIENT

parameters:
  - name: EvtxGlob
    type: str
    default: '%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx'
    description: Glob of event log files to parse.
  - name: StartDate
    type: timestamp
    description: Only return events on or after this time (UTC).
  - name: MaxRows
    type: int
    default: 50000
    description: Hard row cap so a noisy host cannot exhaust the collector.

resources:
  timeout: 600
  ops_per_second: 100
  cpu_limit: 50
  max_rows: 50000

sources:
  - name: ScriptBlocks
    query: |
      LET paths = SELECT OSPath
        FROM glob(globs=expand(path=EvtxGlob), accessor="auto")
        WHERE NOT IsDir

      LET events = SELECT
            timestamp(epoch=int(int=System.TimeCreated.SystemTime)) AS EventTime,
            System.Computer AS Computer,
            System.EventID.Value AS EventID,
            get(field="ScriptBlockId", item=EventData) AS ScriptBlockId,
            get(field="MessageNumber", item=EventData) AS MessageNumber,
            get(field="MessageTotal", item=EventData) AS MessageTotal,
            get(field="ScriptBlockText", item=EventData) AS ScriptBlockText,
            OSPath AS SourcePath
        FROM foreach(row=paths, query={
            SELECT * FROM parse_evtx(filename=OSPath, accessor="auto")
            WHERE System.EventID.Value = 4104
              AND (if(condition=StartDate,
                      then=timestamp(epoch=int(int=System.TimeCreated.SystemTime)) >= StartDate,
                      else=true))
        })

      SELECT * FROM events
      LIMIT MaxRows
```

**Why this matters:** the glob resolves paths cheaply, the parser runs per file with a channel and event-ID filter pushed down, and `resources` plus `LIMIT` bound both the endpoint cost and the result size — the two things an unbounded `parse_evtx` sweep ignores.

## When It Is NOT This Issue

- **A hunt returns far fewer rows than expected** — check `max_rows` and `timeout` first; a truncated hunt looks identical to a clean host, so read the resources block before editing the query.
- **The artifact verifies but produces nothing on a real host** — a parameter default using Windows path syntax may need `expand()`; and `%SystemRoot%` only expands inside a VQL string, not in the YAML scalar.
- **Client CPU spikes during a hunt** — `ops_per_second`/`cpu_limit` are missing or set per-artifact too high for the endpoint class; the fix is the resources block, not rewriting the plugin chain.
- **An event log parse takes minutes** — `parse_evtx` on every log including large third-party channels is expensive by nature; narrow the glob or add an ID filter rather than raising the timeout.
- **A plugin name is rejected as unknown** — the installed client version does not have it; check the VQL reference for that version instead of assuming the server's version applies to clients.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER invent a VQL plugin or parameter name; verify against the installed version's reference and `artifacts verify`.
- NEVER ship an artifact without a `resources` block if it touches `parse_evtx`, `parse_mft`, or `yara` — those are the plugins that can saturate an endpoint.
- NEVER present `max_rows` truncation as a complete collection; label partial results.
- NEVER assume server and client plugin availability are identical across versions in a mixed fleet.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Velociraptor version, delivery mode (hunt/notebook/offline), and endpoint class for `velociraptor-vql-artifact-development` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The artifact YAML or verify gate is specific and runnable (no generic 'collect the logs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: velociraptor-vql-artifact-development
- **Target Stack & Schema**: Velociraptor VQL artifact YAML with typed parameters and a resources block
- **Safety, Scope & Exit-Code Guards**: [ops_per_second/cpu_limit/max_rows bounds, parameter validation, verify gate, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Truncated results, missing plugins, unexpanded path variables, large third-party channels]
- **Implementation**:
  [Runnable artifact YAML following the Starter Skeleton]
- **Self-Validation Command**: `velociraptor artifacts verify ./artifacts/*.yaml`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-evtx-and-powershell-audit-scripting`](../windows-evtx-and-powershell-audit-scripting/SKILL.md) - Offline 4104 reassembly logic this artifact expresses in VQL
- [`osquery-extension-and-pack-development`](../osquery-extension-and-pack-development/SKILL.md) - The other fleet-visibility surface, with different scheduling semantics
- [`windows-forensic-artifact-parser-development`](../windows-forensic-artifact-parser-development/SKILL.md) - Parser-level detail behind `parse_mft`/`parse_prefetch`
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - Rule engineering for the `yara` plugin
- [`super-timeline-and-plaso-postprocessing-scripting`](../super-timeline-and-plaso-postprocessing-scripting/SKILL.md) - Consumes the collected rows as timeline input

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `velociraptor-vql-artifact-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
