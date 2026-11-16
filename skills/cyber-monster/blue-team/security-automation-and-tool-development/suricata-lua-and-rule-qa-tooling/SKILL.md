---
name: suricata-lua-and-rule-qa-tooling
description: "Develops Suricata rule linters, `suricata-verify` PCAP regression harnesses, and Lua sticky-buffer inspection scripts: validating `fast_pattern` placement, flowbits pairing, `sid`/`rev` hygiene, and `eve.json` alert assertions. Use when engineering IDS rule QA and custom Suricata protocol checks."
family: security-automation-and-tool-development
tier: leaf
triggers: ["suricata lua script", "suricata-verify", "ids rule linter", "fast_pattern check", "eve.json parser"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, ocsf-and-ecs-log-normalizer-development]
corpus_sparse: true
---

# Suricata Lua and Rule QA Tooling - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **leaf** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Suricata evaluates rules in stages: a multi-pattern matcher finds candidate packets from the selected content patterns, then the rule's full inspection logic runs on the candidates. `fast_pattern` nominates which content drives that first stage, so a badly chosen `fast_pattern` — a common string, or one placed inside a buffer that will not be searched — multiplies the candidate set and turns a cheap rule into a load problem without changing what it matches. Lua rules (`lua:<script>;`) extend detection into logic the rule language cannot express: since Suricata 8.0 they are enabled by default and run **sandboxed** on **Lua 5.4**, with reduced libraries and an instruction-count limit, so a script depending on an unrestricted library or an unbounded loop now fails or is terminated rather than running. Rule QA is therefore two different jobs: static property checks on the rule text (`sid` uniqueness, `rev` bumping, `flowbits` set/isset pairing, protocol keywords matching the declared `flow`), and dynamic regression proof that the rule still alerts on its PCAP and still stays silent on a benign capture, asserted against `eve.json`.

- **CWE-778 (Insufficient Logging):** a rule that stopped loading — because `requires` was unmet, or a Lua script failed in the sandbox — logs nothing and looks like a quiet network.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are linting rule text **THEN** check four properties before anything else: unique `sid`, `rev` incremented on every content change, every `isset` flowbit having a matching `set`, and a `fast_pattern` on a content that is actually unique to the rule.
2. **IF** you need logic the rule language cannot express **THEN** write a `lua` rule with `init(args)` and `match(args)` returning `1`/`0`, using `require("suricata.http")` and `http.get_tx()`, and confirm it works inside the Suricata 8 sandbox on Lua 5.4.
3. **IF** you are proving a rule still works **THEN** add a `suricata-verify` test: a PCAP, a `test.yaml` with `filter` entries asserting `event_type: alert` counts, and a benign control case asserting zero.
4. **IF** the question is really about Sigma rule portability or backend compilation **THEN** use [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md); Suricata rules are not Sigma output.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `suricata-lua-and-rule-qa-tooling` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable lint and verify commands | [`QUERIES.md`](QUERIES.md) | `suricata -T`, `suricata-verify` invocation, `eve.json` assertions |
| Need CLI syntax, flags, and Lua API references | [`TOOLS.md`](TOOLS.md) | `-T`, `-S`, `-r`, `suricata-verify` options, sandbox constraints |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Rule-load and performance incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Sensor-scope handoff while a rule set is corrected |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Suricata 8.x (`suricata -T` rule load test, sandboxed Lua 5.4 detection scripts, `suricata-verify` PCAP harness), `eve.json` schema for assertions
- **Mandatory Self-Validation Command:** `suricata -T -S rules/local.rules -c suricata.yaml`

1. **Confirm the inputs.** Establish the Suricata version, the rule file or directory under change, the `suricata.yaml` in use, and which PCAP fixtures exist for the rule. Check whether the rule depends on a Lua script and whether that script uses anything the sandbox forbids.
2. **Choose the branch.** Static property lint runs offline on the rule text. Load validity requires `suricata -T` with the real config. Behaviour requires a PCAP replay with `eve.json` assertions. Lua work additionally requires confirming sandbox compatibility before writing more than a few lines.
3. **Define how to validate the script.** Three gates in order: the linter reports zero property violations; `suricata -T` loads the rule set with exit `0`; the `suricata-verify` case alerts on the malicious PCAP and stays silent on the benign one. A rule that loads but never alerts has passed only the first two gates.
4. **Name the stop condition.** Stop when `suricata -T` reports a load error, when a `requires` keyword names an unmet dependency (Suricata 8 treats unknown requirements as unmet, so the rule silently drops out), when the benign fixture alerts, or when moving `fast_pattern` changes the alert count — that last one means the pattern placement was load-bearing for correctness, not just performance.
5. **State what counts as a working tool.** A working QA harness exits `0` only when all three gates pass, `1` when a rule property violates policy or the differential breaks, and `2` when the config, rule file, or PCAP is missing. It prints the offending `sid` for every finding so a rule author can act without re-reading the whole log.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `suricata -T -S rules/local.rules -c suricata.yaml` | Proves the rule set loads against the real config; catches `requires` and syntax faults that a text linter cannot |
| `fast_pattern` on a rule-unique content | Proves the multi-pattern stage will not be swamped; moving it must not change the alert count |
| `flowbits:set` / `flowbits:isset` pairing | Proves a multi-packet rule can only fire after its setup packet, which is the difference between a stateful detection and a random one |
| `eve.json` `event_type: alert` with `alert.signature_id` | Proves which `sid` fired, so a differential can attribute a change to one rule |
| Lua `http.get_tx()` + `tx:request_line()` inside the sandbox | Proves the script inspects the transaction the rule selected, under Lua 5.4 restrictions |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```lua
-- ANTI-PATTERN: no sandbox-safe module use, unbounded string work, and no return contract
function init(args)
end

function match(args)
  local tx = require("suricata.http").get_tx()
  local buf = ""
  while true do
    buf = buf .. tostring(tx:request_line())   -- unbounded growth, sandbox instruction limit
  end
  return buf:find("attack")
end
```

**Production-Grade Starter Skeleton (USE):**

```lua
-- http_long_request_line.lua - sandbox-safe Suricata 8 Lua detection script
local http = require("suricata.http")

local max_len = 1024

function init(args)
  for _, arg in ipairs(args) do
    local k, v = arg:match("^(%w+)=(%d+)$")
    if k == "max_len" then
      max_len = tonumber(v)
    end
  end
end

function match(args)
  local tx = http.get_tx()
  if tx == nil then
    return 0
  end
  local line = tx:request_line()
  if line == nil then
    return 0
  end
  if #line > max_len then
    return 1
  end
  return 0
end
```

**Why this matters:** the script returns the documented `0`/`1` contract, guards every nil, and does a single bounded length comparison — the shape that survives the Lua 5.4 instruction limit instead of being terminated mid-scan. Pair it with `lua:http_long_request_line.lua;` in the rule's detection list and a `suricata-verify` case that asserts one alert on the malicious capture and none on the benign one (see [`QUERIES.md`](QUERIES.md)).

## When It Is NOT This Issue

- **Rule present in the file but absent from the running ruleset** — Suricata 8 treats unknown `requires` keywords as unmet and refuses to load the rule; the file linter sees valid syntax and the engine sees no rule.
- **An alert count changed after a "performance-only" `fast_pattern` edit** — the pattern was also constraining which buffers were inspected, so the edit was semantic. Treat `fast_pattern` changes as detection changes and re-run the differential.
- **Lua rule never fires and logs no error** — the script may be terminated by the sandbox instruction limit, which is not a Lua exception you can catch. Reduce work per call instead of adding error handling.
- **`stats.whitelist` missing from `eve.json` after upgrade** — Suricata 8 renamed it to `stats.score`; a consumer asserting on the old key reports "no stats" for a healthy engine.
- **Benign alert on a scanner or backup host** — that is an environment exclusion decision documented in the site's rule policy, not a rule defect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER state a Lua detection script can use arbitrary Lua libraries — Suricata 8 sandboxes detection scripts with reduced libraries and an instruction limit.
- NEVER recommend `base64_decode` for new rules when `from_base64` is available; the transform was superseded in Suricata 8.
- NEVER claim `suricata -T` proves a rule alerts; it proves only that the rule loads.
- NEVER assert a specific `eve.json` field path without checking the installed version's output schema — the stats and DNS event shapes changed in 8.0.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Suricata version, config file, rule scope, and fixture PCAPs for `suricata-lua-and-rule-qa-tooling` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The lint check, Lua script, or verify case is specific and runnable (no generic 'test the rule' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: suricata-lua-and-rule-qa-tooling
- **Target Stack & Schema**: Suricata 8.x with sandboxed Lua 5.4 detection scripts and suricata-verify PCAP cases
- **Safety, Scope & Exit-Code Guards**: [Rule-file scope, `-T` load gate, fixture replay only, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Unmet requires, sandbox termination, benign control PCAP]
- **Implementation**:
  [Runnable linter check, Lua script, or test.yaml following the Starter Skeleton]
- **Self-Validation Command**: `suricata -T -S rules/local.rules -c suricata.yaml`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md) - Portable rule source that must not be conflated with IDS syntax
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - File-side signature QA with the same positive/benign differential discipline
- [`zeek-script-and-notice-development`](../zeek-script-and-notice-development/SKILL.md) - The other network-sensor scripting surface, with its own `btest` harness
- [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md) - Consumes `eve.json` as a normalized event stream
- [`pcap-and-netflow-beacon-analysis-scripting`](../pcap-and-netflow-beacon-analysis-scripting/SKILL.md) - Builds the PCAP fixtures these tests replay

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `suricata-lua-and-rule-qa-tooling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
