---
name: codeql-query-development
description: "Develops CodeQL `.ql` security queries across Java, JavaScript/TypeScript, Python, C/C++, and Go: `DataFlow::Configuration` / `TaintTracking::Global`, AST/CFG predicates, threat-model sources, barrier guards, and SARIF `@kind path-problem` metadata. Use when writing interprocedural taint or variant-analysis queries."
family: security-assessment-tooling-and-automation
tier: flagship
triggers: ["codeql query", "write codeql", "tainttracking global", "path-problem ql", "variant analysis codeql"]
cwe: [CWE-20]
owasp: [A03:2021]
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
---


# Codeql Query Development - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **flagship** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

CodeQL queries are QL programs over a relational database extracted from source. A taint query defines a configuration module implementing `DataFlow::ConfigSig` with `isSource`, `isSink`, and `isBarrier`, instantiates `TaintTracking::Global<Config>` (or `DataFlow::Global`), imports that module's `PathGraph`, and declares `@kind path-problem`. The audit work is proving the source really is untrusted, the sink really is dangerous, and the barrier set matches the sanitizers the codebase actually uses.

- **The configuration module is the query's argument.** Sources, sinks, and barriers are reviewable claims; a query with a broad source set and no barrier answers a different question than the one asked.
- **Path graph is the evidence.** `path-problem` output shows the intermediate steps, which is what lets a reviewer dismiss a false positive at the right hop instead of rejecting the query.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the flow crosses function or file boundaries **THEN** use `TaintTracking::Global` and add `isAdditionalFlowStep` for the codebase's own wrappers rather than widening sources.
2. **IF** a known sanitizer exists **THEN** add it to `isBarrier` before reporting, otherwise the finding count is a false-positive count.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an extracted database for the exact commit, and a named source/sink pair the codebase actually uses — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** CodeQL 2.2x with the modular dataflow API: `module Config implements DataFlow::ConfigSig`, `module Flow = TaintTracking::Global<Config>`, `import Flow::PathGraph`
- **Mandatory Self-Validation Command:** `codeql query compile --search-path <packs> MyQuery.ql`

1. Confirm the target surface: extract the database from the commit under review and record the language pack version, because taint steps change between releases.
2. Choose the branch: local dataflow when the sink is in the same function, global taint when the value crosses calls, and a custom `isAdditionalFlowStep` when a project wrapper hides the flow.
3. Define the differential: run the query against the vulnerable commit and against the commit that fixes it; the finding must disappear on the fix, and a finding that survives the fix is a query defect, not a bug.
4. Name the stop condition: a result cap plus a review of the first page of paths, because a query returning thousands of paths is uncalibrated rather than thorough.
5. Prove it: attach the `path-problem` output with the source and sink locations, and name the barrier that does *not* cover this path.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `module C implements DataFlow::ConfigSig` | The configuration is a named claim; separate modules per vulnerability class keep sources honest. |
| `module Flow = TaintTracking::Global<C>` | Instantiates the analysis and provides `flow`, `flowPath`, and the module's own `PathGraph`. |
| `predicate isBarrier(DataFlow::Node n)` | Encodes the sanitizers the codebase really uses; `isSanitizer` and `isSanitizerIn` are the deprecated names. |
| `predicate isAdditionalFlowStep` | Adds flow for project wrappers without broadening what counts as a source. |

## Worked Contrast

**Sink-Only Query Without Barriers:**

```ql
/**
 * @name SQL execution
 * @kind problem
 */
import python

from Call c
where c.getFunc().(Attr).getName() = "execute"
select c, "SQL execution"  // BUG: no taint, no source, so parameterised calls are reported
```

**Modular Taint Query With Declared Barriers and Path Graph:**

```ql
/**
 * @name Request data reaches raw SQL
 * @kind path-problem
 * @problem.severity error
 * @id py/audit/raw-sql
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module C implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) {
    exists(Call c | c.getFunc().(Attr).getName() = "execute" | n = c.getArg(0))
  }
  predicate isBarrier(DataFlow::Node n) { n.getNode().getALocalSource() instanceof Sanitizer }
}

module Flow = TaintTracking::Global<C>;
import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink.getNode(), src, sink, "request data reaches raw SQL"
```

**Why this matters:** The sink-only version cannot distinguish a parameterised call from a concatenated query, so its output is a list of every database call in the codebase. Declaring the source as a remote flow source and the barrier as the project's sanitiser makes the result set equal to the bug class, and the path graph shows the hop a reviewer needs to judge.

## When It Is NOT This Issue

- **Query compiled against a different pack version.** Taint steps for standard-library functions change between releases; a missing finding may be a version difference.
- **Sanitizer not modelled.** A project wrapper that validates input is invisible until added to `isBarrier`; its absence produces findings the code already prevents.
- **Extraction gap.** Files excluded from the database cannot produce findings; check the extraction diagnostics before concluding a sink is safe.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER extend the deprecated `TaintTracking::Configuration` class — implement `DataFlow::ConfigSig` and instantiate `TaintTracking::Global<Config>`.
- NEVER omit `@kind path-problem` and `import MyFlow::PathGraph` when reporting source-to-sink flows.
- NEVER leave unbounded cross-product predicates (`exists` without join variables) that stall compilation.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `codeql-query-development` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: codeql-query-development
- **Target Stack & Schema**: CodeQL modern `DataFlow::ConfigSig` + `TaintTracking::Global<MyConfig>` (CodeQL CLI 2.16+)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `codeql query compile query.ql; codeql test run test-dir/`
```

## Related Sub-Skills

- [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `codeql-query-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/gh_security_lab (12) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
