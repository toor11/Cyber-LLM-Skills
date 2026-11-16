---
name: semgrep-rule-engineering
description: "Authors high-precision Semgrep YAML rules: `mode: taint` with `pattern-sources`, `pattern-sanitizers`, and `pattern-sinks`, `metavariable-regex`/`metavariable-comparison`, autofix blocks, and inline `# ruleid:` / `# ok:` test fixtures. Use when codifying vulnerability patterns into deterministic SAST rules."
family: security-assessment-tooling-and-automation
tier: flagship
triggers: ["semgrep rule", "write semgrep yaml", "semgrep taint mode", "pattern-sinks", "pattern-sanitizers"]
cwe: [CWE-20]
owasp: [A03:2021]
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Semgrep Rule Engineering - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **flagship** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Authoring Semgrep rules that hold up in CI: `mode: taint` with `pattern-sources`, `pattern-sanitizers`, and `pattern-sinks`, `metavariable-regex` or `metavariable-comparison` for value constraints, `paths:` to bound the scan, and inline `# ruleid:` / `# ok:` fixtures checked by `semgrep --test`. The audit problem is specificity: a rule that matches a call shape without its argument provenance reports every safe call in the codebase.

- **Sanitizers are part of the rule.** A taint rule without `pattern-sanitizers` reports parameterised and escaped paths, and the finding count becomes a false-positive count.
- **Fixtures are the contract.** `# ruleid:` and `# ok:` annotations make both directions executable, so a later edit that widens the rule fails the test instead of the build.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the sink takes a query string **THEN** use taint mode with a `focus-metavariable` on the query argument, not a bare `pattern:` on the call.
2. **IF** the rule needs a value comparison **THEN** use `metavariable-regex` or `metavariable-comparison` rather than encoding the constraint in the pattern text.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a Semgrep version, a target language, and one source-sink pair present in the codebase — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Semgrep 1.1xx with `rules:` list schema, `mode: taint`, `pattern-sources`/`pattern-sanitizers`/`pattern-sinks`, and inline test annotations
- **Mandatory Self-Validation Command:** `semgrep --validate --config rule.yaml && semgrep --test rule.yaml`

1. Confirm the target surface: name the source (framework request object, CLI argument, file read) and the sink function with its resolved module path.
2. Choose the branch: search mode for a syntactic pattern, taint mode when provenance matters, and `join` mode when two conditions in different files must hold together.
3. Define the differential: run the rule against a fixture with the vulnerable pattern and one with the sanitiser applied; the second must produce zero findings.
4. Name the stop condition: a `paths:` include set, a finding cap, and `--error` only after the fixture pair passes.
5. Prove it: `semgrep --test` output plus the matched code range, so the rule's precision is demonstrated rather than asserted.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `mode: taint with the three pattern groups` | Tracks provenance from source to sink; the only mode that can distinguish a concatenated query from a bound one. |
| `pattern-sanitizers with the project's own validator` | Encodes the codebase's real defences; omitting it is the top cause of false positives. |
| `focus-metavariable on the sink argument` | Narrows the reported range to the argument, which makes the finding point at the injected value. |
| `# ruleid: and # ok: annotations` | Executable precision contract for both directions, run by `semgrep --test`. |

## Worked Contrast

**Pattern Rule That Flags Every Safe Call:**

```yaml
rules:
  - id: noisy-sql-pattern
    languages: [python]
    severity: ERROR
    message: Potential SQL injection
    pattern: $CURSOR.execute($QUERY, ...)  # BUG: flags bound parameter calls, no taint, no sanitiser
```

**Taint Rule With Sources, Sanitisers and a Focused Sink:**

```yaml
rules:
  - id: python-raw-sql-taint
    mode: taint
    languages: [python]
    severity: ERROR
    message: Untrusted request data reaches cursor.execute without binding.
    paths:
      include: ["src/**", "app/**"]
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: flask.request.args.get(...)
              - pattern: flask.request.json[...]
    pattern-sanitizers:
      - pattern-either:
          - pattern: int(...)
          - pattern: uuid.UUID(...)
    pattern-sinks:
      - patterns:
          - pattern: $CURSOR.execute($SQL, ...)
          - focus-metavariable: $SQL
```

**Why this matters:** The search-mode rule cannot tell `execute("SELECT ... WHERE id = %s", (uid,))` from a concatenated query, so its output includes every correct call. Taint mode with an explicit source, the project's own sanitisers, and a focused sink reduces the result set to calls that carry request data into the SQL string, which is the class the rule claims.

## When It Is NOT This Issue

- **Bound parameters reported.** A parameterised call is safe; the finding usually means the sink pattern was not narrowed to the query argument.
- **Sanitiser not modelled.** A project validator missing from `pattern-sanitizers` produces findings the code already prevents.
- **Rule matched in test fixtures.** Fixtures intentionally contain the pattern; exclude test paths in `paths:` rather than accepting the noise.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER write greedy `pattern: $FUNC(...)` without constraining the sink module/method, and NEVER invent `--dry-run` (Semgrep scans are read-only by default; autofix preview uses `--dryrun` without a hyphen, and CI blocking requires `--error`).
- NEVER omit `pattern-sanitizers` in taint rules (causes false positives on parameterized or escaped paths).
- NEVER ship a Semgrep rule without `# ruleid:` and `# ok:` inline test annotations verified via `semgrep --test`.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `semgrep-rule-engineering` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: semgrep-rule-engineering
- **Target Stack & Schema**: Semgrep YAML syntax v2 (`rules:`, `mode: taint`, `pattern-sources`, `pattern-sanitizers`, `pattern-sinks`, `paths:` scope bounds, `--error` non-zero CI exit)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `semgrep --validate --config rule.yaml; semgrep --test rule.yaml`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `semgrep-rule-engineering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
