---
name: sarif-and-assessment-report-automation
description: "Builds SARIF 2.1.0 converters, multi-scanner finding deduplicators, CWE/OWASP enrichers, and Markdown/DOCX/JSON assessment report generators: fingerprinting findings by `(ruleId, uri, line/endpoint)` and enforcing evidence completeness checks. Use when automating pentest, AppSec, or bug-bounty reporting pipelines."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["sarif generator", "finding deduplication script", "pentest report automation", "sarif 2.1.0 python"]
cwe: [CWE-200]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
---


# SARIF and Assessment Report Automation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)

## Mechanism and Preconditions

Normalising heterogeneous tool output into SARIF 2.1.0 so findings from several scanners live in one result set with stable identity: `runs[].results[]` with `ruleId`, `locations`, `partialFingerprints`, and a `properties` block carrying severity and taxonomy. The report automation then deduplicates by fingerprint and enriches with CWE and control mappings instead of concatenating tool reports.

- **`partialFingerprints` is the identity.** It is what lets a finding track across runs; without it every scan is a new set of results and trends are meaningless.
- **`ruleId` must be namespaced.** Two scanners both emitting `sql-injection` collapse into one rule unless the id carries the tool prefix.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** two tools report the same defect **THEN** deduplicate on location plus rule family, not on message text, and keep both `ruleId` values as evidence.
2. **IF** the finding must map to a framework **THEN** put the CWE and control ids in `properties.tags` and the rule's `relationships`, not in the message string.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the SARIF version, the rule-id namespace per tool, and a fingerprint strategy — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** SARIF 2.1.0 (`$schema: https://json.schemastore.org/sarif-2.1.0.json`, `runs[].tool.driver.rules`, `runs[].results[].partialFingerprints`)
- **Mandatory Self-Validation Command:** `python -c "import json; d=json.load(open('out.sarif')); print(d['version'], len(d['runs'][0]['results']))"`

1. Confirm the target surface: enumerate the tools whose output must merge, and record each tool's native rule-id format and location encoding.
2. Choose the branch: single-run merge when all tools report the same artefact, multi-run when they analyse different languages or stages.
3. Define the differential: run the pipeline on a known finding set and on the same set after a fix; the fixed finding's fingerprint must be absent and every other fingerprint unchanged.
4. Name the stop condition: a result cap per run and a schema validation step, so a malformed log fails the pipeline instead of producing a partial report.
5. Prove it: validate against the SARIF schema, then deduplicate and show the before/after counts with the fingerprint used for each merge.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `$schema pointed at sarif-2.1.0.json` | Anchors the document to a validating schema so consumers parse it predictably. |
| `runs[].tool.driver.rules with namespaced ids` | Keeps two tools' rules distinct while allowing correlation by tag. |
| `partialFingerprints: {primaryLocationLineHash: ...}` | Stable identity across runs, computed from path, rule, and a normalised snippet. |
| `properties.tags for CWE and control ids` | Keeps taxonomy machine-readable instead of embedded in prose messages. |

## Worked Contrast

**SARIF Without Identity or Namespacing:**

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "merged"}},
      "results": [
        {"ruleId": "sql-injection", "message": {"text": "found"}}
      ]
    }
  ]
}
```

**Namespaced Rule With Fingerprint and Location:**

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "audit-merge", "rules": [
        {"id": "semgrep/python.raw-sql", "properties": {"tags": ["CWE-89"]}}
      ]}},
      "results": [
        {"ruleId": "semgrep/python.raw-sql",
         "level": "error",
         "message": {"text": "request data reaches raw SQL"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"},
                          "region": {"startLine": 42}}}],
         "partialFingerprints": {"primaryLocationLineHash": "9f2c:1"}}
      ]
    }
  ]
}
```

**Why this matters:** A result with no location, no fingerprint, and a bare `ruleId` cannot be tracked, deduplicated, or attributed to a tool, so the merged report is only a list of sentences. Namespacing the rule, including the physical location, and carrying a fingerprint makes each finding identifiable across runs and lets a consumer join it with the tool that produced it.

## When It Is NOT This Issue

- **Duplicate results across runs.** The same defect from two tools is one finding; deduplicate on fingerprint and keep both rule ids.
- **Missing location read as missing finding.** A result without `locations` is schema-valid but untrackable; treat it as a tool defect, not a finding.
- **Level mapped from tool severity literally.** Different tools' `error` levels are not comparable; carry the raw severity in `properties`.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `$schema: sarif-2.1.0` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sarif-and-assessment-report-automation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: sarif-and-assessment-report-automation
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `$schema: sarif-2.1.0`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile sarif_and_assessment_report.py; python sarif_and_assessment_report.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sarif-and-assessment-report-automation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 1 |
| Top sources | bug-bounty-pentest-en (12) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
