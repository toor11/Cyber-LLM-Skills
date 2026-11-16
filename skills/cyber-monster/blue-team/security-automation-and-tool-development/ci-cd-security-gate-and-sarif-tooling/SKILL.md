---
name: ci-cd-security-gate-and-sarif-tooling
description: "Engineers CI/CD PR security gates and SARIF 2.1.0 policy engines: diff-aware blocking (failing PRs only on newly introduced high-confidence findings in changed lines), inline baseline/waiver expiration enforcement, and unified PR review annotations across SAST/SCA/secret scanners. Use when building DevSecOps pipeline gates."
family: security-automation-and-tool-development
tier: core
triggers: ["ci security gate script", "sarif diff blocker", "pr security annotation", "baseline waiver expiry"]
cwe: [CWE-693]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# CI/CD Security Gate and SARIF Tooling - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A PR security gate is a policy engine over normalized findings, not a wrapper around one scanner. Every scanner emits SARIF 2.1.0, whose `runs[].results[]` carry `ruleId`, `level`, `locations[].physicalLocation` (file plus region), `partialFingerprints`, `baselineState`, and `suppressions`. Two SARIF mechanisms make a gate trustworthy. `partialFingerprints` is the stable identity of a finding across runs, so "the same issue moved three lines" is not treated as a new issue. `baselineState` (`new`, `unchanged`, `updated`, `absent`) and `suppressions` (with `status` of `accepted`, `underReview`, or `rejected`) express the difference between "this is pre-existing debt" and "this PR introduced it" — and a result is only considered suppressed when no suppression is `underReview` or `rejected`. Diff-awareness adds a second axis: even a `new` finding on an untouched line is not the PR author's problem, so the gate intersects the finding's position with the changed-line ranges from `git diff --unified=0`. A gate that blocks on total finding count instead of this intersection trains developers to bypass it, which is the failure mode that actually loses security value.

- **CWE-693 (Protection Mechanism Failure):** a gate that can be bypassed, or that silently stops evaluating, provides the appearance of a control without the effect.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are building a new gate **THEN** consume SARIF only (`semgrep scan --sarif --sarif-output=...`, `codeql database analyze --format=sarifv2.1.0`), never a scanner's human output, and key findings on `partialFingerprints` plus `ruleId`.
2. **IF** the repo has pre-existing findings **THEN** compute `baselineState` against a stored baseline SARIF and block only on `new` results; never on `unchanged`.
3. **IF** blocking only on changed lines **THEN** derive ranges from `git diff --unified=0 origin/<base>...HEAD` and intersect with `physicalLocation.region.startLine`/`endLine`; a finding outside the hunk is pre-existing regardless of `baselineState`.
4. **IF** a waiver suppresses a finding **THEN** require an `expires_at` date and treat an expired or `rejected` waiver as unsuppressed; a waiver with no expiry is a permanent bypass.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `ci-cd-security-gate-and-sarif-tooling` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable gate and annotation shapes | [`QUERIES.md`](QUERIES.md) | SARIF ingestion, diff intersection, exit-code contract |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `semgrep`, `codeql`, `upload-sarif`, GitHub annotation flags |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Bypassed-gate and waiver-rot incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Pipeline handoff when a gate blocks a release |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** SARIF 2.1.0 (`runs[].results[]` with `ruleId`, `level`, `locations[].physicalLocation`, `partialFingerprints`, `baselineState`, `suppressions[].status`) produced by Semgrep CE or CodeQL CLI and consumed by a Python policy engine
- **Mandatory Self-Validation Command:** `python -m py_compile sarif_gate.py`

1. **Confirm the inputs.** Establish which scanners run, how their SARIF is produced (`--sarif`, `--format=sarifv2.1.0`), where the baseline SARIF lives, the repository's base ref for diffing, and the organization's severity policy. Confirm the SARIF actually contains `partialFingerprints` — a hand-built SARIF without them cannot be deduplicated across runs.
2. **Choose the branch.** Whole-repo blocking is appropriate only on an empty baseline. Existing debt → baseline comparison plus changed-line intersection. Single-scanner repos still normalize to SARIF so the gate survives adding a second scanner.
3. **Define how to validate the gate.** Three fixtures, each a SARIF file: one finding on a changed line at blocking severity (must fail), one finding on an unchanged line at blocking severity (must pass), and one suppressed finding with an unexpired waiver (must pass). Add a fourth with an expired waiver (must fail). Run the gate against each and assert the exit code.
4. **Name the stop condition.** Stop when a finding has no stable fingerprint (cannot be deduplicated), when the base ref cannot be resolved (a diff against the wrong base silently changes the verdict), when a waiver lacks an expiry, or when a blocking-severity finding lands outside every changed hunk and is still counted against the PR.
5. **State what counts as a working tool.** A working gate exits `0` only when every blocking-severity `new` finding inside a changed hunk is either absent or covered by an unexpired waiver; exits `1` when at least one such finding is unbounded; exits `2` when a SARIF file is missing, unparseable, or lacks the fields the policy needs. It emits one annotation per finding with file, line, rule, and reason.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `partialFingerprints` on each result | Proves finding identity survives line drift, which is what makes baseline comparison meaningful |
| `baselineState` == `new` (not `unchanged`/`updated`) | Proves the finding was introduced by this change set rather than inherited |
| `physicalLocation.region.startLine` inside a `git diff -U0` hunk | Proves the finding sits on code this PR touched; the second, independent gate |
| `suppressions[].status` absent or `accepted` plus unexpired `expires_at` | Proves the waiver is live; `underReview` or `rejected` must not suppress |
| Distinct exit codes for finding vs environment failure | Proves a scanner crash cannot be mistaken for a clean PR |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: blocks on total finding count, ignores fingerprints, and treats any
# suppression as permanent regardless of status or expiry.
import json
import sys

sarif = json.load(open(sys.argv[1]))
findings = [r for run in sarif["runs"] for r in run.get("results", [])]
blocking = [f for f in findings if f.get("level") in ("error", "warning")]
unsuppressed = [f for f in blocking if not f.get("suppressions")]
print(f"{len(unsuppressed)} findings block this PR")
sys.exit(1 if unsuppressed else 0)
```

**Production-Grade Starter Skeleton (USE):**

```python
# sarif_gate.py - Exit 0 clean, 1 blocking finding, 2 unusable input
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys

BLOCKING_LEVELS = {"error", "warning"}
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

def changed_lines(repo: pathlib.Path, base_ref: str) -> dict[str, set[int]]:
    out = subprocess.run(
        ["git", "-C", str(repo), "diff", "--unified=0", f"{base_ref}...HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout
    touched: dict[str, set[int]] = {}
    current = None
    for line in out.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:].strip()
            touched.setdefault(current, set())
        elif current and (m := HUNK_RE.match(line)):
            start = int(m.group(1))
            span = int(m.group(2) or 1)
            touched[current].update(range(start, start + span))
    return touched

def waiver_live(result: dict, today: dt.date) -> bool:
    for sup in result.get("suppressions", []) or []:
        if sup.get("status") in ("underReview", "rejected"):
            continue
        expires = (sup.get("properties") or {}).get("expires_at")
        if not expires:
            continue
        if dt.date.fromisoformat(expires) >= today:
            return True
    return False

def gate(sarif_path: pathlib.Path, repo: pathlib.Path, base_ref: str, baseline: pathlib.Path | None) -> int:
    if not sarif_path.is_file():
        sys.stderr.write(f"fatal: missing SARIF {sarif_path}\n")
        return 2
    try:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"fatal: unparseable SARIF: {exc}\n")
        return 2
    baseline_ids: set[str] = set()
    if baseline and baseline.is_file():
        prior = json.loads(baseline.read_text(encoding="utf-8"))
        for run in prior.get("runs", []):
            for res in run.get("results", []):
                fp = (res.get("partialFingerprints") or {}).get("primaryLocationLineHash")
                if fp:
                    baseline_ids.add(fp)
    touched = changed_lines(repo, base_ref)
    today = dt.date.today()
    blocking = 0
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            if res.get("level") not in BLOCKING_LEVELS:
                continue
            fp = (res.get("partialFingerprints") or {}).get("primaryLocationLineHash")
            if res.get("baselineState") == "unchanged" or (fp and fp in baseline_ids):
                continue
            if waiver_live(res, today):
                continue
            for loc in res.get("locations", []) or []:
                phys = (loc.get("physicalLocation") or {})
                uri = (phys.get("artifactLocation") or {}).get("uri", "")
                region = phys.get("region") or {}
                first = int(region.get("startLine", 0) or 0)
                last = int(region.get("endLine", first) or first)
                if any(n in touched.get(uri, set()) for n in range(first, last + 1)):
                    blocking += 1
                    print(json.dumps({"file": uri, "line": first, "rule": res.get("ruleId"),
                                      "fingerprint": fp, "annotation": "introduced by this change"}))
    return 1 if blocking else 0

if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.stderr.write("usage: sarif_gate.py <sarif> <repo> <base_ref> [baseline.sarif]\n")
        raise SystemExit(2)
    b = pathlib.Path(sys.argv[4]) if len(sys.argv) > 4 else None
    raise SystemExit(gate(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], b))
```

**Why this matters:** three independent filters must all agree before a PR is blocked — not in the baseline, no live waiver, and the location intersects a line this branch actually changed — so inherited debt and untouched code cannot fail the build.

## When It Is NOT This Issue

- **The gate blocks a PR that changed only documentation** — the diff base was wrong (comparing against an unrelated ref) or the SARIF came from a full-repo scan with baseline disabled; check the base ref before touching the policy.
- **A finding reappears every run with a new identity** — the SARIF lacks `partialFingerprints` (common with hand-built or minimal scanner output), so nothing can be deduplicated. Generate fingerprints rather than weakening the gate.
- **A waiver "does not work" but the annotation says suppressed** — the suppression had `status: underReview` or `rejected`, which SARIF explicitly says does not suppress; fix the waiver's status, not the gate.
- **The scanner crashed and the PR went green** — the wrapper collapsed "no findings" and "scan failed" into the same exit code. Distinguish them before anyone trusts the gate.
- **`upload-sarif` shows duplicate alerts** — the upload path without fingerprint data creates duplicates; the fix is fingerprint generation at scan time, not suppression at the platform.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER claim `baselineState` is populated automatically — it must be computed against a prior run or supplied by a baseline-aware tool.
- NEVER treat `suppressions` as unconditional; a suppression with `underReview` or `rejected` status does not suppress the result.
- NEVER use `--format=sarif-latest` in automation when a pinned `sarifv2.1.0` exists; the "latest" alias may change between tool releases.
- NEVER present a gate that exits `0` on scanner failure as passing; the environment-failure path must be observable and distinct.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Scanner set, SARIF producer flags, baseline location, and diff base ref for `ci-cd-security-gate-and-sarif-tooling` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The gate, waiver check, or annotation step is specific and runnable (no generic 'fail on critical issues' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: ci-cd-security-gate-and-sarif-tooling
- **Target Stack & Schema**: SARIF 2.1.0 from Semgrep CE or CodeQL CLI, consumed by a Python policy engine
- **Safety, Scope & Exit-Code Guards**: [Base-ref pinning, changed-line intersection, waiver expiry, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Missing fingerprints, underReview suppressions, scanner crash, untouched-line findings]
- **Implementation**:
  [Runnable gate following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile sarif_gate.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`custom-secret-scanner-detector-engineering`](../custom-secret-scanner-detector-engineering/SKILL.md) - Adds the secrets scanner whose SARIF this gate consumes
- [`sbom-cyclonedx-and-cve-reachability-tooling`](../sbom-cyclonedx-and-cve-reachability-tooling/SKILL.md) - Dependency findings that also land in this gate
- [`iac-rego-opa-and-checkov-policy-development`](../iac-rego-opa-and-checkov-policy-development/SKILL.md) - The infrastructure half of the same PR check
- [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) - Same repository-scanning discipline applied to detection content

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ci-cd-security-gate-and-sarif-tooling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
