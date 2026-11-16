---
name: cis-benchmark-and-baseline-compliance-scripting
description: "Develops read-only CIS Benchmark and security-baseline drift auditors (Python/pytest-testinfra/PowerShell): checking SSHD, sysctl, mount flags, auditd, and Windows GPO/Registry state without mutating hosts, and emitting pass/fail/exception JSON reports. Use when automating host configuration compliance checks."
family: security-automation-and-tool-development
tier: leaf
triggers: ["cis audit script", "testinfra security", "baseline drift checker", "readonly hardening audit"]
cwe: [CWE-1188]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# CIS Benchmark and Baseline Compliance Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **leaf** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A compliance auditor answers one question per control: does the host's observed state match the benchmark requirement, and can that be shown without changing the host? That second clause is the engineering constraint. Every check must be a read — `sshd -T` rather than parsing a config file and guessing which of several conflicting directives wins, `sysctl -n` rather than reading `/proc` paths by assumption, mount-table inspection rather than remounting, and registry reads rather than `Set-ItemProperty`. The output is a three-valued judgement, not a boolean: pass, fail, and a third state for controls that cannot be evaluated on this host (unsupported platform, missing tool, control not applicable). Collapsing the third state into pass is how compliance reports become fiction. A benchmark is also versioned — CIS RHEL 9 v2.0 and Ubuntu 24.04 v2.0 have different control numbering and different required values — so the report has to name the benchmark version it was evaluated against, and an upgrade of the benchmark is a code change, not a config change. Drift detection follows naturally: run the same audit twice and diff, which turns "is this host compliant" into "what changed since the baseline" and gives a reviewable delta instead of an absolute claim.

- **CWE-1188 (Initialization of a Resource with an Insecure Default):** the auditor exists to find defaults that were never changed; an auditor that inherits a default assumption about a control reports compliance that does not exist.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you check a service setting **THEN** query the effective runtime value (`sshd -T`, `sysctl -n`) rather than parsing a config file, because the last matching directive wins and a file often contains conflicting entries.
2. **IF** a control cannot be evaluated on this host **THEN** emit `not_applicable` or `error` with a reason; never emit `pass`.
3. **IF** you report results **THEN** include the benchmark name and version, the control ID, the observed value, the expected value, and the command used to observe it — a result without its observation is not auditable.
4. **IF** the same audit runs on a schedule **THEN** diff against the stored baseline so the report describes change rather than restating absolute state.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `cis-benchmark-and-baseline-compliance-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable check shapes | [`QUERIES.md`](QUERIES.md) | Effective-value queries, tri-state results, baseline diff |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `sshd -T`, `sysctl -n`, registry reads, testinfra/goss |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | False-pass and benchmark-version incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Remediation-approval handoff |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** read-only host queries (`sshd -T`, `sysctl -n`, mount options, registry/GPO reads) driven from Python 3.11 or PowerShell, with tri-state results and a stored baseline for drift
- **Mandatory Self-Validation Command:** `python -m py_compile cis_audit.py`

1. **Confirm the inputs.** Establish the benchmark name and version, the host OS and role, which controls are in scope, and the expected pass criteria for each. Confirm the audit runs with read-only privileges and that no control executes a mutating command.
2. **Choose the branch.** Single control check → one read plus one comparison. Full benchmark → a control table with per-control query and expectation. Drift report → the same table plus a baseline diff. Platform-specific controls → a `not_applicable` branch per OS rather than a skipped control.
3. **Define how to validate the auditor.** For each control, assert the observed value against a fixture host (or a recorded snapshot) in both a compliant and a non-compliant state, and assert that an unevaluable control produces `not_applicable` rather than `pass`. Verify the audit changed nothing by comparing a host state hash before and after.
4. **Name the stop condition.** Stop when a control's query fails (report `error`, not `pass`), when the benchmark version does not match the control table, when a check would require writing to the host, or when the number of `not_applicable` results exceeds a stated proportion — a mostly-inapplicable report proves nothing.
5. **State what counts as a working tool.** A working auditor exits `0` when every in-scope control evaluated to `pass`, `1` when any control failed, and `2` when the benchmark mapping is missing or the host is unsupported. Every result row carries control ID, observed value, expected value, status, and the command used.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `sshd -T` effective configuration dump | Proves the value in force, not the first or last line of a config file |
| `sysctl -n <key>` runtime read | Proves the applied kernel parameter, after any override |
| Mount options read from the mount table | Proves flags in effect without attempting a remount |
| Tri-state result with `not_applicable` and a reason | Proves unevaluable controls are not counted as compliant |
| Baseline diff between two runs | Proves what changed, which is reviewable, versus an absolute claim |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: greps a config file for the desired value, treats an unreadable
# check as a pass, and reports a boolean per control with no benchmark version.
import pathlib

def check_ssh_root_login():
    text = pathlib.Path("/etc/ssh/sshd_config").read_text()
    if "PermitRootLogin no" in text:
        return True
    return False                  # a later matching directive could still enable it

def check_all():
    results = {}
    for name, fn in {"ssh_root": check_ssh_root_login}.items():
        try:
            results[name] = fn()
        except Exception:
            results[name] = True  # unreadable becomes compliant
    return results
```

**Production-Grade Starter Skeleton (USE):**

```python
# cis_audit.py - Read-only compliance evaluation with tri-state results.
# Exit 0 all pass, 1 any failure, 2 benchmark mapping missing.
import json
import subprocess
import sys

BENCHMARK = "CIS Ubuntu 24.04 LTS Benchmark v2.0.0"

CONTROLS = [
    {"id": "5.1.20", "title": "SSH PermitRootLogin disabled",
     "query": ["sshd", "-T"], "kind": "sshd_option",
     "option": "permitrootlogin", "expected": "no"},
    {"id": "1.1.1.1", "title": "cramfs filesystem disabled",
     "query": ["sh", "-c", "grep -c cramfs /proc/filesystems || true"],
     "kind": "integer_max", "expected": 0},
    {"id": "1.5.1", "title": "ASLR enabled",
     "query": ["sysctl", "-n", "kernel.randomize_va_space"],
     "kind": "exact", "expected": "2"},
]

def run(query: list[str]) -> tuple[int, str]:
    proc = subprocess.run(query, capture_output=True, text=True, timeout=30)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

def evaluate(control: dict) -> dict:
    row = {"benchmark": BENCHMARK, "control": control["id"], "title": control["title"],
           "command": " ".join(control["query"]), "status": "error",
           "observed": None, "expected": control["expected"]}
    try:
        code, output = run(control["query"])
    except (OSError, subprocess.SubprocessError) as exc:
        row["reason"] = str(exc)
        return row
    if code != 0 and control["kind"] == "sshd_option":
        row["status"] = "not_applicable"
        row["reason"] = "sshd not installed or not configurable"
        return row
    kind = control["kind"]
    if kind == "sshd_option":
        observed = None
        for line in output.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == control["option"]:
                observed = parts[1].strip()
                break
        if observed is None:
            row["status"] = "not_applicable"
            row["reason"] = "option not present in effective config"
            return row
        row["observed"] = observed
        row["status"] = "pass" if observed.lower() == str(control["expected"]).lower() else "fail"
        return row
    if kind == "integer_max":
        try:
            observed = int(output.strip().splitlines()[-1])
        except (ValueError, IndexError):
            row["reason"] = f"unparseable output: {output.strip()[:60]!r}"
            return row
        row["observed"] = observed
        row["status"] = "pass" if observed <= int(control["expected"]) else "fail"
        return row
    observed = output.strip()
    row["observed"] = observed
    row["status"] = "pass" if observed == str(control["expected"]) else "fail"
    return row

def main() -> int:
    if not CONTROLS:
        sys.stderr.write("fatal: no controls mapped for this benchmark\n")
        return 2
    rows = [evaluate(control) for control in CONTROLS]
    for row in rows:
        print(json.dumps(row, sort_keys=True))
    failures = sum(1 for row in rows if row["status"] in ("fail", "error"))
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(main())
```

**Why this matters:** every control reads the effective value, an unevaluable control is reported as `not_applicable` or `error` rather than pass, and each row carries the command that produced it — so the report can be audited control by control.

## When It Is NOT This Issue

- **A control passes in the audit but the setting is wrong at runtime** — the check read a config file rather than the effective value; `sshd -T` and `sysctl -n` exist for exactly this reason.
- **The audit reports far more `not_applicable` controls than expected** — the control table is written for a different benchmark version or OS release; remap before drawing conclusions.
- **A previously passing host now fails several controls** — check whether the benchmark version changed, not just the host; control numbering and expected values move between revisions.
- **The auditor requires elevated privileges** — reading some kernel parameters needs root; that is a deployment consideration, not a reason to skip the control silently.
- **A drift report shows constant churn on the same control** — an automated task is changing the setting; the audit is correct and the churn source is the finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER report `pass` for a control that could not be evaluated.
- NEVER mutate a host during an audit; remediation is a separate, approved action.
- NEVER omit the benchmark version from a compliance report.
- NEVER assert a specific control ID or expected value from memory; take it from the benchmark document you are auditing against.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Benchmark name/version, host OS and role, and in-scope controls for `cis-benchmark-and-baseline-compliance-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The check, tri-state handling, or diff is specific and runnable (no generic 'harden the host' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: cis-benchmark-and-baseline-compliance-scripting
- **Target Stack & Schema**: read-only host queries (sshd -T, sysctl -n, registry) with tri-state JSON results and a stored baseline
- **Safety, Scope & Exit-Code Guards**: [Read-only enforcement, not_applicable honesty, benchmark version recorded, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Effective vs file value, benchmark revision drift, privilege requirements, benign churn]
- **Implementation**:
  [Runnable auditor following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile cis_audit.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`iac-rego-opa-and-checkov-policy-development`](../iac-rego-opa-and-checkov-policy-development/SKILL.md) - The build-time counterpart that prevents insecure defaults
- [`osquery-extension-and-pack-development`](../osquery-extension-and-pack-development/SKILL.md) - Fleet query surface that can carry these checks at scale
- [`purple-team-telemetry-validation-harnesses`](../purple-team-telemetry-validation-harnesses/SKILL.md) - Proves the telemetry controls actually emit
- [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) - Same inventory-diff discipline for detection content

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cis-benchmark-and-baseline-compliance-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1188`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
