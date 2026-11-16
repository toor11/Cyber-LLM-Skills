---
name: custom-secret-scanner-detector-engineering
description: "Authors high-precision secret-scanning detectors (Gitleaks TOML rules + Python Git-diff/archive scanners): combining prefix anchors, token-charset regexes, Shannon entropy floors, test/fixture path allowlists, and redacted SHA-256 secret fingerprinting so raw secrets are never written to logs. Use when building custom secret detection tools."
family: security-automation-and-tool-development
tier: core
triggers: ["gitleaks rule toml", "custom secret scanner", "shannon entropy secret", "redacted secret hash"]
cwe: [CWE-798]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Custom Secret Scanner Detector Engineering - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A secret detector is a precision instrument, and its precision comes from staged filtering rather than from one clever regex. Gitleaks applies a documented four-stage pipeline: an Aho-Corasick keyword prefilter (rules only run when a keyword is present), the rule regex with an optional `secretGroup` capture, a Shannon entropy floor on the captured secret, and per-rule allowlists that can match against `secret`, `match`, or `line` via `regexTarget`. Everything except the regex is a false-positive control, which is why a rule without `keywords`, `entropy`, or an allowlist is a noise generator no matter how good the pattern is. The second half of the discipline is output safety: a scanner that prints the matched secret turns the detection tool into a credential leak, so findings must carry a salted or redacted SHA-256 fingerprint of the secret plus file, line, rule ID, and commit — enough to triage and correlate, never enough to reuse. A custom Python scanner over `git log -p` or archive members applies the same staging: prefilter, regex, entropy floor, path allowlist, redacted output.

- **CWE-798 (Use of Hard-coded Credentials):** the weakness being detected; the scanner's job is to find it without reproducing the credential.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are writing a Gitleaks rule **THEN** include `id`, `regex` (Go RE2, no lookarounds), `secretGroup`, `keywords`, an `entropy` floor, and at least one `[[rules.allowlists]]` entry; a rule with no keyword or entropy is incomplete.
2. **IF** the target content is a token with a fixed prefix (AWS `AKIA`, GitHub `ghp_`) **THEN** anchor on the prefix and set entropy low, because the structure already discriminates; reserve entropy floors for unstructured high-entropy strings.
3. **IF** the secret appears in tests, fixtures, or documentation **THEN** scope an allowlist by path or `regexTarget = "line"` rather than disabling the rule; a disabled rule hides production leaks.
4. **IF** you write a Python scanner over `git log -p` **THEN** stream the diff, stop at `+++ b/` boundaries, and emit `sha256(secret)[:16]` plus location — never the secret itself.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `custom-secret-scanner-detector-engineering` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable rule and scanner shapes | [`QUERIES.md`](QUERIES.md) | Gitleaks TOML, `git log -p` pipeline, entropy maths |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `gitleaks detect`/`dir`, config schema keys |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Leaked-secret-in-output and fixture-noise incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Rotation handoff when a live credential is confirmed |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Gitleaks 8.x TOML rules (`id`, `regex`, `secretGroup`, `entropy`, `keywords`, `[[rules.allowlists]]` with `regexTarget`) plus a Python 3.11 streamer over `git log -p` for cases the CLI cannot express
- **Mandatory Self-Validation Command:** `python -m py_compile secret_scan.py`

1. **Confirm the inputs.** Identify the credential format and at least one real example structure (prefix, length, charset), the scan target (working tree, full history, archive), and the legitimate placeholder patterns that will appear in tests and docs. Confirm that findings will be stored somewhere with an access policy — the output is itself sensitive.
2. **Choose the branch.** Known-prefix token → anchored regex with low entropy. Unstructured high-entropy string → keyword prefilter plus a higher entropy floor. History scan → `git log -p` streaming with commit attribution. Archive scan → per-member extraction with a size cap.
3. **Define how to validate the detector.** A three-fixture differential: a synthetic secret that must match, a placeholder in the same shape that must not match, and a `gitleaks:allow`-annotated or path-excluded line that must not match. Then confirm the emitted record contains a fingerprint and no plaintext secret — grep the output for the secret string and assert zero hits.
4. **Name the stop condition.** Stop when the secret appears verbatim anywhere in the scanner output, when the placeholder fixture matches, when the entropy floor admits a repeated-character string, or when an allowlist suppresses a production path instead of a fixture path.
5. **State what counts as a working tool.** A working detector exits `0` when no findings, `1` when findings exist, `2` on a config parse error or unreadable target; every finding carries rule ID, file, line, commit (when applicable), and a redacted hash, and the raw secret is never written to disk or stdout.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `keywords` prefilter in the TOML rule | Proves the regex only runs on candidate content, which keeps large-repo scans tractable |
| `entropy` floor on the captured `secretGroup` | Proves low-entropy placeholders (`AKIAIOSFODNN7EXAMPLE`) are rejected structurally, not by name |
| `[[rules.allowlists]]` with `regexTarget = "line"` or `paths` | Proves exclusions are scoped to fixtures/docs rather than to the rule as a whole |
| Redacted `sha256(secret)[:16]` in the finding | Proves a finding can be correlated across runs without exposing the credential |
| Three-fixture differential (real / placeholder / excluded) | Proves precision and recall in one run, which single-fixture tests cannot show |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: one greedy regex, no entropy floor, no allowlist, and the matched secret printed verbatim
import re
import subprocess

PATTERN = re.compile(r"(?i)(api[_-]?key|token|secret)\s*[=:]\s*(\S{6,})")

def scan():
    diff = subprocess.run(["git", "log", "-p"], capture_output=True, text=True).stdout
    for n, line in enumerate(diff.splitlines(), 1):
        m = PATTERN.search(line)
        if m:
            print(f"line {n}: {m.group(0)}")     # leaks the credential into CI logs
```

**Production-Grade Starter Skeleton (USE):**

```python
# secret_scan.py - Exit 0 no findings, 1 findings, 2 config/target error. Never prints a raw secret.
import hashlib
import json
import math
import pathlib
import re
import subprocess
import sys

RULES = [
    {
        "id": "generic-api-key",
        "keywords": ("api", "token", "secret", "password"),
        "regex": re.compile(r"(?i)(?:api[_-]?key|token|secret|password)\s*[=:]\s*['\"]?([0-9A-Za-z\-_.=]{16,64})"),
        "secret_group": 1,
        "entropy": 3.5,
        "allow_paths": re.compile(r"(^|/)(tests?|fixtures?|docs?|examples?)/"),
    },
    {
        "id": "aws-access-key-id",
        "keywords": ("akia", "asia", "abia", "acca"),
        "regex": re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"),
        "secret_group": 1,
        "entropy": 3.0,
        "allow_paths": re.compile(r"(^|/)tests?/"),
    },
]

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def redact(secret: str, salt: str) -> str:
    return hashlib.sha256((salt + secret).encode("utf-8")).hexdigest()[:16]

def scan_text(path: str, text: str, salt: str) -> list[dict]:
    findings = []
    for rule in RULES:
        if rule["allow_paths"].search(path):
            continue
        lowered = text.lower()
        if not any(k in lowered for k in rule["keywords"]):
            continue
        for match in rule["regex"].finditer(text):
            secret = match.group(rule["secret_group"])
            if shannon_entropy(secret) < rule["entropy"]:
                continue
            findings.append({
                "rule": rule["id"],
                "path": path,
                "secret_sha256_16": redact(secret, salt),
                "secret_length": len(secret),
            })
    return findings

def scan_history(salt: str, cwd: pathlib.Path) -> list[dict]:
    diff = subprocess.run(
        ["git", "-C", str(cwd), "log", "-p", "--no-color", "--all"],
        capture_output=True, text=True, check=True,
    ).stdout
    findings, current = [], "<unknown>"
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:].strip()
            continue
        if line.startswith(("+++", "---", "@@", "index ", "commit ", "diff ")):
            continue
        for finding in scan_text(current, line, salt):
            findings.append(finding)
    return findings

def main() -> int:
    salt = "site-specific-salt"           # replace with a value from the secret store
    try:
        findings = scan_history(salt, pathlib.Path("."))
    except (subprocess.CalledProcessError, OSError) as exc:
        sys.stderr.write(f"fatal: {exc}\n")
        return 2
    for finding in findings:
        print(json.dumps(finding))
    return 1 if findings else 0

if __name__ == "__main__":
    raise SystemExit(main())
```

**Why this matters:** the keyword prefilter, the entropy floor, and the path allowlist each remove a different class of false positive, and the finding carries a salted hash instead of the credential, so the report can be shared without becoming a second leak.

## When It Is NOT This Issue

- **A finding appears in a test fixture** — that is what path allowlists are for; disabling the rule instead loses production coverage.
- **The same secret reports on every commit** — history scanning matches the adding commit and every later diff context; deduplicate by `secret_sha256_16` and report the earliest introducing commit.
- **A high-entropy string matches but is not a credential** — base64 blobs, hashes in lockfiles, and minified bundles are structurally identical to secrets; a contextual keyword or path exclusion is the fix, not raising entropy until real secrets are missed.
- **`gitleaks:allow` on a line suppresses it** — that is the documented inline suppression, and `--ignore-gitleaks-allow` exists to override it; treating it as a scanner bug leads to removing a legitimate escape hatch.
- **A rule with a lookaround fails to compile** — Go's RE2 has no lookarounds; the pattern must be rewritten, not run under a different engine.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER print, log, or commit a raw detected secret; findings carry a redacted hash and location only.
- NEVER write a Gitleaks rule using lookarounds or backreferences — the pattern is compiled with Go's RE2 engine.
- NEVER claim a detector is precise because it matched a sample; precision is proven by the placeholder and excluded-path fixtures staying silent.
- NEVER disable a rule to silence a fixture; scope the allowlist by path or `regexTarget`.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Credential format, scan target, and legitimate placeholder patterns for `custom-secret-scanner-detector-engineering` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The rule, scanner, or allowlist is specific and runnable (no generic 'scan for secrets' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: custom-secret-scanner-detector-engineering
- **Target Stack & Schema**: Gitleaks 8.x TOML rules plus a Python 3.11 history streamer with redacted output
- **Safety, Scope & Exit-Code Guards**: [Path allowlists, output redaction, entropy floors, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Placeholder fixtures, lockfile hashes, inline gitleaks:allow, duplicate history hits]
- **Implementation**:
  [Runnable rule or scanner following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile secret_scan.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ci-cd-security-gate-and-sarif-tooling`](../ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Consumes these findings as a PR gate
- [`sbom-cyclonedx-and-cve-reachability-tooling`](../sbom-cyclonedx-and-cve-reachability-tooling/SKILL.md) - The dependency half of the supply-chain review
- [`iac-rego-opa-and-checkov-policy-development`](../iac-rego-opa-and-checkov-policy-development/SKILL.md) - Prevents hardcoded values at the infrastructure layer
- [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md) - Same repository-scanning discipline for detection content

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `custom-secret-scanner-detector-engineering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-798`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
