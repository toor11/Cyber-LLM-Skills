---
name: bug-bounty-and-vdp-workflow
description: "Runs a disciplined bug bounty engagement: scope triage, target prioritization, methodology selection, duplicate avoidance, impact-first reporting and programme-specific rules. Use when working a VDP or bounty programme and deciding what to test and how to report it."
family: web-and-application
tier: core
triggers: ["bug bounty", "vdp", "disclosure programme", "bounty workflow", "scope triage", "report submission"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Bug Bounty and Vdp Workflow - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A bug bounty or vulnerability disclosure programme defines an authorization boundary in the form of a scope list and rules of engagement, and the workflow's job is to keep testing inside that boundary and to route effort toward in-scope, high-impact, non-duplicate findings. The decision points are the scope gate, which determines whether a given host or asset is authorised to test, and the triage gate, which determines whether an observed behaviour is a valid, impactful, novel finding or a self-only, out-of-scope, or duplicate non-finding. Getting either wrong wastes effort or, worse, tests an asset the programme never authorised. The researcher gains accepted, paid, or acknowledged reports when the workflow enforces these gates; confirmation of a valid finding is always a reproducible effect that crosses a trust boundary between the researcher's own test accounts rather than a cosmetic or self-contained observation.

- **Precondition chain:** a programme publishes a scope and rules, a candidate asset or finding must be matched against that scope and against known duplicates, and only a reproducible cross-boundary impact inside the authorised envelope counts as a valid submission.
- **Readable differential:** a candidate asset or finding evaluated against the normalised scope and impact rules versus one assumed in-scope and impactful; reverting the assumption shows whether the target is actually authorised and whether the behaviour is a real cross-boundary issue rather than a self-only artefact.
- **Empirical grounding:** The anchoring taxonomy is CWE-20 Improper Input Validation framed through disclosed-programme methodology, OWASP WSTG testing procedures, and the OWASP API Security Top 10:2023 for impact classification; SOURCES had no programme-specific advisory, so this slug stays at the methodology and taxonomy level without inventing a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the task is enumerating which hosts under a wildcard are actually in scope **THEN** resolve the scope boundary first and read [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md)
2. **IF** a candidate asset matches the scope only by a substring of the domain **THEN** reject it until it matches by exact host or registrable domain against the allowlist
3. **IF** the engagement is a contracted pentest rather than an open bounty **THEN** switch to [`web-pentest-engagement-workflow`](../web-pentest-engagement-workflow/SKILL.md) for a rules-of-engagement model
4. **IF** the candidate is a published CVE you want to reproduce on the target **THEN** route to [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md) for safe reproduction and provenance
5. **IF** the behaviour affects only the researcher's own account **THEN** classify it as self-only and do not submit it as a cross-user finding
6. **IF** the finding may already be reported by the programme **THEN** run a duplicate check against disclosed reports before writing the submission
7. **IF** the programme requires a custom identification header on all test traffic **THEN** attach the required header so the activity is attributable within the rules
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the asset is out of scope or the effect never crosses another account **THEN** STOP and record a verified non-finding rather than submitting an invalid report

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Task is enumerating which wildcard hosts are in scope | [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) | Invariant is scope-boundary resolution before any probing |
| Engagement is a contracted pentest, not an open bounty | [`web-pentest-engagement-workflow`](../web-pentest-engagement-workflow/SKILL.md) | Invariant is a contracted rules-of-engagement model |
| Candidate is a published CVE to reproduce on the target | [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md) | Invariant is PoC provenance and safe reproduction |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the programme policy and extract the authoritative scope.** Capture the structured-scopes list, wildcard entries, explicit out-of-scope assets, and the rules of engagement. The scope list is the sink that every candidate target is checked against, so normalise it before testing anything.
2. **Classify the candidate as an asset decision or a finding decision.** Enumerating hosts to test is a scope question; evaluating an observed behaviour is a triage question. Each gate has different inputs, so decide which you are at before acting.
3. **Resolve the scope boundary precisely.** For a wildcard such as `*.example.com`, match candidate hosts by registrable domain rather than substring so look-alike or attacker-suffixed domains are excluded. A host that only matches by containment is out of scope.
4. **Record an in-scope, intended-behaviour baseline on your own test accounts.** For a candidate finding, capture the normal response and the normal state before probing, using accounts you control so no real user is involved.
5. **Apply the one-variable probe and check for cross-boundary impact.** Change the single element under test and observe whether the effect reaches a second test account or tenant rather than only your own session. Self-only effects are not valid regardless of how surprising they look.
6. **Stop condition.** Halt when the candidate either (a) is in scope and produces a reproducible cross-account impact, (b) is out of scope or affects only the researcher's own account, or (c) would require acting against real users or destructive operations to advance. Case (a) is a reportable finding, (b) is a non-finding, (c) is outside the rules of engagement.
7. **State what counts as proof.** Proof is a minimal reproduction that crosses a trust boundary between the researcher's own test accounts, the exact scope entry that authorises the target, and a duplicate check showing the issue is novel, assembled as an impact-first report. A policy-violation observation or a self-only quirk is not proof.
8. **Close with the structural control and verify it.** Encode the scope as an allowlist matched on registrable domain, require a cross-account reproduction and a duplicate check before submission, and attach any mandated identification header; verify by re-running the scope check on every candidate host before testing resumes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A programme `structured-scopes` entry marking an asset in or out of scope | Proves which targets are authorised on HackerOne or Bugcrowd, the boundary all testing must respect |
| A wildcard scope entry such as `*.example.com` | Proves the breadth of authorised hosts but requires registrable-domain matching to exclude look-alikes |
| A finding whose signature matches an already-resolved public report | Proves a likely duplicate, which changes the triage outcome rather than validity |
| A proof of concept that affects only the researcher's own account | Proves a self-only scenario that most programmes treat as a non-finding |
| A safe-harbor or rules-of-engagement clause in the policy | Proves the authorised testing envelope and the non-destructive requirements |
| An impact statement tying the bug to a cross-account or cross-tenant effect | Proves business impact, the field that drives severity and payout |

## Worked Contrast

**Vulnerable pattern:**

```python
SCOPE = ["example.com", "api.example.com"]


def in_scope(target_host):
    # Substring match: notexample.com and example.com.evil.net both pass
    return any(entry in target_host for entry in SCOPE)
```

**Hardened pattern:**

```python
from urllib.parse import urlsplit

SCOPE = {"example.com", "api.example.com"}
WILDCARDS = {"example.com"}  # authorises *.example.com


def registrable(host):
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def in_scope(target):
    host = urlsplit("//" + target).hostname or ""
    host = host.lower().strip(".")
    return host in SCOPE or registrable(host) in WILDCARDS
```

**Why this matters:** The defect authorises any host that merely contains a scope string, so look-alike and attacker-suffixed domains pass the gate and risk unauthorised testing. The control parses the host and matches it exactly or by registrable domain against the allowlist, keeping testing inside the programme's authorised boundary.

## When It Is NOT This Issue

- **Self-only proof of concept:** a scenario that affects only the researcher's own account, such as self-XSS or a self-reset, is not a valid cross-user finding.
- **Out-of-scope asset:** a technically valid issue on a marketing subdomain or any asset the programme marks out of scope cannot be accepted regardless of severity.
- **Known duplicate:** a finding matching an already-resolved report is valid behaviour to report but is triaged as a duplicate, not a new award.
- **Test-environment artefact:** a result reproducible only in a sandbox or seeded demo tenant does not demonstrate production impact.
- **Best-practice or informational note:** a missing header or a theoretical weakness with no demonstrated impact is informational rather than a finding.
- **Policy violation observation:** noticing that the programme itself breaks a rule is not a vulnerability in an in-scope asset.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `bug-bounty-and-vdp-workflow` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `bug-bounty-and-vdp-workflow` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: bug-bounty-and-vdp-workflow
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `bug-bounty-and-vdp-workflow` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 53 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (31), hackerone_disclosed_reports (12), bugbounty-hunter-v1 (9), SecEval/windows_security (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
