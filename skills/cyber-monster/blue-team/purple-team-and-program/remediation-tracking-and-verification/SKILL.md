---
name: remediation-tracking-and-verification
description: "Tracks remediation to verified closure: finding ownership, SLA management, evidence of fix and retest discipline. Use when ensuring reported issues actually get fixed."
family: purple-team-and-program
tier: core
triggers: ["remediation tracking", "retest", "fix verification", "sla tracking"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, security-program-and-control-frameworks, control-testing-and-audit-evidence, risk-assessment-and-treatment]
---

# Remediation Tracking and Verification - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

Remediation tracking is the difference between a list of intentions and a measurable reduction in exposure: every item has an owner, a date, a verification method, and closure evidence that the condition no longer exists. The failure mode is closure by ticket status - an item marked done because someone said so, while the asset still exhibits the condition. Good tracking therefore defines closure as a re-test result, and treats an ageing exception as an item that reappears rather than one that quietly persists.

- **CWE-693 framing:** the measure is whether the protection now works, so verification is a property of the control rather than of the change record.
- Verification methods differ by finding class: a configuration finding needs a re-read of the effective config, a patch needs an asset-reported version, a code finding needs a clean scan of the fixed commit.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the finding is a KEV item on an exposed asset **THEN** `cisa-kev-emergency-triage-workflow` owns the clock and this skill owns the record.
2. **IF** the item is being deferred **THEN** open `vulnerability-management-triage-exception-handling` for the exception structure.
3. **IF** the remediation changed a control baseline **THEN** pair this with `configuration-baselines-and-cis` so drift detection covers it.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Define closure per finding class before tracking begins.** Configuration: effective config re-read. Patch: asset-reported version. Code: scan of the fixed commit. Access: entitlement query. A tracker without class-specific closure rules will close on ticket status.
2. **Assign an owner and a date derived from evidence, not from severity.** KEV membership and exposure set the date; severity alone does not.
3. **Choose the branch on the verification outcome.** Verified clean takes the close branch; verification not run takes the pending branch; verification failed takes the reopen branch with the failed artefact.
4. **Define the baseline-vs-probe differential.** Baseline: the original evidence that opened the item. Probe: the same check re-run after the change. Closure requires the probe to differ from the baseline in the direction that shows the condition is gone.
5. **State the stop condition and the proof.** Stop when every closed item has a probe result stored against it; proof is that artefact, not the approver's name.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Item closed with the change ticket and no re-test | Proves closure by assertion; the condition may persist and the next scan reopens it. |
| Patch item verified with the asset-reported version | Proves the running artefact changed, which is the only closure evidence that survives a rebuild. |
| Code finding closed on a scan of the fixed commit | Proves the specific rule no longer matches, which is tighter than a clean overall scan. |
| Configuration item whose verification reads the effective config | Proves the deployed value changed rather than the repository template. |

## Worked Contrast

**Closure recorded from the change ticket:**

```yaml
id: SEC-5512
finding: TLS 1.0 enabled on load balancer
change: CHG-9981 applied
status: closed
closed_by: engineer
closed_at: 2026-10-20
verification: none
```

**Closure with a class-specific probe and its artefact:**

```yaml
id: SEC-5512
finding: TLS 1.0 enabled on load balancer
class: configuration
change: CHG-9981 applied 2026-10-20
closure_rule: re-read effective listener policy
baseline_evidence: openssl s_client -connect lb:443 -tls1 -> handshake OK (2026-10-12)
probe:
  command: openssl s_client -connect lb:443 -tls1
  result: handshake failure (protocol version)
  captured: evidence/SEC-5512/probe-2026-10-21.txt
  run_at: 2026-10-21T08:12:00Z
status: closed_verified
owner: network-security
reopen_if: listener policy changes or a new listener is added
```

**Why this matters:** The first record proves a change was applied and nothing about the condition, so the item is closed while TLS 1.0 may still be accepted on a second listener. The second defines the closure rule by class, keeps the baseline evidence that opened it, and stores a probe that fails in the expected direction - which is what allows an auditor to re-run the check.

## When It Is NOT This Issue

- **Item closed because the asset was decommissioned.** Legitimate closure; the evidence is the decommission record, not a probe.
- **Verification failing because the probe targets a different listener or host.** That is a probe defect; re-run against the asset named in the finding.
- **Finding that is a duplicate of another item.** Close as duplicate with the surviving id, not as verified.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `ownership` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `remediation-tracking-and-verification` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: remediation-tracking-and-verification
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-693 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) - Purple Team and Program (core)
- [`security-program-and-control-frameworks`](../security-program-and-control-frameworks/SKILL.md) - Purple Team and Program (core)
- [`control-testing-and-audit-evidence`](../control-testing-and-audit-evidence/SKILL.md) - Purple Team and Program (core)
- [`risk-assessment-and-treatment`](../risk-assessment-and-treatment/SKILL.md) - Purple Team and Program (core)
- [`compliance-mapping-and-reporting`](../compliance-mapping-and-reporting/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `remediation-tracking-and-verification` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/gh_advisories (3), CYBER_CPT/expku (1), CYBER_CPT/hacker_recipes (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
