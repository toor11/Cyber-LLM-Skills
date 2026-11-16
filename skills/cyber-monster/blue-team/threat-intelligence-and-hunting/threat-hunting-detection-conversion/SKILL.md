---
name: threat-hunting-detection-conversion
description: Converting hunts into detections. Covers turning a successful hunt into a durable detection rule with tuning and documentation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["hunt to detection", "convert hunt", "detection from hunt"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-hunting, threat-hunting-hypothesis-and-scoping, threat-hunting-hunt-execution-and-triage, threat-intelligence-and-cti]
parent: threat-hunting
---

# Threat Hunting Detection Conversion - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Conversion turns a hunt finding into something that runs without a human: a rule with a stable identity, a documented baseline, a false-positive list derived from the hunt, and a test case. The hard part is not the query syntax - it is preserving the context that made the hunt conclusive, because the rule will run for years against an estate that changes. Sigma's correlation rules (specification 2.1.0, released 2 August 2025) give the portable structure for multi-event logic that a single-event rule cannot express.

- **CWE-778 framing:** a rule without a false-positive list is a future alert-fatigue source; the list is part of the detection, not documentation.
- Sigma correlation types are `event_count`, `value_count`, `temporal`, `temporal_ordered`, plus the value aggregation variants; choosing the wrong type is the most common portability failure.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the hunt has not produced a clustered, dispositioned result **THEN** go back to `threat-hunting-hunt-execution-and-triage`.
2. **IF** the finding is a single indicator rather than behaviour **THEN** open `indicator-lifecycle-and-ioc-management`, since a behaviour rule outlives an indicator.
3. **IF** the estate is primarily one SIEM **THEN** still write the rule in a portable form first and convert, so the rule survives a platform change.
4. **IF** the target narrows to `threat-hunting` **THEN** open [`threat-hunting`](../threat-hunting/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`threat-hunting`](../threat-hunting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Extract the analytic from the hunt, not the query.** State what makes the pattern malicious: the parent-child relationship, the sequence, the rare field combination. The query is an implementation of that statement and may need to change per platform.
2. **Choose the rule type on the event structure.** Single event takes a selection rule; count or rate takes an `event_count` correlation; sequence takes `temporal_ordered`; distinct-value breadth takes `value_count`.
3. **Derive the false-positive list from the hunt's own baseline clusters.** Each baseline cluster becomes a filter or a documented exception with an owner, rather than a note that the rule is noisy.
4. **Define the baseline-vs-probe differential for the rule.** Baseline: the rule produces zero (or the documented count) over the last full window on production data. Probe: a replay of the confirmed hunt events must fire. A rule that cannot reproduce its own hunt is not ready.
5. **State the stop condition and the proof.** Stop when the rule fires on the replay, is quiet on production baseline, and carries its false-positive list and owner; proof is the two run results plus the rule's metadata block.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Rule with a stable id and a version-controlled file | Proves the detection has identity, so tuning history and exceptions attach to something durable. |
| False-positive list derived from hunt baseline clusters | Proves the rule was tuned against reality rather than intuition. |
| Correlation rule with explicit `timespan` and `group-by` | Proves sequence logic is portable; a hand-written join rarely survives a backend change. |
| Replay of the original hunt events fires the rule | Proves the conversion preserved the analytic rather than approximating it. |

## Worked Contrast

**Conversion that copies the hunt query into the SIEM as a scheduled search:**

```yaml
title: Suspicious PowerShell
search: index=win EventCode=4104 (encoded OR bypass OR downloadstring)
schedule: every 15m
severity: high
# no id, no false positives, no owner, no test
```

**Portable rule with identity, derived false positives, and a replay test:**

```yaml
title: Office Process Spawns Proxy Execution Chain to Outbound Connection
id: 88f1c2a4-5b7e-4c31-9a1d-2f0c1e7d9b10
status: test
level: high
description: >
  Word spawning a script host which spawns a signed proxy binary, followed by an
  outbound connection owned by that chain. Derived from hunt H-2026-31.
logsource: {product: windows, category: process_creation}
detection:
  selection_parent:
    ParentImage|endswith: ['\WINWORD.EXE', '\EXCEL.EXE']
  selection_proxy:
    Image|endswith: ['\rundll32.exe', '\regsvr32.exe', '\mshta.exe']
  condition: selection_parent and selection_proxy
falsepositives:
  - finance macro workbook signed by IT (owner: finance-apps, review 2027-01-31)
  - patch-manager helper (parent svc-patchmgr.exe, excluded in the correlation below)
---
title: Proxy Chain Followed by Outbound Connection
id: 5d2b8c11-0e4a-4f77-8a3c-7b1d9e0f2a44
correlation:
  type: temporal_ordered
  rules: [88f1c2a4-5b7e-4c31-9a1d-2f0c1e7d9b10, outbound-after-proxy]
  group-by: [host]
  timespan: 10m
```

**Why this matters:** The first artefact is a saved search: no identity, no false-positive basis, no owner, and no way to tell whether it still matches after a log-source change. The second carries an id, a description that states the analytic, false positives derived from the hunt's real baseline clusters with owners, and a correlation rule for the sequence - which is what makes it maintainable and portable.

## When It Is NOT This Issue

- **Rule that fires only on the original hunt window.** That is overfitting to the incident; re-test against a broader benign window before enabling.
- **False positive documented as 'admin activity'.** An unnamed activity is not a filter; name the process, account pattern, or path so the rule can exclude it precisely.
- **Correlation used for a single-event pattern.** Over-structuring adds latency and fragility; use a selection rule when one event carries the signal.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `rule authoring` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-hunting-detection-conversion` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: threat-hunting-detection-conversion
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting-hypothesis-and-scoping`](../threat-hunting-hypothesis-and-scoping/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-hunting-hunt-execution-and-triage`](../threat-hunting-hunt-execution-and-triage/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-hunting-detection-conversion` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/hacktricks (2), CYBER_CPT/ctf_search (1), CYBER_CPT/awesome_list (1), CYBER_CPT/blackhills (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
