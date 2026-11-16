---
name: sigma-rule-authoring
description: "Writes and validates Sigma rules: log source selection, field mapping, condition logic, filters and conversion to backend query languages. Use when authoring vendor-neutral detection rules."
family: detection-and-monitoring
tier: core
triggers: ["sigma rule", "sigma authoring", "write sigma", "sigma conversion"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [sigma-rule-authoring-windows-event-rules, sigma-rule-authoring-cloud-and-network-rules, detection-engineering, yara-rule-authoring]
---

# Sigma Rule Authoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

A Sigma rule is a YAML document whose portability comes from separating the *logsource* from the *detection logic*: the logsource names a generic source (`category: process_creation`, `product: windows`), and a backend pipeline maps that promise onto whatever the query language and schema actually provide. Everything that makes a rule portable also makes it fragile. If the pipeline has no mapping for that category, conversion emits a query that runs and matches nothing. Field names in the detection block must be Sigma's own field names, with the pipeline performing the rename; writing ECS or vendor names directly defeats the abstraction and breaks on the next backend. Conditions use a small algebra (`and`, `or`, `not`, wildcards, `1 of`, `all of them`, `|` field modifiers such as `contains` and `endswith`), and the specification's correlation section adds group-level logic (`event_count`, `value_count`, `temporal`, `temporal_ordered`, plus the metric types `value_sum`, `value_avg`, `value_percentile`, `value_median` added in v2.1.0). Multi-document YAML is used for a base rule plus its correlation rule, and only the outermost correlation rule may carry the meta fields.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves `windows-event-rules` **THEN** switch to [`sigma-rule-authoring-windows-event-rules`](../sigma-rule-authoring-windows-event-rules/SKILL.md) (1 hop).
2. **IF** the target specifically involves `cloud-and-network-rules` **THEN** switch to [`sigma-rule-authoring-cloud-and-network-rules`](../sigma-rule-authoring-cloud-and-network-rules/SKILL.md) (1 hop).
3. **IF** the rule needs a threshold or an ordering across events **THEN** author a base rule plus a correlation rule in one multi-document file, and **IF** you do **THEN** keep the meta fields on the outermost correlation rule only.
4. **IF** you are choosing a logsource category **THEN** pick the category the pipeline actually maps for your backend, and verify with a conversion rather than assuming; an unmapped category converts cleanly into a query that can never match.
5. **IF** a field name comes from a specific vendor schema **THEN** replace it with the Sigma field name and let a processing pipeline perform the rename, or the rule is bound to one backend.
6. **IF** telemetry source covering `logsource` or `condition` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `sigma-rule-authoring-windows-event-rules` | [`sigma-rule-authoring-windows-event-rules`](../sigma-rule-authoring-windows-event-rules/SKILL.md) | Event IDs, Sysmon schema, PowerShell channels |
| Target matches `sigma-rule-authoring-cloud-and-network-rules` | [`sigma-rule-authoring-cloud-and-network-rules`](../sigma-rule-authoring-cloud-and-network-rules/SKILL.md) | CloudTrail, proxy, DNS and Zeek fields |
| Need validity, mapping and conversion queries | [`QUERIES.md`](QUERIES.md) | Lint, pipeline and correlation classes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | `sigma check`, `convert`, `pySigma` in-process use |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need the technique IDs a rule claims | [`mitre-attack-mapping`](../mitre-attack-mapping/SKILL.md) | `attack.tXXXX` tags must defend against the definition |

## Procedure

1. **Confirm the logsource exists in the target backend before writing logic.** Convert a one-line probe rule for the intended category and inspect the generated query. If the pipeline produced an unmapped placeholder or an always-false clause, the category is wrong for that backend and no amount of detection logic will help.
2. **Choose the branch: single-event, correlation, or filter-first.** Single-event rules select on one record. Correlation rules reference base rules by `name` or `id` and add `group-by`, `timespan` and a condition. Filter-first rules start from `falsepositives` and build exclusions before adding selections, which is the right order for noisy categories.
3. **Define the baseline-versus-probe differential against a real corpus.** Convert the rule, run it across a quiet 7-day window and a positive replay, and compare hit counts per host. A rule that produces thousands of benign hits in the quiet window is not ready regardless of how precise it looks in the editor.
4. **Name the stop condition.** Stop when the logsource category has no pipeline mapping, when a required field has no Sigma equivalent, when the condition cannot express the needed grouping (that is a correlation rule, not a selection tweak), when a modifier is unsupported by the target backend, or when the only way to make it fire is to hard-code a vendor field name.
5. **State what counts as proof.** Proof is a converted rule that fires on a positive replay and stays quiet on the baseline corpus, with the conversion command, the backend, and the pySigma version recorded. A rule that validates without a conversion check has proven only its YAML syntax.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| `sigma check` exit status and error count | validity | The YAML, spec conformance and required meta fields are intact before any conversion |
| Converted query text for a probe rule per category | pipeline mapping | Whether the backend's pipeline knows that category, or silently produces an unmatchable clause |
| Hit count per host on a quiet corpus | baseline differential | The rule's real noise level, which no editor preview shows |
| Correlation rule with `group-by` and `timespan` | correlation | A threshold or ordering claim, which a single-event condition cannot express |
| `falsepositives` entries that map to concrete filter conditions | exclusion design | Whether the documented exclusions are implemented rather than aspirational |
| Field name absent from the pipeline mapping table | portability | The rule is bound to one backend and will not survive conversion to another |
| `attack.tXXXX` tags matched against the technique definition | taxonomy | Whether the claimed technique is actually evidenced by the selection |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```yaml
# WEAK: portable in appearance only.
title: Suspicious Command
logsource:
  product: windows
detection:
  sel:
    EventID: 1
    CommandLine|contains: 'whoami'
  condition: sel
level: high
# No category, so no pipeline can map it to a process-creation source.
# Vendor-specific EventID inside the logic instead of a category promise.
# 'whoami' appears in every provisioning script, and no falsepositives exist.
```

**High-Signal Grounded Artifact:**

```yaml
title: Reconnaissance Commands Followed by Encoded PowerShell
id: 6b1f4f2e-3c1a-4c77-9d0e-2f5a8a1c9e10
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_recon:
    Image|endswith:
      - '\whoami.exe'
      - '\net.exe'
      - '\systeminfo.exe'
  selection_encoded:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - ' -enc'
      - 'FromBase64String'
  condition: selection_recon and selection_encoded
falsepositives:
  - Provisioning and imaging tooling that runs recon then invokes a packaged script
level: medium
tags:
  - attack.discovery
  - attack.t1033
---
title: Recon Then Encoded PowerShell On Same Host
id: 9c2f7f10-4d61-4a3e-8f52-1b7d3e0c4a21
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - Reconnaissance Commands Followed by Encoded PowerShell
  group-by:
    - ComputerName
    - User
  timespan: 10m
```

**Why this matters:** the weak rule names a product but no category, so the pipeline has nothing to map and embeds a vendor event ID in the logic. The strong pair separates the single-event selection from the ordering claim, uses category-based logsources and Sigma field modifiers, and puts the meta fields where the specification allows them — on the outermost correlation document.

## When It Is NOT This Issue

- **Category with no pipeline mapping:** the rule converts without error into a query that cannot match. The symptom is a rule that validates, deploys, and never fires — check the converted text, not the YAML.
- **Vendor field names inside the detection block:** these bind the rule to one backend, and conversion to another either drops the clause or leaves a field the target schema does not have.
- **Threshold expressed as a selection:** a single-event condition cannot count or order. Attempting it produces either no matches or matches on the wrong grain; the answer is a correlation rule.
- **Meta fields on a base document in a multi-document file:** the specification places them on the outermost correlation rule. Some tooling accepts the duplication; others resolve the wrong title and the rule appears to vanish from the corpus.
- **`falsepositives` written as prose:** an entry that says "legitimate admin activity" is not an exclusion. If no condition implements it, the noise remains and the field documents an intention rather than a control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER invent logsource categories, field modifiers, or correlation types** that are not in the specification version you are targeting.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `logsource` was disabled, rotated out, or uncollected.**
- **NEVER present a rule that has only passed `check` as a validated detection** — conversion plus a replay against baseline is the minimum.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the logsource category was converted for the target backend and the generated query inspected, not assumed mapped.
- [ ] **Branch chosen:** single-event, correlation or filter-first was selected deliberately and the correlation case carries its meta fields on the outermost document.
- [ ] **Differential defined:** converted rule hits compared between a quiet 7-day corpus and a positive replay, per host.
- [ ] **Stop condition stated:** unmapped category, missing Sigma field, inexpressible grouping or unsupported modifier was named where it applied.
- [ ] **Proof standard met:** the rule fires on the replay and stays quiet on baseline, with the conversion command, backend and pySigma version recorded.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: sigma-rule-authoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-rule-authoring-windows-event-rules`](../sigma-rule-authoring-windows-event-rules/SKILL.md) - Detection and Monitoring (leaf)
- [`sigma-rule-authoring-cloud-and-network-rules`](../sigma-rule-authoring-cloud-and-network-rules/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **The logsource is the promise, the pipeline is the delivery:** a rule is only as portable as the weakest mapping between them. Inspect the converted query, every time.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; conversion writes files only, and replay should use historical corpora rather than live blocking.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/ctf_search (3), CYBER_CPT/awesome_list (2), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
