---
name: threat-hunting-hunt-execution-and-triage
description: Hunt execution and result triage. Covers running the hunt, triaging results, separating benign from malicious and escalating confirmed findings. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["hunt execution", "hunt triage", "hunt results"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-hunting, threat-hunting-hypothesis-and-scoping, threat-hunting-detection-conversion, threat-intelligence-and-cti]
parent: threat-hunting
---

# Threat Hunting Hunt Execution and Triage - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Executing a hunt means running the query set, separating signal from baseline artefact, and deciding what happens to each hit: escalate, convert to a rule, extend the baseline, or record a coverage gap. The work is mostly triage discipline - the same host appearing in every hunt because it runs a management agent, the service creation that is a patching artefact, the authentication pattern that is a VPN concentrator. A hunt that produces a hundred hits and no decision has failed.

- **CWE-778 framing:** hits that cannot be attributed to an actor or a process are not evidence; attribution is the triage step that turns a row into a finding.
- ATT&CK v18 Detection Analytics describe the observable and the analytic together, which is the structure triage should follow: the analytic predicts what a benign instance looks like as well as a malicious one.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the scope or hypothesis is not yet written **THEN** go back to `threat-hunting-hypothesis-and-scoping`; executing an unscoped query produces unreviewable output.
2. **IF** a hit is confirmed **THEN** the incident response playbook owns containment; this skill owns the triage decision.
3. **IF** the output is a pattern worth alerting on **THEN** open `threat-hunting-detection-conversion`.
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

1. **Run the query set in a fixed order and save every result.** Baseline first, then probe, then enrichment joins. Saving the raw output is what allows a second analyst to reproduce the triage.
2. **Cluster hits before reading them.** Group by host, account, parent process, or destination. A hundred hits on one host is one investigation; a hundred hits across a hundred hosts is an artefact or an estate-wide event.
3. **Choose the branch per cluster.** Correlated with an incident or showing malicious ancestry takes the escalate branch; matching a known management or patch artefact takes the baseline-extension branch; ambiguous takes the endpoint-confirmation branch.
4. **Define the baseline-vs-probe differential per cluster.** Baseline: the same pattern in the baseline window, with its frequency. Probe: the cluster's frequency and its distinguishing feature. A cluster with no distinguishing feature is baseline.
5. **State the stop condition and the proof.** Stop when every cluster has a disposition and an owner; proof is the cluster's evidence (process tree, parent image, account context) plus the baseline frequency that justified the decision.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Single host with many hits, all from one parent process | Proves one investigation scope; clustering by parent is what prevents a hundred separate tickets. |
| Hits spread evenly across the estate at a fixed interval | Proves an automated agent or patch cycle, which belongs in the baseline rather than in the hunt. |
| Service creation shortly after an authentication anomaly on the same host | Proves a sequence worth escalating; the temporal link is the evidence, not either event alone. |
| Cluster with process ancestry showing an Office parent | Proves a proxy-execution pattern; the ancestry is the distinguishing feature triage needs. |

## Worked Contrast

**Hunt output triaged as a flat list of hits:**

```text
Query returned 1,842 events.
Reviewed top 50 by time.
- 46 looked like normal admin activity
- 4 unclear, noted in the ticket
Conclusion: no clear malicious activity identified.
Status: closed
```

**Clustered triage with baseline frequency and a disposition per cluster:**

```text
Query returned 1,842 events -> clustered by (host, parent_image)

cluster A: 1,204 events, 380 hosts, parent=svc-patchmgr.exe, hourly
  baseline frequency: same shape 1,190/probe window, 1,180/baseline window
  disposition: baseline artefact -> add parent to hunt exclusion list

cluster B: 41 events, 1 host, parent=winword.exe -> powershell.exe -> rundll32.exe
  baseline frequency: 0 in baseline window
  evidence: process tree captured, EID 3 to 203.0.113.44 (matches CTI record),
            account = finance.user4, service installed 6 min later
  disposition: escalate -> IR-2026-118

cluster C: 12 events, 9 hosts, parent=explorer.exe, user-initiated
  baseline frequency: 9-14 per window historically
  disposition: baseline artefact, extend baseline with the binary path

cluster D: 585 events, 0 attributable process (sensor gap on 19 hosts)
  disposition: coverage gap -> SEC-6710
```

**Why this matters:** The first triage reads fifty rows, finds them plausible, and closes without a decision - the 1,792 unread events and the missing baseline make the conclusion unfalsifiable. The second clusters first, states each cluster's baseline frequency, and produces four different dispositions, one of which is a coverage gap that would otherwise be invisible.

## When It Is NOT This Issue

- **Hit on a host running a management agent.** The parent process is the tell; extend the baseline list rather than escalating the same host every hunt.
- **Activity matching a documented change window.** Confirm with the change record before treating a service creation as malicious.
- **Ambiguous cluster with a sensor gap.** Unanswerable is a valid disposition; calling it benign records confidence you do not have.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `query run` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-hunting-hunt-execution-and-triage` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: threat-hunting-hunt-execution-and-triage
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
- [`threat-hunting-detection-conversion`](../threat-hunting-detection-conversion/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-hunting-hunt-execution-and-triage` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/ctf_search (6), CYBER_CPT/atomic_red_team (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
