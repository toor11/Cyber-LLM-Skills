---
name: indicator-lifecycle-ioc-deployment-retirement
description: IOC deployment and retirement. Covers pushing indicators into controls, measuring hit rates and retiring stale or noisy indicators. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["ioc deployment", "ioc retirement", "blocklist hygiene"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [indicator-lifecycle-and-ioc-management, indicator-lifecycle-ioc-validation-scoring, threat-intelligence-and-cti, cti-collection-and-enrichment]
parent: indicator-lifecycle-and-ioc-management
---

# Indicator Lifecycle and Ioc Management Ioc Deployment and Retirement - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Deployment and retirement are the operational half of indicator management: where an indicator is enforced, in what mode, and how it leaves service with evidence. A hash belongs in an endpoint control, a domain in a DNS or proxy control, and an IP in a network control with an allowlist exemption for shared infrastructure. Retirement is a decision with a date, and the indicator must remain queryable afterwards so retrospective hunts can still use it.

- **CWE-778 / CWE-345:** a deployed indicator that cannot be attributed to a source or re-evaluated is a standing integrity risk in the enforcement path.
- Deployment mode matters more than the matching engine: alert-only deployment produces evidence; enforcement produces outages when the indicator is wrong.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the indicator has not been validated or scored **THEN** open `indicator-lifecycle-ioc-validation-scoring` first.
2. **IF** the deployment target is a detection rule rather than an enforcement control **THEN** open `threat-hunting-detection-conversion`, since behaviour logic belongs there.
3. **IF** the indicator came from a sharing community **THEN** check the TLP or licence field before deploying it outside the agreed audience.
4. **IF** the target narrows to `indicator-lifecycle-and-ioc-management` **THEN** open [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map each observable class to the control that can actually see it.** Hash to endpoint execution control, domain to DNS or proxy, IP to network or firewall, URL path to proxy with TLS inspection considered. A control that cannot see the class will always report zero.
2. **Choose the deployment mode deliberately.** Alert-only for anything unvalidated or low-specificity; enforce for high-specificity indicators with a documented false-positive profile; allowlist-exempt for anything on shared infrastructure.
3. **Choose the branch on the expiry state.** Inside TTL takes the keep branch; at TTL takes the re-justify branch; past TTL takes the retire branch, which removes enforcement but keeps the record queryable.
4. **Define the baseline-vs-probe differential.** Baseline: the control's hit count for the indicator over the last cycle. Probe: a synthetic match (a test request to the blocked domain, or a benign file with the hash) to confirm the control fires. An indicator deployed into a control that never fires is untested enforcement.
5. **State the stop condition and the proof.** Stop when each indicator has a control, a mode, a TTL, and a probe result; proof is the probe match plus the control's configuration line naming the indicator source.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Hash indicator deployed to a proxy rather than an endpoint control | Proves the control cannot see file execution, so the indicator will never fire and the gap looks like clean coverage. |
| IP indicator enforced without a shared-hosting exemption | Proves collateral risk; the block will affect unrelated tenants of the same provider. |
| Indicator retired by deletion | Proves retrospective hunts lose the record; retirement should remove enforcement and keep the history. |
| Indicator deployed alert-only with no review date | Proves alert-only became permanent, which is how a deployment decision turns into an untested control. |

## Worked Contrast

**Deployment by pasting indicators into every control:**

```text
blocklist applied to: proxy, DNS, firewall, EDR, mail gateway
mode: enforce everywhere
retirement: remove the line when someone complains
history: overwritten nightly by the feed sync
false positives: reported by users
```

**Class-mapped deployment with modes, probes, and a retirement record:**

```yaml
indicator: cdn-update.example.net   class: domain   score: 72
deployment:
  - control: dns-resolver
    mode: enforce
    scope: outbound
    exempt: [partner-api.acme.example]      # shared CDN tenant
    probe: dig cdn-update.example.net @resolver -> NXDOMAIN (sinkholed) 2026-11-12
  - control: proxy
    mode: alert
    scope: forward-proxy users
    probe: curl -x proxy https://cdn-update.example.net -> 403 deny page 2026-11-12
retirement:
  ttl: 30d
  review: 2026-12-12
  on_retire: remove enforcement rules, keep record with status=retired for retro-hunts
  evidence: enforcement removed 2026-12-12, record retained, hit history archived
```

**Why this matters:** The first approach enforces one list everywhere, so the controls that cannot see the observable report clean and the controls that can produce outages, and retirement is whoever complains first. The second maps each class to a control that can see it, records the mode and scope per control, proves the match with a probe, and defines retirement as removal plus retention - which is what keeps the enforcement path trustworthy.

## When It Is NOT This Issue

- **Indicator enforced at the mail gateway only.** That is correct scope for a sender domain; the absence from endpoint controls is a design choice, not a gap.
- **Alert-only deployment for a low-specificity IP.** Alert mode is the correct choice for shared infrastructure; the finding would be enforcing it.
- **Retirement without a hit history because the control never logged.** That is a coverage gap in the control, not a reason to keep the indicator.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `deployment` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `indicator-lifecycle-ioc-deployment-retirement` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: indicator-lifecycle-ioc-deployment-retirement
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-ioc-validation-scoring`](../indicator-lifecycle-ioc-validation-scoring/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `indicator-lifecycle-ioc-deployment-retirement` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/expku (2), CYBER_CPT/nuclei_templates (1), CYBER_CPT/github_security_md (1), CYBER_CPT/atomic_red_team (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
