---
name: osint-operational-security
description: "Protects the investigator's identity and infrastructure during collection: sock puppet discipline, attribution risk, logging hygiene and legal boundaries. Use before any sensitive collection activity."
family: osint-and-red-operations
tier: leaf
triggers: ["osint opsec", "sock puppet", "collection attribution", "investigator opsec"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# OSINT Operational Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Protecting the assessment while it runs: separating research identity from the analyst's own, keeping collection traffic off the corporate egress where the engagement requires it, and ensuring the collected material is handled under the engagement's data rules. The failure modes are attribution back to the client and contamination of the target's view of the research.

- **Research identity is an engagement artefact.** Sock puppets, mailboxes, and phone numbers used in collection are documented and retired at the end, along with their credentials.
- **Collection traffic is attributable.** A source that sees the analyst's corporate address learns that the client is being investigated; route collection through the agreed egress or not at all.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the source can see the request origin **THEN** use the engagement's designated egress, and record which egress each source saw.
2. **IF** a persona interacts with a person **THEN** log every contact and retire the persona at engagement close, because an abandoned persona is a liability.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a documented research identity, an egress path agreed with the client, and a data-handling rule for collected material — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A persona register, an egress register per source, and a data-handling note covering storage, retention, and destruction
- **First Check:** `python -c "import yaml; print(yaml.safe_load(open('opsec.yaml'))['personas'])"`

1. Confirm the target surface: list the sources to be queried, the identity each will see, and the egress each will observe.
2. Choose the branch: passive collection from third-party datasets (no direct contact), active collection against the target's own services, and persona interaction where a human is involved.
3. Define the differential: compare the request origin and identity seen by the source against the intended ones; a mismatch is an attribution risk, not a technicality.
4. Name the stop condition: a source that requires identity verification the persona cannot pass, or an interaction that would require a real credential.
5. Prove it: the egress register maps each source to the address it observed, and the persona register records what was created, used, and retired.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Egress register per source` | Records what each source observed, which is the difference between an attributable and an unattributable engagement. |
| `Persona register with retirement date` | Prevents a forgotten account becoming a liability after the engagement ends. |
| `Passive-first ordering` | Third-party datasets answer many questions without the target seeing any traffic from the analyst. |
| `Data-handling note with retention` | Decides where collected material lives and when it is destroyed, before collection starts. |

## Worked Contrast

**Collection From the Corporate Egress With a Personal Account:**

```text
Query the target's public API and registry endpoints from the office network using the analyst's own account.
# BUG: the target can attribute the research to the client, and the analyst's identity is now linked to the engagement
```

**Egress and Persona Registered Per Source:**

```yaml
personas:
  - id: research-a
    created: "2026-10-01"
    retire_by: "2026-12-15"
    used_for: [registry, forum-read]
egress:
  - source: registry.example
    observed_address: "203.0.113.20"
    note: dedicated assessment egress
  - source: target-api
    observed_address: "203.0.113.20"
    note: passive only, no authentication
data_handling:
  store: encrypted, engagement workspace
  retention: 90 days post-engagement
  destroy: with certificate of destruction
```

**Why this matters:** Querying from the office network with a personal account tells the target that the client is investigating and links the analyst to the work permanently. Registering the persona and the egress per source makes both visible before collection, and the retention rule decides what happens to the material afterwards rather than leaving it on a laptop.

## When It Is NOT This Issue

- **Passive dataset query attributed to the client.** The dataset provider sees the analyst, not the target; the risk is only where the target's own service is queried.
- **Persona with no interactions.** A read-only persona still needs retirement, but it carries less risk than one that contacted people.
- **Egress shared with other engagements.** Sharing is acceptable if the register records it, because attribution to a specific client then depends on other evidence.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `osint-operational-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `osint-operational-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: osint-operational-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `osint-operational-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/gh_advisories (2), CYBER_CPT/oxdf (2), osint-ctf-corpus-fr (1), CYBER_CPT/infocon (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
