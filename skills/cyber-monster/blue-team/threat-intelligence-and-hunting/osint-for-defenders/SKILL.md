---
name: osint-for-defenders
description: "Uses open source information defensively: external attack surface discovery, brand impersonation detection and exposure monitoring. Use when reducing externally visible risk."
family: threat-intelligence-and-hunting
tier: core
triggers: ["defensive osint", "external exposure monitoring", "brand monitoring defense"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management, threat-hunting]
---

# OSINT for Defenders - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Defender-side OSINT is the practice of looking at your own organisation from outside: what is exposed, what is impersonating you, and what has leaked. The discipline is scope and legality - you may examine what is public, you may not interact with third-party infrastructure, and you should not expose employees while checking whether they appear in a breach. The output feeds exposure management and brand protection, not intelligence collection for its own sake.

- **CWE-200 framing:** most defender OSINT findings are unintended disclosure - a document, a repository, or a certificate that reveals internal structure.
- Passive collection only: no authentication attempts, no scanning of third-party hosts, no interaction with impersonating infrastructure beyond reporting.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is your externally reachable estate **THEN** open `attack-surface-management`, which has the attribution discipline this skill lacks.
2. **IF** the finding is leaked credentials **THEN** open `compromised-credentials-and-token-revocation-playbook` for the response.
3. **IF** the target is a person rather than the organisation **THEN** check the legal basis first; employee-level collection usually needs a documented purpose.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Define the collection scope and the legal basis.** Domains, brands, repositories, and document patterns, with the reason. A scope that includes individuals needs a documented purpose and a handling rule.
2. **Collect passively from public sources.** Certificate transparency, document sharing search, public code hosts, breach indexes where licensing permits, and app store listings.
3. **Choose the branch on the finding type.** Exposure takes the remediation branch (take down, decommission, rotate); impersonation takes the takedown branch; leak takes the credential-response branch.
4. **Define the baseline-vs-probe differential.** Baseline: the same query on a control domain or brand you know is clean. Probe: your own assets. This distinguishes a real finding from a search artefact, because document-search recall is noisy.
5. **State the stop condition and the proof.** Stop when each finding has a source URL, a verification step, and an owner action; proof is the artefact saved with its retrieval date, since pages disappear.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Internal document indexed on a public sharing site | Proves unintended disclosure; the document often contains architecture or credential material. |
| Certificate naming an internal hostname issued publicly | Proves a misissued or over-broad certificate, which reveals internal naming. |
| Public repository containing a deploy key | Proves a supply-chain exposure; the key's scope determines urgency. |
| Lookalike domain registered with a mail exchanger | Proves impersonation preparation; the MX record indicates intent to send mail. |

## Worked Contrast

**OSINT sweep that lists everything found without verification:**

```text
Search results for example.com:
- 143 documents on sharing sites
- 12 repositories mentioning the company
- 4 lookalike domains
- employees found in 3 breach dumps
Action: forward the list to security for review
```

**Scoped collection with verification and an owner per finding:**

```text
Scope: example.com brand + 3 product domains. Legal basis: brand protection programme.
Collection: passive only (CT logs, document search, public code hosts). No interaction with lookalikes.

F1 internal-wiki-export.pdf on sharing site
   verified: opens in browser, contains 'vpn.internal.example.com' and a 2026 architecture diagram
   owner: IT-platform   action: takedown request submitted 2026-11-10, ticket SEC-6681
F2 certificate SAN '*.internal.example.com' issued by public CA
   verified: CT log entry, issuer matching our ACME account
   owner: platform   action: revoke + reissue, prevent internal names in public CSRs
F3 deploy key in public repo 'example-ci-tools'
   verified: key fingerprint matches a key active in CI (checked scope: read-only to one repo)
   owner: ci-platform  action: revoke 2026-11-11, rotate, enable secret scanning
F4 lookalike 'examp1e-login.com' with MX record
   verified: MX present, no credential-harvest page yet
   owner: brand   action: takedown filed; monitor for hosting change
Employees in breach dumps: not collected (outside programme scope, handled by HR policy)
```

**Why this matters:** The first sweep produces a list with no verification, no ownership, and an individual-focused collection step that the programme has no basis for. The second verifies each finding with the specific evidence, assigns an owner and an action, and explicitly declines the individual-level collection - which is the scope discipline that makes defender OSINT defensible.

## When It Is NOT This Issue

- **Document that is intentionally public.** Marketing collateral on a sharing site is not a leak; check the content before filing.
- **Lookalike domain with no mail or web service.** Many are defensive registrations or parked; monitor rather than escalate.
- **Employee name in a breach dump.** Outside a defender OSINT scope unless a documented HR or legal purpose exists.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `external surface` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `osint-for-defenders` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: osint-for-defenders
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`hypothesis-driven-hunting`](../hypothesis-driven-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `osint-for-defenders` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 24 |
| Distinct dataset sources | 4 |
| Top sources | osint-tool-database (16), CYBER_CPT/ctf_search (3), CYBER_CPT/blackhills (3), cyber-security/CyberSec-Dataset (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
