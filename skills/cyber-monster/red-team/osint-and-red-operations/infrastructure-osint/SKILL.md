---
name: infrastructure-osint
description: "Maps external infrastructure: ASN and netblock ownership, DNS history, certificate transparency, technology and cloud provider identification. Use when scoping an external attack surface."
family: osint-and-red-operations
tier: core
triggers: ["infrastructure osint", "dns history", "asn lookup", "certificate transparency", "external footprint"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [infrastructure-osint-dns-and-certificate, infrastructure-osint-host-and-service-discovery, osint-methodology, corporate-and-person-osint]
---


# Infrastructure OSINT - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Mapping an organisation's internet footprint from registration and routing data: ASN and prefix allocation, passive DNS history, certificate transparency records, and service banners. The parent skill sets the order — registration first, then routing, then certificates, then services — because each layer constrains what the next can contain.

- **Registration constrains routing.** An ASN and its announced prefixes bound which addresses can plausibly belong to the organisation; a banner on an unrelated prefix is not theirs.
- **Certificates reveal names before services do.** CT records often expose hostnames that no DNS enumeration will find, and they carry issuance timestamps.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target resolves to `infrastructure-osint-dns-and-certificate` **THEN** switch to [`infrastructure-osint-dns-and-certificate`](../infrastructure-osint-dns-and-certificate/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
2. **IF** the target resolves to `infrastructure-osint-host-and-service-discovery` **THEN** switch to [`infrastructure-osint-host-and-service-discovery`](../infrastructure-osint-host-and-service-discovery/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
3. **IF** the target is an organisation **THEN** start from its ASN and prefixes, and only then enumerate names within those ranges.
4. **IF** a name resolves to an address outside the organisation's prefixes **THEN** record it as hosted elsewhere and check the CNAME chain before attributing it.
5. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
6. **IF** the input cannot establish the precondition this skill needs — an organisation identifier (ASN, registrant handle, or domain), and a scope that names which layers are in bounds — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `infrastructure-osint-dns-and-certificate` | [`infrastructure-osint-dns-and-certificate`](../infrastructure-osint-dns-and-certificate/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `infrastructure-osint-host-and-service-discovery` | [`infrastructure-osint-host-and-service-discovery`](../infrastructure-osint-host-and-service-discovery/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** RDAP for registration, BGP and prefix data for routing, certificate transparency for names, and banner data for services — each recorded with retrieval time
- **First Check:** `curl -sS https://rdap.example/domain/target.example | jq '.entities'`

1. Confirm the target surface: identify the organisation's ASN or registrant handle, and record which of registration, routing, certificates, and services are in scope.
2. Choose the branch: routing-first for a large network, certificate-first for a single brand, and service-first when a specific host is already known.
3. Define the differential: attribute a name or address to the organisation only when a registration or routing record corroborates it; the differential is corroboration present versus absent.
4. Name the stop condition: a prefix set and a name set that stop growing across two sources.
5. Prove it: each attributed asset carries the record that ties it to the organisation (prefix announcement, registrant handle, or certificate subject) and its retrieval date.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ASN and announced prefix set` | Bounds the address space that can plausibly belong to the organisation. |
| `Registrant handle from RDAP` | Ties a domain to a legal entity rather than to a brand name. |
| `Certificate transparency subject and issuer` | Reveals hostnames and issuance dates, often ahead of any DNS record. |
| `Banner product and version` | Describes a service on an attributed address; without attribution it describes someone else's host. |

## Worked Contrast

**Attribution From a Shared Hosting Address:**

```text
target.example resolves to 203.0.113.10.
Scan 203.0.113.10 and list every service found as target infrastructure.
# BUG: the address is a shared host; the services belong to other tenants
```

**Attribution Bounded by Registration and Routing:**

```text
Registrant handle EX-1 (RDAP, retrieved 2026-11-02).
Announced prefixes for AS64500 (routing data, retrieved 2026-11-02): 198.51.100.0/24.
target.example resolves to a CNAME on a shared host outside those prefixes -> hosted elsewhere.
Attributed assets: hosts inside 198.51.100.0/24 with certificates whose subject matches the registrant handle.
```

**Why this matters:** A shared hosting address hosts many tenants, so scanning it produces services that belong to other organisations and would be an out-of-scope finding. Bounding attribution by announced prefixes and by certificate subject ties each asset to the organisation with a record, and explicitly records the CNAME case as hosted elsewhere.

## When It Is NOT This Issue

- **Shared hosting or CDN address.** Services on a shared address belong to whoever runs them, not to the customer whose name resolves there.
- **Subdomain takeover candidate read as owned service.** A dangling CNAME is a takeover surface for the *owner of the target*, not an asset of the organisation that once used it.
- **Historical prefix no longer announced.** A prefix that moved to another ASN may now belong to a different organisation.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `infrastructure-osint` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `infrastructure-osint` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: infrastructure-osint
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`infrastructure-osint-dns-and-certificate`](../infrastructure-osint-dns-and-certificate/SKILL.md) - OSINT and Red Operations (leaf)
- [`infrastructure-osint-host-and-service-discovery`](../infrastructure-osint-host-and-service-discovery/SKILL.md) - OSINT and Red Operations (leaf)
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `infrastructure-osint` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 34 |
| Distinct dataset sources | 9 |
| Top sources | osint-tool-database (16), OffsecCyber (6), CYBER_CPT/github_security_md (4), bugbounty-hunter-v1 (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 16 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
