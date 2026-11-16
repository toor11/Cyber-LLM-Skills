---
name: lab-and-tooling-setup
description: "Builds and maintains a security workstation and lab: tool installation, isolated networks, snapshots and reproducible environments. Use when setting up or repairing tooling."
family: osint-and-red-operations
tier: leaf
triggers: ["security lab setup", "tooling setup", "lab environment", "kali setup"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Lab and Tooling Setup - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Building an isolated environment where assessment tooling can run without touching production: a virtual network with no route to the corporate LAN, snapshots before each scenario, pinned tool versions, and a documented reset procedure. The engineering problem is ensuring that a mistake in the lab cannot become an incident in the estate.

- **Isolation is a routing property, not a policy.** The lab must have no route to the corporate network and no NAT that reaches it, because a firewall rule can be changed by the same person who is testing.
- **Snapshots make destructive work safe.** A snapshot before each scenario means a broken lab costs minutes, which is what lets the work be aggressive where the scenario requires it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the lab needs internet access **THEN** route it through a dedicated egress with logging, never through the corporate default gateway.
2. **IF** a tool version matters to the finding **THEN** pin it in the lab image, because a different version produces different results.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an isolated network with a verified no-route test, snapshots, and pinned tool versions — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A hypervisor or container lab with an internal-only network, snapshots, and a pinned tool manifest
- **First Check:** `python -c "import yaml; print(yaml.safe_load(open('lab.yaml'))['networks'])"`

1. Confirm the target surface: draw the lab network, name every subnet, and identify any interface that could reach the corporate network.
2. Choose the branch: fully offline when the scenario needs no external resources, logged egress when it does, and air-gapped with a transfer process when the artefact source cannot be trusted.
3. Define the differential: the isolation test is a route lookup and a connection attempt from the lab to a corporate address; both must fail before any scenario runs.
4. Name the stop condition: a verified isolation test and a snapshot taken after it, before any tooling is installed.
5. Prove it: record the route table, the failed connection attempt, and the snapshot identifier, so the environment's isolation is evidenced rather than assumed.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Internal-only virtual network` | Removes the route rather than filtering it, which is the only isolation that survives a configuration change. |
| `Snapshot before each scenario` | Makes destructive testing recoverable, which is a prerequisite for realistic scenario design. |
| `Pinned tool manifest with versions` | Keeps results reproducible across analysts and across lab rebuilds. |
| `Documented reset procedure` | Turns rebuilding into a routine step instead of an unplanned afternoon. |

## Worked Contrast

**Lab Bridged to the Corporate LAN:**

```text
Create lab VMs on the default bridged adapter.
Install tooling and start testing.
# BUG: the lab has a route to production, and a misaddressed command reaches real systems
```

**Internal Network With a Verified No-Route Test:**

```bash
ip route get 10.20.0.5 || true
curl -sS --max-time 3 -o /dev/null -w '%{http_code}\n' http://10.20.0.5/ || echo "no route (expected)"
virt-snapshot create lab-base-before-scenario
```

**Why this matters:** A bridged adapter puts the lab on the corporate subnet, so a typo in a target address reaches a production host. An internal-only network removes the route entirely, and running the route and connection test before each scenario turns isolation into an observation that is recorded, not an assumption.

## When It Is NOT This Issue

- **Lab VM with a NAT interface for updates.** Update traffic through a dedicated egress is not a break in isolation if it cannot reach corporate ranges; test the route.
- **Snapshot from before a tool upgrade.** An old snapshot with old tool versions explains results that differ from the current manifest.
- **Shared clipboard or folder with the host.** Convenient but it is a data path; record whether it is enabled.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `lab-and-tooling-setup` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `lab-and-tooling-setup` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: lab-and-tooling-setup
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `lab-and-tooling-setup` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/nuclei_templates (4), CYBER_CPT/wiz_research (2), CYBER_CPT/netresec (1), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
