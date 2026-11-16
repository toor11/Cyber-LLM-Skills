---
name: pivoting-and-tunneling-dns-and-icmp-tunnels
description: DNS and ICMP tunnelling. Covers exfiltration and interactive access over DNS and ICMP where TCP egress is blocked, including throughput constraints. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["dns tunnel", "icmp tunnel", "dns exfiltration channel"]
cwe: [CWE-284]
owasp: []
attack: [T1090]
capec: [CAPEC-563]
related: [pivoting-and-tunneling, pivoting-and-tunneling-socks-and-port-forwarding, network-recon-and-port-scanning, service-enumeration]
parent: pivoting-and-tunneling
---

# Pivoting and Tunneling DNS and Icmp Tunnels - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

DNS and ICMP are permitted almost everywhere because they are required for basic connectivity, which makes them attractive as covert channels. A DNS tunnel encodes data in query names and responses; an ICMP tunnel encodes it in echo payloads. Both are constrained by protocol overhead and by the resolver in the path, and both leave a distinctive statistical trace: query-name length, label entropy, response size and query rate that no legitimate resolver pattern produces.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the resolver forwards to the internet **THEN** a tunnel needs an authoritative server for a delegated subdomain, so the finding is the delegation
3. **IF** queries are logged **THEN** entropy and length statistics on the query name are the evidence, not the payload
4. **IF** ICMP is permitted outbound **THEN** an echo tunnel is possible, and the payload size and rate are the signals
5. **IF** the resolver blocks unknown domains **THEN** a tunnel over the resolver's allowlist is much harder; the finding becomes the allowlist's breadth
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `pivoting-and-tunneling-dns-and-icmp-tunnels` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The channel is HTTP or WebSocket | [`pivoting-and-tunneling-socks-and-port-forwarding`](../pivoting-and-tunneling-socks-and-port-forwarding/SKILL.md) | Application-level forwarding |
| The infrastructure is the question | [`c2-infrastructure-and-redirectors`](../c2-infrastructure-and-redirectors/SKILL.md) | Certificates and hosting |
| The timing is the question | [`c2-implant-and-beaconing`](../c2-implant-and-beaconing/SKILL.md) | Beacon periodicity |
| The resolver policy must be assessed | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Egress rule evidence |
| Need the class-level branch table first | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish whether a delegated subdomain exists for the organisation.** A tunnel requires an authoritative server the client can query. An NS record for a subdomain pointing outside the organisation's nameservers is the strongest possible indicator, and it is a single DNS query to check.
2. **Measure query-name statistics against the domain's normal pattern.** Length, label count and character entropy. Legitimate names are short and dictionary-like; tunnel names are long and high-entropy because they carry encoded data.
3. **Read the resolver's forwarding policy.** A resolver that forwards everything to the internet permits any tunnel; one with a response policy zone or an allowlist constrains it. That policy is the control.
4. **Name the stop condition.** Stop at the first statistical anomaly that is not explained by a known application, or at the first delegation that should not exist.
5. **State the proof.** Proof is the query-name statistics over a stated window plus the delegation record, or the ICMP payload and rate. A single long query is not a finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| NS record for a subdomain pointing outside the organisation | Proves the delegation a DNS tunnel requires, and it is the single most reliable indicator; any DNS zone. |
| Query-name length above 100 characters sustained | Proves encoded data in the name, since legitimate names rarely exceed that; resolver logs. |
| High character entropy in the leftmost label | Proves base32 or base64 encoding, the tunnel's payload form; resolver logs. |
| ICMP echo payloads larger than the default | Proves data carried in echo requests, which legitimate pings do not do; any egress path. |
| Query rate to one parent domain far above baseline | Proves a tunnel or a domain-generation scheme, since legitimate resolution is bursty and low-rate; resolver logs. |

## Worked Contrast

**Weak configuration — resolver forwards all queries to the internet with no policy zone and no logging:**

```bash
# named.conf: forwarders set, no response policy zone, query logging off
# any delegated subdomain resolves, and nothing records the query names
options { forwarders { 203.0.113.53; }; };
# an encoded tunnel runs without producing a log entry
```

**Hardened configuration — logging enabled, response policy zone applied, and external delegation reviewed:**

```bash
logging { channel queries { file "/var/log/named/queries.log"; severity info; }; category queries { queries; }; };
# add a response policy zone for known-bad and unapproved domains
# and audit NS records so no subdomain delegates outside the organisation
# verification: a test query appears in the log and an unapproved domain is refused
```

**Why this matters:** a DNS tunnel needs an unmonitored resolver and a delegation, so the controls are query logging, a policy zone and delegation review, verified by a logged query and a refused name.

## When It Is NOT This Issue

- **Long names from a legitimate service.** Some CDNs and telemetry services use long encoded names; check the parent domain against the sanctioned inventory.
- **ICMP echo with a large payload from a monitoring tool.** Some tools use large pings for MTU discovery; correlate with the tool's schedule.
- **A delegated subdomain for a sanctioned SaaS service.** Delegation is a normal DNS pattern; the finding is a delegation nobody can explain.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `pivoting-and-tunneling-dns-and-icmp-tunnels` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `pivoting-and-tunneling-dns-and-icmp-tunnels` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: pivoting-and-tunneling-dns-and-icmp-tunnels
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1090]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`pivoting-and-tunneling-socks-and-port-forwarding`](../pivoting-and-tunneling-socks-and-port-forwarding/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `pivoting-and-tunneling-dns-and-icmp-tunnels` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1090`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/github_security_md (9), CYBER_CPT/pentest_partners (3), CYBER_CPT/blackhills (2), CYBER_CPT/govuln (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
