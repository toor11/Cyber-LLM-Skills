---
name: network-recon-and-port-scanning-internal-network-mapping
description: Internal network mapping. Covers internal host discovery and segmentation mapping from a foothold, including passive discovery from ARP and traffic observation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["internal scan", "internal discovery", "network mapping internal"]
cwe: [CWE-284]
owasp: []
attack: [T1046]
capec: [CAPEC-116]
related: [network-recon-and-port-scanning, network-recon-and-port-scanning-external-perimeter-scanning, service-enumeration, network-protocol-attacks]
parent: network-recon-and-port-scanning
---

# Network Recon and Port Scanning Internal Network Mapping - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Internal mapping answers a different question than external scanning: given one compromised or authorised host, which hosts and services are reachable east-west, and which paths cross a segmentation boundary. Because the source is inside the estate, ARP, LLMNR and mDNS answer where ICMP and TCP would be filtered, and the local segment reveals hosts that never appear in an external inventory. The evidence is a reachability graph with the observing source recorded per edge.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** no foothold exists yet **THEN** return to [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) and confirm what is reachable from outside before mapping inside
3. **IF** the segment answers ARP but not IP **THEN** map layer two first; ARP and NDP tables enumerate hosts that a routed probe will never see
4. **IF** a route exists but the destination is silent **THEN** test with a protocol the path is expected to allow, such as DNS or SMB, before concluding the host is absent
5. **IF** mapping starts to touch production availability **THEN** stop at the first device that reports CPU or session-table pressure; a scan is not worth an outage
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `network-recon-and-port-scanning-internal-network-mapping` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Exposure from outside is the question | [`network-recon-and-port-scanning-external-perimeter-scanning`](../network-recon-and-port-scanning-external-perimeter-scanning/SKILL.md) | Different vantage point and different evidence rules |
| A mapped host needs service-level detail | [`service-enumeration`](../service-enumeration/SKILL.md) | Banners and shares belong to enumeration |
| The mapped path crosses a firewall | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Per-rule differentials instead of a host list |
| Traffic must be routed through the foothold | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Tunnelling changes the source address the target sees |
| Need the class-level branch table first | [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Pin the observation point.** Record the foothold's IP, subnet mask, default gateway and DNS servers before scanning. Every later edge in the map is only meaningful relative to that source, and a source that changes (DHCP renewal, VPN reconnect) invalidates the map.
2. **Enumerate the local segment before routing.** ARP sweep, NDP for IPv6, then LLMNR and mDNS listeners. Hosts that answer at layer two are present even when every TCP port is filtered, which is exactly the case segmentation is designed to produce.
3. **Baseline a known-allowed path, then probe the suspect one.** Take a service you know is permitted from this segment and confirm it answers, then send the identical probe to a host across the boundary. If both answer, the boundary is open for that protocol; if only the first does, the control holds and you have its proof.
4. **Cap the scan by blast radius, not by time.** Set a maximum concurrent connection count and a per-host rate, and name the abort trigger: an interface error counter rising, a routing loop, or a broadcast storm. Broadcast-heavy discovery on a large VLAN is the classic way an assessment causes an outage.
5. **Define proof of reachability.** An edge exists when a protocol exchange completes from the recorded source and the response is attributable to the destination host, not to an intermediary. Two independent protocols on the same edge make the finding defensible.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `arp-scan --localnet --interface eth0` | Proves which layer-two neighbours exist on the segment, including hosts with all TCP ports filtered; Linux. |
| `nmap -sn -PS445,3389,22 10.20.30.0/24` | Proves routed reachability using protocol probes that survive ICMP filtering; Linux. `-sn` keeps it to discovery so the differential stays cheap. |
| `Get-NetNeighbor -AddressFamily IPv4` | Proves the local ARP cache contents from a Windows foothold and reveals recently contacted hosts; Windows. |
| `route print` / `ip route get` | Proves which interface and next hop a destination uses, which is what decides whether a probe crosses the boundary at all; Windows and Linux respectively. |
| `nmap -sT -Pn --top-ports 100 10.20.40.0/24` | Proves reachability where raw sockets are unavailable, at the cost of full handshakes that are far more visible; any platform. |

## Worked Contrast

**Weak configuration — flat data VLAN where a workstation can reach the database tier directly:**

```powershell
# no host-based rule between workstation and database subnets;
# any compromised workstation reaches 1433/3306/5432 east-west
Get-NetFirewallRule -Direction Outbound -Enabled True |
    Where-Object DisplayName -match 'Block' | Measure-Object
```

**Hardened configuration — tier-to-tier default deny with an application allowlist:**

```powershell
New-NetFirewallRule -DisplayName 'App-to-DB-1433' -Direction Outbound `
    -Protocol TCP -RemotePort 1433 -RemoteAddress 10.20.40.0/24 -Action Allow
New-NetFirewallRule -DisplayName 'Deny-App-to-DB-Other' -Direction Outbound `
    -Protocol TCP -RemoteAddress 10.20.40.0/24 -Action Block
# the map now shows one permitted edge per application, not a reachable subnet
```

**Why this matters:** internal reachability is produced by the union of host firewall and network ACL, so an outbound allowlist with an explicit deny is the control that turns a flat map into a small one.

## When It Is NOT This Issue

- **VLAN-hopping artefact.** A host that appears reachable only when the scanner is on a trunk port is a switch misconfiguration, not a host exposure; confirm the source port is an access port before reporting.
- **Broadcast responders.** WSD, SSDP and mDNS answer on behalf of other devices; a discovery result from those protocols names a service, not necessarily the host you probed.
- **NAT or proxy collapsing many hosts to one address.** If twenty destinations return identical banners and identical latency, you are probably talking to one reverse proxy.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `network-recon-and-port-scanning-internal-network-mapping` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-recon-and-port-scanning-internal-network-mapping` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: network-recon-and-port-scanning-internal-network-mapping
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1046]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-recon-and-port-scanning-external-perimeter-scanning`](../network-recon-and-port-scanning-external-perimeter-scanning/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-recon-and-port-scanning-internal-network-mapping` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1046`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/expku (3), OffsecCyber (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
