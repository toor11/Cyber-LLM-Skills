---
name: network-recon-and-port-scanning
description: "Maps a network: host discovery, port and service scanning, OS fingerprinting, and scan timing under detection pressure. Use at the start of any internal or external network assessment."
family: network-ad-and-endpoint
tier: core
triggers: ["network recon", "port scan", "nmap", "host discovery", "service scan", "network discovery"]
cwe: [CWE-284]
owasp: []
attack: [T1046]
capec: [CAPEC-116]
related: [network-recon-and-port-scanning-external-perimeter-scanning, network-recon-and-port-scanning-internal-network-mapping, service-enumeration, network-protocol-attacks]
---

# Network Recon and Port Scanning - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Port scanning is a reachability experiment, not an attack: each probe classifies a port by which of three answers comes back. A SYN to an open port draws SYN-ACK, a closed port answers RST, and a filtered port answers nothing at all or an ICMP unreachable. The finding is never 'a port is open' but the shape of the reachable surface: which hosts answer which probes, from which source, and at what rate. Timing, retransmission and decoy behaviour are what network telemetry actually records, so scan configuration is part of the evidence rather than an implementation detail.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the scope question is *what is exposed to the internet* rather than *what a foothold can reach* **THEN** start with [`network-recon-and-port-scanning-external-perimeter-scanning`](../network-recon-and-port-scanning-external-perimeter-scanning/SKILL.md)
2. **IF** you already hold a host inside the estate and need east-west reachability **THEN** use [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md)
3. **IF** the port set is known and the question becomes *which service and version answers* **THEN** hand off to [`service-enumeration`](../service-enumeration/SKILL.md) before drawing conclusions
4. **IF** a scan shows *open* but a manual connect fails **THEN** suspect an inline device answering on behalf of the host, and re-probe with a payload-bearing request before reporting exposure
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `network-recon-and-port-scanning` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Exposure claim must survive a second vantage point | [`network-recon-and-port-scanning-external-perimeter-scanning`](../network-recon-and-port-scanning-external-perimeter-scanning/SKILL.md) | Two-source confirmation is the core rule for perimeter findings |
| Need east-west reachability from a foothold | [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md) | Local segment behaviour differs from routed paths |
| Ports are known, need banners and protocol detail | [`service-enumeration`](../service-enumeration/SKILL.md) | Version and configuration claims belong to enumeration |
| Scan crosses a firewall or ACL | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Rule-by-rule differentials, not open-port lists |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the probe contract first.** Write down source address, target CIDR, allowed port set, and rate ceiling before the first packet. A scan is only reproducible if the source interface and the probe type are recorded; a later 'the port was open' claim with no source named is unfalsifiable.
2. **Choose the discovery branch by what the segment answers.** ICMP echo where the host allows it, ARP on a local broadcast domain, TCP SYN to a sparse port set when ICMP is dropped, and full TCP connect only when raw sockets are unavailable. Skipping discovery and scanning the whole range is legitimate for a /24 but changes the noise profile.
3. **Build a baseline-versus-probe pair.** Scan one host you know is up and one you know is filtered with the identical flag set. If both produce the same answer the probe is being answered by something other than the host, usually a load balancer, a NAT rule, or a host firewall in a 'drop and log' state.
4. **Set the stop condition before scanning.** Throughput ceiling in packets per second, a wall-clock cap per subnet, and an abort rule: first IDS-blocked source, first link-saturation alert, or first out-of-scope response. Name the threshold in the plan so the scan cannot drift into a denial-of-service by accident.
5. **Decide what counts as proof.** An open port is proven by a completed protocol exchange, not by one SYN-ACK: banner plus a valid protocol response, repeated from a second source, with the same service identity. Record the exact flag set, timestamp, and both vantage points; anything less is a lead.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `nmap -sS -Pn -p- --min-rate 1000` | Proves which TCP ports complete a handshake from this source; Linux, raw socket required. `-Pn` suppresses discovery so a filtered ICMP path does not hide a live host. |
| `nmap -sU --top-ports 50` | Proves UDP reachability where closed ports draw ICMP port-unreachable; Linux. Silent UDP ports are inconclusive, so pair with a service-specific payload. |
| RST versus silence on the same port | Distinguishes a host firewall dropping (filtered) from a service absent (closed); platform-independent, readable in any packet capture. |
| `masscan --rate 500 --ports 0-65535` | Proves scan-rate tolerance and full-range exposure fast; Linux. The rate, not the port list, is usually what trips network detection. |
| `Test-NetConnection -ComputerName host -Port 445` | Proves reachability from a Windows host without raw sockets; Windows. Useful when the assessment host is itself a domain member and egress is filtered. |

## Worked Contrast

**Weak configuration — workstation firewall disabled, so every listening port is reachable from the user VLAN:**

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
# Every bound port is now visible to a flat-network scan;
# a single SYN sweep maps the whole estate from one workstation.
```

**Hardened configuration — inbound default-deny with an explicit management allowlist:**

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
New-NetFirewallRule -DisplayName 'Mgmt-SSHD' -Direction Inbound -Protocol TCP `
    -LocalPort 22 -RemoteAddress 10.20.0.0/24 -Action Allow
# Scan results now show only the management plane, and only to the jump subnet.
```

**Why this matters:** scan findings are a function of the filtering policy between the scanner and the host, so the firewall profile and the per-rule remote-address scoping are the actual control being measured.

## When It Is NOT This Issue

- **Scanner noise, not adversary behaviour.** A scheduled vulnerability scanner produces the same SYN sweep every week from a known appliance address; confirm the source against the scanner inventory before treating a full-range scan as hostile.
- **Middlebox answering for a dead host.** An F5, Citrix ADC or cloud load balancer will complete a handshake for a backend that is down; if the SYN-ACK TTL and window size match other virtual IPs on the same device, the port is not the host's.
- **Cloud provider health checks.** Ports 10250, 8080 or 443 that answer only from the provider's probe ranges are platform plumbing, not an exposed service.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `network-recon-and-port-scanning` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-recon-and-port-scanning` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: network-recon-and-port-scanning
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1046]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning-external-perimeter-scanning`](../network-recon-and-port-scanning-external-perimeter-scanning/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-recon-and-port-scanning` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1046`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 34 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/L5/ctf_search (12), CYBER_CPT/oxdf (9), OffsecCyber (6), CYBER_CPT/ctf_search (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 1 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
