---
name: pivoting-and-tunneling-socks-and-port-forwarding
description: SOCKS proxying and port forwarding. Covers building SOCKS proxies and port forwards with SSH, chisel, ligolo and metasploit, plus toolchain configuration through proxychains. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["socks proxy pivot", "port forwarding", "chisel pivot", "ligolo"]
cwe: [CWE-284]
owasp: []
attack: [T1090]
capec: [CAPEC-563]
related: [pivoting-and-tunneling, pivoting-and-tunneling-dns-and-icmp-tunnels, network-recon-and-port-scanning, service-enumeration]
parent: pivoting-and-tunneling
---

# Pivoting and Tunneling Socks and Port Forwarding - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

A SOCKS proxy is an application-level relay: the client asks it to connect to a destination, and the proxy makes the connection from its own network position. Port forwarding is the narrower form, relaying one local port to one remote destination. Both change the apparent source address and both are limited to TCP unless SOCKS5 UDP association is implemented, which is why UDP services and ICMP need a routed tunnel instead.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the tool cannot be made proxy-aware **THEN** port forwarding is the alternative, or a routed tunnel if many ports are needed
3. **IF** the service is UDP **THEN** SOCKS5 UDP association is required and not every implementation supports it; check before planning
4. **IF** ICMP is needed for discovery **THEN** a routed tunnel is the only option, since SOCKS cannot carry ICMP
5. **IF** the egress proxy permits only HTTP **THEN** an HTTP-carried tunnel is required; a raw SOCKS connection will be blocked
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `pivoting-and-tunneling-socks-and-port-forwarding` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Many protocols and ICMP are needed | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Routed tunnels |
| The channel must be DNS or ICMP | [`pivoting-and-tunneling-dns-and-icmp-tunnels`](../pivoting-and-tunneling-dns-and-icmp-tunnels/SKILL.md) | Covert channels |
| The destination must be mapped first | [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md) | Reachability mapping |
| The question is whether the boundary holds | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Rule evidence |
| Need the class-level branch table first | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the destination is reachable from the foothold.** A port-forward is pointless if the foothold cannot reach the target. Test with a single connect from the foothold before building the tunnel, and record the result.
2. **Choose the narrowest forwarding that works.** One port for one service is the smallest change; a dynamic SOCKS proxy exposes every destination the foothold can reach. The narrowest option is also the least detectable and the easiest to clean up.
3. **Record the apparent source address.** The target sees the foothold's address. Capture it from the target's log, because that is the evidence that the traffic traversed the pivot rather than originating locally.
4. **Name the stop condition and the clean-up.** Stop at the first successful service response through the tunnel, then remove the tunnel. A tunnel left running is an exposure and confuses later attribution.
5. **State the proof.** Proof is the target-side log entry showing the foothold's address, plus the same request failing directly from the assessment host. Both halves are needed.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ssh -L` local forward for one port | Proves a single-service path through the foothold, the narrowest form; any SSH foothold. |
| `ssh -D` dynamic SOCKS | Proves reachability to any destination the foothold can reach, at the cost of a wider exposure; any SSH foothold. |
| Target log showing the foothold's source address | Proves the traffic traversed the pivot rather than originating locally; any target. |
| `proxychains` with `proxy_dns` enabled | Proves DNS resolution also traverses the tunnel, which prevents a resolution leak; Linux. |
| Tunnel listener bound to loopback only | Proves the proxy is not exposed beyond the assessment host, a hygiene property of the pivot itself; any platform. |

## Worked Contrast

**Weak configuration — a foothold permits arbitrary SSH forwarding and reaches every internal subnet:**

```bash
# sshd on the foothold allows TCP forwarding, and the foothold routes to every
# internal subnet, so one account provides a SOCKS proxy for the whole estate
sshd -T | Select-String 'allowtcpforwarding'
# allowtcpforwarding yes
```

**Hardened configuration — forwarding disabled where it is not required and reach segmented:**

```bash
# sshd_config: AllowTcpForwarding no for accounts that do not need it
# network: remove the foothold's route to segments it has no business reaching
# verification: ssh -D fails and the foothold can no longer reach the restricted subnet
```

**Why this matters:** a SOCKS pivot needs both forwarding permission and reach, so the controls are the sshd policy and the segmentation, verified by a failed forward and a failed connect.

## When It Is NOT This Issue

- **A sanctioned bastion with forwarding enabled.** Bastions exist for this; the finding is an unauthorised foothold with the same capability.
- **A local port forward to a service on the same host.** Forwarding to localhost changes nothing about reachability.
- **A SOCKS proxy published by the organisation.** Check the configuration before treating proxy use as tunnelling.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `pivoting-and-tunneling-socks-and-port-forwarding` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `pivoting-and-tunneling-socks-and-port-forwarding` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: pivoting-and-tunneling-socks-and-port-forwarding
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1090]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`pivoting-and-tunneling-dns-and-icmp-tunnels`](../pivoting-and-tunneling-dns-and-icmp-tunnels/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `pivoting-and-tunneling-socks-and-port-forwarding` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1090`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 23 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (19), CYBER_CPT/L5/ctf_search (3), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
