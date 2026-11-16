---
name: pivoting-and-tunneling
description: "Routes traffic into otherwise unreachable networks: SOCKS proxies, port forwarding, SSH and chisel tunnels, DNS and ICMP tunnelling, and protocol-level covert channels. Use when you need to reach an internal network through a foothold."
family: network-ad-and-endpoint
tier: core
triggers: ["pivoting", "tunneling", "socks proxy", "port forward", "chisel", "ligolo", "covert channel"]
cwe: [CWE-284]
owasp: []
attack: [T1090]
capec: [CAPEC-563]
related: [pivoting-and-tunneling-socks-and-port-forwarding, pivoting-and-tunneling-dns-and-icmp-tunnels, network-recon-and-port-scanning, service-enumeration]
---

# Pivoting and Tunneling - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Pivoting extends reach by making traffic appear to originate from a host that can already reach the target. The three models are application-level proxying (SOCKS through a foothold), port forwarding (a specific port relayed), and network-level routing (a tunnel interface with routes). The model determines what the pivot can carry: a SOCKS proxy handles TCP only and needs proxy-aware tools, while a routed tunnel carries ICMP and UDP and lets any tool work unmodified.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the tools must work unmodified **THEN** a routed tunnel is required; SOCKS needs proxy-aware tooling and excludes ICMP and most UDP
2. **IF** only one port is needed **THEN** port forwarding is simplest and leaves the smallest footprint
3. **IF** egress is restricted to HTTP **THEN** a tunnel over HTTP or WebSocket is the pattern; check whether the proxy permits the upgrade
4. **IF** the destination is a UDP service **THEN** SOCKS5 UDP association or a routed tunnel is required; plain TCP SOCKS will not carry it
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `pivoting-and-tunneling` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The tunnel is SOCKS or a port forward | [`pivoting-and-tunneling-socks-and-port-forwarding`](../pivoting-and-tunneling-socks-and-port-forwarding/SKILL.md) | Application-level forwarding |
| The channel is DNS or ICMP | [`pivoting-and-tunneling-dns-and-icmp-tunnels`](../pivoting-and-tunneling-dns-and-icmp-tunnels/SKILL.md) | Covert channels |
| The question is segmentation rather than reach | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Rule evidence |
| The destination must be discovered | [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md) | Reachability mapping |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish what the foothold can already reach.** Routing table, DNS servers and one permitted destination. A pivot is only useful if the foothold has reach the assessment host does not, and that difference is the finding's premise.
2. **Choose the model by what must traverse it.** TCP only: SOCKS or a port forward. UDP or ICMP: a routed tunnel. One protocol over a restrictive egress: an HTTP-carried tunnel. The choice determines both capability and detectability.
3. **Baseline the source address the target will see.** Traffic through a SOCKS proxy or a routed tunnel appears to come from the foothold. Record the target-side observation, because a finding that does not name the apparent source is not reproducible.
4. **Name the stop condition and the clean-up rule.** Stop at the first confirmed reachability from the foothold to a target the assessment host could not reach. Remove the tunnel and its artefacts, since a tunnel left running is both a security exposure and an attribution problem.
5. **State the proof.** Proof is the target's own log showing the foothold's address as the source, plus the reachability that was previously absent. A tool's connected banner is not proof.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| SOCKS proxy on 1080 with `proxychains` | Proves TCP-only reachability through the foothold, with the limitation that ICMP and most UDP are excluded; any foothold. |
| TUN interface with a route for the target subnet | Proves network-level reachability, which carries ICMP and UDP and needs no proxy-aware tools; Linux attacker host. |
| HTTP or WebSocket tunnel through a proxy | Proves a path past egress filtering, at the cost of a distinctive protocol signature; restricted egress. |
| Target log showing the foothold address | Proves the apparent source of the traffic, which is what makes the pivot verifiable; any target. |
| Tunnel process with a long-lived outbound connection | Proves the pivot's own footprint, which is the detection opportunity; any foothold. |

## Worked Contrast

**Weak configuration — a foothold with unrestricted egress and a flat internal path:**

```bash
# the foothold can reach the entire internal estate and any external address,
# so a single tunnel provides both reach and a covert egress path
ip route show default
# default via 10.20.30.1, no egress ACL on the segment
```

**Hardened configuration — egress restricted and internal reach segmented:**

```bash
# egress: allow only the sanctioned destinations from the application segment
# internal: replace the flat route with per-service paths through a proxy
# verification: the foothold can no longer reach 443 to an arbitrary address and
# the internal subnet is reachable only on the permitted ports
```

**Why this matters:** pivoting needs a host with both reach and egress, so the controls are the egress allowlist and the internal segmentation, verified from the foothold rather than from the assessment host.

## When It Is NOT This Issue

- **A jump host with sanctioned forwarding.** Bastion hosts exist to forward traffic; the finding is an unauthorised tunnel, not forwarding itself.
- **A SOCKS proxy provided by the organisation.** Some estates publish a sanctioned proxy; check the configuration before treating proxy use as tunnelling.
- **A long-lived connection from a management tool.** Agents hold persistent connections; the destination and the process are the discriminators.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `pivoting-and-tunneling` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `pivoting-and-tunneling` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: pivoting-and-tunneling
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1090]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`pivoting-and-tunneling-socks-and-port-forwarding`](../pivoting-and-tunneling-socks-and-port-forwarding/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`pivoting-and-tunneling-dns-and-icmp-tunnels`](../pivoting-and-tunneling-dns-and-icmp-tunnels/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `pivoting-and-tunneling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1090`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 26 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/oxdf (15), CYBER_CPT/L5/ctf_search (5), CYBER_CPT/ctf_search (2), hackerone_disclosed_reports (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
