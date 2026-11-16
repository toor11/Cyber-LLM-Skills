---
name: network-protocol-attacks-name-resolution-poisoning
description: Name resolution poisoning. Covers LLMNR, NBT-NS and mDNS spoofing to capture hashes and relay authentication on a local segment. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["llmnr spoof", "nbt-ns poisoning", "mdns spoof", "responder capture"]
cwe: [CWE-284]
owasp: []
attack: [T1557]
capec: [CAPEC-612]
related: [network-protocol-attacks, network-protocol-attacks-ipv6-and-dhcp-abuse, network-protocol-attacks-layer-two-attacks, network-protocol-attacks-capture-and-intercept]
parent: network-protocol-attacks
---

# Network Protocol Attacks Name Resolution Poisoning - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Windows resolves a mistyped or unresolved hostname by broadcasting: LLMNR on UDP 5355, NBT-NS on UDP 137, and mDNS on 5353. None of these protocols authenticates the responder, so whichever host answers first becomes the name's owner for that victim. The victim then authenticates to the attacker, usually with NTLM over SMB, which is why name-resolution poisoning is a credential-capture technique rather than a discovery one. The finding is the victim's own resolver result and the outbound authentication that followed it.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the victim uses a fully qualified name **THEN** LLMNR and NBT-NS do not answer FQDNs, so the poisoning path does not apply; check the query type first
3. **IF** the objective is relay rather than capture **THEN** the captured authentication is only useful if a target does not require signing, so pair with [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md)
4. **IF** the estate is IPv6-first **THEN** DHCPv6-based DNS assignment is a different mechanism; see [`network-protocol-attacks-ipv6-and-dhcp-abuse`](../network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md)
5. **IF** the segment is not switched or is wireless with client isolation **THEN** the answer will not reach the victim; confirm the topology before interpreting a silent capture
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `network-protocol-attacks-name-resolution-poisoning` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The captured authentication must be used | [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) | Signing state and relay targets |
| IPv6 resolver assignment | [`network-protocol-attacks-ipv6-and-dhcp-abuse`](../network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) | DHCPv6 and RA instead of broadcast names |
| Frame redirection instead of name answers | [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) | ARP and neighbour spoofing |
| The credential is captured and needs cracking | [`password-cracking-and-wordlists`](../password-cracking-and-wordlists/SKILL.md) | Offline recovery of the captured hash |
| Need the class-level branch table first | [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the victim emits broadcast name queries.** Passive capture on UDP 5355, 137 and 5353 from the victim address. No broadcast query means no poisoning path, whatever the tool reports; this single check eliminates most false positives.
2. **Choose LLMNR, NBT-NS or mDNS by observed traffic.** LLMNR for Windows Vista and later, NBT-NS for legacy stacks and some appliances, mDNS for printers and macOS. Answer only the protocol the victim actually used, because answering a protocol the victim does not speak produces no authentication.
3. **Baseline the victim's name resolution.** Resolve a known-bad name before the probe and record the failure. After the probe, the differential is that same name resolving to the assessment host plus an outbound SMB or HTTP connection to it.
4. **Set the capture window and stop condition.** Bound the run to named victims and a fixed duration, and stop on the first authentication captured. Continuing to harvest after the first credential is unnecessary collection and increases both risk and report noise.
5. **Define proof.** Proof is the victim's query, the assessment host's answer, and the victim's own outbound authentication to the offered address, evidenced by the destination IP in the connection. The hash itself is evidence of what was exposed, not proof of the technique.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `tcpdump -ni eth0 'udp port 5355 or udp port 137'` | Proves which broadcast resolution protocols the victim uses, the precondition for any poisoning claim; any platform with libpcap. |
| SMB connection to the offered address | Proves the victim accepted the answer and authenticated, which is the actual finding; Windows victim, visible in the capture and in the victim's 4624/5145 logs. |
| `Get-SmbConnection` on the victim | Proves which server the client believes it is talking to, including the dialect and signing state; Windows. |
| WPAD name query on 137 | Proves whether proxy auto-discovery is attempted, a common source of machine-account authentication; Windows with WPAD enabled. |
| `Resolve-DnsName -LlmnrNetbiosOnly` | Proves LLMNR is enabled on the local stack and would emit a query; Windows. |

## Worked Contrast

**Weak configuration — LLMNR enabled and WPAD auto-discovery active by default:**

```powershell
# default: multicast name resolution on, WPAD lookup attempted
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast
# a mistyped \\fileserver\share is broadcast, answered, and authenticated to
```

**Hardened configuration — multicast resolution disabled and WPAD lookup disabled by policy:**

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttpSettings' -Name Migrate -Value 0
# the mistyped name now fails with no broadcast and no outbound authentication
```

**Why this matters:** the attack needs the victim to broadcast and then trust the first answer, so the control is disabling the broadcast protocols at the endpoint and the network rather than filtering the answer.

## When It Is NOT This Issue

- **A legitimate second responder.** A NAS, print server or router answering its own name is normal; check whether the returned address belongs to that device before calling the answer malicious.
- **WPAD served by a real proxy.** A WPAD answer from the sanctioned proxy is expected; confirm the hostname and address against the proxy inventory.
- **mDNS reflector traffic.** An mDNS reflector forwards legitimate answers between VLANs; the source address is the reflector, not a victim-compromising responder.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `network-protocol-attacks-name-resolution-poisoning` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-protocol-attacks-name-resolution-poisoning` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: network-protocol-attacks-name-resolution-poisoning
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1557]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks-ipv6-and-dhcp-abuse`](../network-protocol-attacks-ipv6-and-dhcp-abuse/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-protocol-attacks-name-resolution-poisoning` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1557`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (17), CYBER_CPT/ctf_search (2), CYBER_CPT/atomic_red_team (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
