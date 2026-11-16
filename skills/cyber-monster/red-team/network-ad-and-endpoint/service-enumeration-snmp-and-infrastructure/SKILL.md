---
name: service-enumeration-snmp-and-infrastructure
description: SNMP and infrastructure service enumeration. Covers SNMP community string discovery and MIB walking, plus NTP, DNS and management protocol enumeration. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["snmp enum", "community string", "mib walk", "ntp enumeration"]
cwe: [CWE-284]
owasp: []
attack: [T1046]
capec: [CAPEC-116]
related: [service-enumeration, service-enumeration-smb-and-netbios, service-enumeration-ldap-and-directory, service-enumeration-database-and-remote-access]
parent: service-enumeration
---

# Service Enumeration Snmp and Infrastructure - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

SNMP and management-plane enumeration reads device identity and topology from the agent rather than the network. A single `sysDescr` read proves the device model and firmware; the interface and routing tables then describe the device's position in the estate. The critical distinction is SNMPv1/v2c community-based access, where the string is the only secret, versus SNMPv3 with a user and auth/priv protocols. Reporting a device as exposed because port 161 is open conflates reachability with answerability.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`service-enumeration`](../service-enumeration/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** port 161 answers but no data returns **THEN** the agent may require a specific community or a v3 user; a timeout is different evidence from an authorisation failure
3. **IF** a community string works **THEN** record the exact OIDs readable and whether the string grants write access via a read-only probe of a sysContact write
4. **IF** the device is a switch or router **THEN** enumerate the forwarding table before the ARP table; the topology claim depends on which interfaces the MACs appear behind
5. **IF** IPMI or a BMC is present **THEN** treat it as a separate management plane with its own credential and exposure rules
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `service-enumeration-snmp-and-infrastructure` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The device is a Windows or Linux server | [`service-enumeration`](../service-enumeration/SKILL.md) | Host-level protocol enumeration first |
| The device segments the network | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Rule and path evidence rather than device data |
| Management plane is reachable from user space | [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md) | Reachability evidence for the management subnet |
| Traffic must be captured to see the community in transit | [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) | Cleartext community exposure |
| Need the class-level branch table first | [`service-enumeration`](../service-enumeration/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the agent's protocol version first.** A v1 or v2c agent answers a community string in cleartext; a v3 agent requires a user name and returns `usmStatsUnknownUserNames` for a wrong one. The error type is the evidence, so record the exact SNMP error rather than the tool's timeout message.
2. **Read identity before topology.** `sysDescr`, `sysObjectID`, `sysName` and `sysLocation` establish what the device is and who owns it. Only once those are known does the interface table mean anything, because a router's `ifDescr` naming scheme differs from a switch's.
3. **Baseline against a hardened device of the same model.** A v3-only device with an ACL on UDP 161 is the reference. A working v2c string on the assessed device is then provably a deviation, not a vendor default you misread.
4. **Cap the walk.** Use a numeric OID subtree and a maximum repetitions value. A full `snmpwalk` of a core switch can generate thousands of requests and is the most common way an assessment degrades a production network.
5. **State what proves the finding.** Community-string exposure is proven by a returned `sysDescr` plus the OID that returned it. Write access is proven only if a write to a benign, reversible OID is explicitly authorised; otherwise report read exposure and stop.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `snmpwalk -v2c -c <string> host 1.3.6.1.2.1.1` | Proves the agent answers a community string and reports its identity; switches, routers, printers, and UPS devices. |
| `snmpwalk -v3 -l authPriv -u user -a SHA -x AES host` | Proves v3 with authentication and privacy is configured and which security level is enforced. |
| `1.3.6.1.2.1.2.2.1.2` (ifDescr) and `1.3.6.1.2.1.17.7.1.2.2.1.2` (bridge FDB) | Proves port naming and which MAC addresses sit behind which port, which is the topology claim; switches only. |
| `snmpget -v2c -c <string> host 1.3.6.1.4.1.9.9.23.1.2.1.1.6` | Proves CDP neighbour adjacency where the vendor MIB is exposed, giving device-to-device links; Cisco infrastructure. |
| `nmap -sU -p161 --script snmp-info,snmp-sysdescr` | Proves reachability and identity without a full walk, useful for a first-pass inventory. |

## Worked Contrast

**Weak configuration — SNMPv2c with a default community reachable from the user VLAN:**

```bash
# device config: v2c community readable from any source
snmp-server community public RO
snmp-server host 0.0.0.0
# from a user workstation the full interface and ARP tables are readable
```

**Hardened configuration — SNMPv3 authPriv with an ACL restricted to the monitoring subnet:**

```bash
no snmp-server community public RO
snmp-server group MON v3 priv read MONVIEW
snmp-server user monitor MON v3 auth sha <auth-secret> priv aes 256 <priv-secret>
snmp-server view MONVIEW iso included
access-list 90 permit 10.20.99.0 0.0.0.255
snmp-server group MON v3 priv read MONVIEW access 90
# v2c now returns authorizationError from the user VLAN, and timeout from elsewhere
```

**Why this matters:** the control is the combination of protocol version, view scope and source ACL, so the verification is the same `snmpget` returning `authorizationError` rather than a value.

## When It Is NOT This Issue

- **Printer or UPS with a read-only public community.** Many devices ship this way and expose only supply levels; confirm the readable subtree contains no topology or credential data before escalating.
- **Timeout mistaken for no agent.** UDP 161 filtered and UDP 161 unanswered look identical from a client; use `--reason` on an nmap UDP scan to distinguish `filtered` from `open|filtered`.
- **SNMP trap destination.** A device sending traps to a collector is not an exposed agent; traps are outbound UDP 162 and carry no readable tree.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `service-enumeration-snmp-and-infrastructure` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `service-enumeration-snmp-and-infrastructure` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: service-enumeration-snmp-and-infrastructure
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1046]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration-smb-and-netbios`](../service-enumeration-smb-and-netbios/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration-database-and-remote-access`](../service-enumeration-database-and-remote-access/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `service-enumeration-snmp-and-infrastructure` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1046`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (6), cyber-security/vulnerability-intelligence__nvd-realtime-cves-7.json (2), ctf-solver-dataset (1), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
