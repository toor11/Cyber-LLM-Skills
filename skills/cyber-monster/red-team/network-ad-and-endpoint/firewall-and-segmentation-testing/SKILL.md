---
name: firewall-and-segmentation-testing
description: "Tests network segmentation and firewall rules: egress restrictions, ACL gaps, cross-VLAN reachability, and protocol tunnelling past filters. Use when verifying whether a boundary actually holds."
family: network-ad-and-endpoint
tier: leaf
triggers: ["firewall test", "segmentation test", "acl bypass", "egress filtering", "network boundary"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-115]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, active-directory-enumeration]
---

# Firewall and Segmentation Testing - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

A segmentation claim is a claim about a rule, not about a port. Testing it means choosing a source-destination-service triple, establishing what the path currently permits, and then changing exactly one variable to see which rule is actually in force. Because most enterprise paths pass several filters — host firewall, security group, network ACL, application proxy — a single probe result cannot identify which control allowed or blocked the traffic, so the evidence has to be layered.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is whether a host is exposed at all **THEN** start with [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md); segmentation is about the path, not the host
2. **IF** the path crosses a cloud security group **THEN** read the group rules first; the host firewall is usually not the deciding control
3. **IF** an allowed path also passes a proxy **THEN** test with the proxy's own protocol, since a proxy may permit a request that a raw socket cannot make
4. **IF** the destination answers from one subnet but not another **THEN** that asymmetry is the finding; capture both results rather than averaging them
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `firewall-and-segmentation-testing` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the host inventory behind the rule | [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md) | Reachability map before rule reasoning |
| The allowed service is a directory | [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) | Protocol-level evidence on the permitted path |
| The rule is enforced by a VLAN boundary | [`network-protocol-attacks-layer-two-attacks`](../network-protocol-attacks-layer-two-attacks/SKILL.md) | Layer-two preconditions for the bypass |
| Traffic must be sourced from another segment | [`pivoting-and-tunneling`](../pivoting-and-tunneling/SKILL.md) | Changing the apparent source address |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Name the rule under test before sending traffic.** Write the expected tuple: source prefix, destination prefix, protocol, port, and the intended verdict. A test without a predicted verdict cannot fail, and an unfalsifiable test is not evidence.
2. **Establish the two control paths.** One tuple you know is permitted and one you know is denied, both from the same source. These calibrate the tooling: if the known-denied path answers, the probe is wrong or something is answering for the destination.
3. **Change one variable at a time.** Source port, destination port, protocol, or direction. Encapsulation is the useful exception: a tunnel over an allowed port tests whether the rule inspects content or only headers, and that is a distinct claim requiring its own approval.
4. **Set the stop condition on availability.** Abort on any state-table exhaustion, any IPS block, or any sign of a production service degrading. A segmentation test that causes an outage has failed regardless of what it proved.
5. **Define proof.** A rule is proven permissive when the permitted tuple completes and the expected-denied tuple with one variable changed also completes, twice, from the recorded source. A rule is proven effective when the denied tuple fails with a network-level rejection, not an application error.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `nmap -Pn -S <src> -p 445,3389 --reason dest` | Proves the verdict per tuple from a chosen source, with the reason name as evidence; source spoofing is limited to authorised boundary tests on controlled links. |
| `Test-NetConnection -ComputerName dest -Port 1433` | Proves application-path reachability from a Windows host, which reflects host firewall and route together; Windows. |
| `hping3 -S -p 443 -c 3 dest` | Proves whether a TCP handshake completes when ICMP is filtered, isolating port-level from protocol-level blocks; Linux. |
| Proxy `CONNECT` request | Proves whether the proxy permits an arbitrary destination, which is a different control from the network ACL; any HTTP proxy. |
| `traceroute -T -p 443 dest` | Proves where the path stops, which distinguishes a host firewall (last hop) from an intermediate ACL (earlier hop); cross-platform. |

## Worked Contrast

**Weak configuration — egress permitted to all destinations on all ports from the application tier:**

```bash
# security group egress: allow all, which makes every segmentation claim vacuous
aws ec2 authorize-security-group-egress --group-id sg-0app \
  --ip-permissions IpProtocol=-1,FromPort=-1,ToPort=-1,IpRanges=[{CidrIp=0.0.0.0/0}]
```

**Hardened configuration — egress restricted to the named dependencies per tier:**

```bash
aws ec2 revoke-security-group-egress --group-id sg-0app \
  --ip-permissions IpProtocol=-1,FromPort=-1,ToPort=-1,IpRanges=[{CidrIp=0.0.0.0/0}]
aws ec2 authorize-security-group-egress --group-id sg-0app \
  --ip-permissions IpProtocol=tcp,FromPort=1433,ToPort=1433,IpRanges=[{CidrIp=10.20.40.0/24}]
# the denied tuple now fails at the group, which is the rule the test was measuring
```

**Why this matters:** permissive egress makes every inbound rule meaningless, so the control is the egress list and the verification is the previously-successful tuple failing with a network rejection.

## When It Is NOT This Issue

- **Application-level refusal read as a network block.** A TCP handshake that completes and then returns HTTP 403 proves the path is open and the application refused; the segmentation control did not apply.
- **Asymmetric routing.** Return traffic taking a different path can make a permitted flow look blocked; confirm with a capture on both ends before concluding the rule denies.
- **Stateful firewall timeouts.** A long-idle connection dropped by state expiry is not a rule change; reproduce with a fresh connection before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `firewall-and-segmentation-testing` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `firewall-and-segmentation-testing` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: firewall-and-segmentation-testing
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) - Network, Active Directory and Endpoint (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `firewall-and-segmentation-testing` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 28 |
| Distinct dataset sources | 11 |
| Top sources | OffsecCyber (16), hackerone_disclosed_reports (2), CYBER_CPT/expku (2), SecEval/attck (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
