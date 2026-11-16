# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`firewall-and-segmentation-testing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Java Deserialization RCE via JBoss JMXInvokerServlet/EJBInvokerServlet on card.starbucks.in

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I found an open JMXInvokerServlet/EJBInvokerServlet and normally I should be able to get a shell just by doing that. However I think due to some egress filtering on the box I've been having issues getting a shell to run.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Cache Manager ACL Bypass

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2019-12524`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: ACL Manager can be bypassed giving non authorized users to squid-internal-mgr. Possible to bypass other url_regex, but only focused on manager.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: CoreDNS' transfer stanza selection uses lexicographic compare (subzone ACL bypass)

- **Provenance:** Source: `CYBER_CPT/gh_security_lab`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Summary CoreDNS' transfer plugin can select the wrong ACL stanza when both a parent zone and a more-specific subzone are configured. A permissive parent-zone transfer rule can override a restrictive subzone rule (name-dependent), allowing an unauthorized client to perform AXFR/IXFR for the subzone...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: HackTheBox — Control (Walkthrough)

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox — Control (Walkthrough) Control was a fun box made by TRX. The box included: * ACL Bypass * SQL Injection * Service Abuse through path hijacking Initial Recon: To begin, the box was port scanned using nmap: text nmap -sC -sV 10.10.10.167 Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-25 16:39 AEDT...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: Poking Holes in the Firewall: Egress Testing With AllPorts.Exposed

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Poking Holes in the Firewall: Egress Testing With AllPorts.Exposed > **Jargon: Egress Testing** — The process of testing what data or connections are allowed to leave a network, rather than trying to get into it. If you have been even remotely in touch with technology in the pa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: T1572 - Protocol Tunneling

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-284`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1572 - Protocol Tunneling ## Description from ATT&CK Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly e
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Android - getpidcon() Usage in Hardware binder ServiceManager Permits ACL Bypass

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-284`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Android - getpidcon() Usage in Hardware binder ServiceManager Permits ACL Bypass EKU-ID: 50514 CVE: CVE-2019-2023 Author: Google Security Research Published: 2019-03-06 We already reported four bugs in Android that are caused by the use of getpidcon(), which is fundamentally un
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Gradio Blocked Path ACL Bypass Vulnerability

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-284`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary Gradio's Access Control List (ACL) for file paths can be bypassed by altering the letter case of a blocked file or directory path. This vulnerability arises due to the lack of case normalization in the file path validation logic. On case-insensitive file systems, such
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
