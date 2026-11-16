# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`network-protocol-attacks-capture-and-intercept`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Gofer

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Gofer starts with a proxy that requires auth. I’ll bypass this using different HTTP verbs, and get access to the proxy that allows for gopher protocol. I’ll use that to interact with an internal SMTP server and send a phishing email to one of the users with a LibreOffice Writer (
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Exploit Development – A Sincere Form of Flattery

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Exploit Development – A Sincere Form of Flattery Recently, BHIS penetration tester Dale Hobbs was on an Internal Network Penetration Test and came across an RPC-based arbitrary command execution vulnerability in his vulnerability scan results. > **Jargon: RPC (Remote Procedure
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Strutted

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** # Strutted Strutted is a box released directly to retired on HackTheBox highlighting the CVE-2024-53677 vulnerability in Apache Struts that was made public in December 2024. It is a bit tricky to exploit, but I’ll use it to upload a webshell and get a foothold. From there, I’ll u
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB Endgame: XEN

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Endgame XEN is all about owning a small network behind a Citrix virtual desktop environment. I’ll phish creds for the Citrix instance from users in the sales department, and then use them to get a foothold. I’ll break out of the restrictions in that environment, and then get admi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Bamboo

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Bamboo offers a Squid HTTP proxy through which I’ll access a PaperCut NG instance. I’ll use Spose to scan through the proxy and discover the print management application. I’ll exploit an authentication bypass vulnerability in PaperCut and use application access to enabling print
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Carrier

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Carrier-cover] (https://0xdfimages.gitlab.io/img/carrier-cover.png) Carrier was awesome, not because it super hard, but because it provided an opportunity to do something that I hear about all the time in the media, but have never been actually tasked with doing - BGP Hijacking.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
