# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-lateral-movement-winrm-and-wmi`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Bruno

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Bruno is a Windows Active Directory box. I’ll start by finding a .NET sample scanning application on FTP, and after reverse engineering it, discover a ZipSlip vulnerability in how it handles zip archives. Combining that with a DLL hijack, I’ll get a shell as the service account t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Redelegate

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I’ll find files on an open FTP server to start Redelegate. These files include the results of a security audit and a shared KeePass database. I’ll crack the password and get access to MSSQL, where I can enumerate domain users. Then I’ll password spray to get a foothold on the dom
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: VulnCicada

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I'll find an open NFS share on VulnCicada, and exfil two images. One of them has a password on a sticknote, which I'll use to get authenticated to the domain. From there, I'll enumerate ADCS and find the DC vulnerable to ESC8. I'll show how to do this attack from Linux, creating
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Hathor

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Hathor is an insane box that lives up to the difficulty. I’ll start with some default creds logging into a mojoPortal website. From there, I’ll figure out how to upload a webshell, and copy it to get the right extension. All my efforts to get a shell are blocked, and I’ll do a de
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Intelligence

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Intelligence was a great box for Windows and Active Directory enumeration and exploitation. I’ll start with a lot of enumeration against a domain controller. Eventually I’ll brute force a naming pattern to pull down PDFs from the website, finding the default password for new user
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
