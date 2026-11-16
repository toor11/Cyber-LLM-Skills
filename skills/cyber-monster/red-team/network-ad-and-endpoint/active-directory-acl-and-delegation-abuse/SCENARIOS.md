# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-acl-and-delegation-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Unconstrained Delegation

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Unconstrained Delegation Unconstrained delegation This a feature that a Domain Administrator can set to any **Computer** inside the domain. Then, anytime a **user logins** onto the Computer, a **copy of the TGT** of that user is going to be **sent inside the TGS** provided by the DC **and saved in...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: RustyKey

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** RustyKey starts as an assume breach Windows AD box, with initial creds provided for a low privilege account. I’ll collect BloodHound data and find some interesting computer accounts. I’ll Timeroast and crack the password for one of these computer accounts. This account can add it
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Phantom

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I’ll start with guest share access where I’ll find an email with an attachment containing a default password. I’ll brute force users on the domain, and spray the password to find a user who hasn’t changed it. That user has access to another SMB share where I’ll find a VeraCrypt v
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: University

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** University is a monster insane level machine. I'll start with a website and exploit a CVE in the process of generating a PDF copy of my profile to get a shell on the host. I'll find the same user's creds in a PowerShell script, and use them to log into not only this host, but two
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Bruno

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Bruno is a Windows Active Directory box. I’ll start by finding a .NET sample scanning application on FTP, and after reverse engineering it, discover a ZipSlip vulnerability in how it handles zip archives. Combining that with a DLL hijack, I’ll get a shell as the service account t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: TombWatcher

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** TombWatcher is an assume breach active directory box. I’ll use BloodHound to find a path to another user with targeted Kerberoasting, GMSA, ForceChangePassword, and a shadow credential. This user has access to the AD Recycle Bin, where I’ll recover an old ADCS admin account. I’ll
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Fluffy

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Fluffy is an assume-breach Windows Active Directory challenge. I'll start by exploiting CVE-2025-24071 / CVE-2025-24055, a vulnerability in how Windows handles library-ms files in zip archives, leading to authentication attempts to the attacker. I'll get a NetNTLMv2 and crack it.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
