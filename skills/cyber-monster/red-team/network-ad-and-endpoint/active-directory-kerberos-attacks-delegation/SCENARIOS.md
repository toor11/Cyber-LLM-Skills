# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-kerberos-attacks-delegation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Constrained Delegation

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Constrained Delegation Using this a Domain admin can **allow** a computer to **impersonate a user or computer** against any **service** of a machine. - **Service for User to self (_S4U2self_):** If a **service account** has a _userAccountControl_ value containing...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Resource-based Constrained Delegation

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Resource-based Constrained Delegation {{#include ../../banners/hacktricks-training.md}} Basics of Resource-based Constrained Delegation This is similar to the basic [Constrained Delegation] (constrained-delegation.md) but **instead** of giving permissions to an **object** to **impersonate any user...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Unconstrained Delegation

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Unconstrained Delegation Unconstrained delegation This a feature that a Domain Administrator can set to any **Computer** inside the domain. Then, anytime a **user logins** onto the Computer, a **copy of the TGT** of that user is going to be **sent inside the TGS** provided by the DC **and saved in...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: HTB: Rebound

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Rebound is a monster Active Directory / Kerberos box. I’ll start off with a RID-cycle attack to get a list of users, and combine AS-REP-Roasting with Kerberoasting to get an crackable hash for a service account. That password is shared by a domain user, and I’ll find a bad ACL th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Abusing S4U2Self for Active Directory Pivoting

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-269`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Abusing S4U2Self for Active Directory Pivoting ### **TL;DR** If you only have access to a valid machine hash > **Jargon: Machine Hash** — The cryptographic secret (essentially a password equivalent) belonging to a computer account in Active Directory, rather than a human user a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Bruno

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Bruno is a Windows Active Directory box. I’ll start by finding a .NET sample scanning application on FTP, and after reverse engineering it, discover a ZipSlip vulnerability in how it handles zip archives. Combining that with a DLL hijack, I’ll get a shell as the service account t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Abusing Delegation with Impacket (Part 3): Resource-Based Constrained Delegation

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-269`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Abusing Delegation with Impacket (Part 3): Resource-Based Constrained Delegation This blog has been cross-posted. We’re grateful to Hunter for allowing us to share this insightful work—you can check out the original post in full [HERE] (https://hunio.org/posts/security/abusing-d
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Kerberos Delegation - Resource Based Constrained Delegation

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Kerberos Delegation - Resource Based Constrained Delegation Resource-based Constrained Delegation was introduced in Windows Server 2012. > The user sends a Service Ticket (ST) to access the service ("Service A"), and if the service is allowed to delegate to another pre-defined
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
