# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-acl-genericall-writedacl`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Fluffy

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Fluffy is an assume-breach Windows Active Directory challenge. I'll start by exploiting CVE-2025-24071 / CVE-2025-24055, a vulnerability in how Windows handles library-ms files in zip archives, leading to authentication attempts to the attacker. I'll get a NetNTLMv2 and crack it.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: BabyTwo

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Another Windows box where I’ll try username as password and find two accounts. From those I’ll get access to the SYSVOL share, where I can poison a logon script to give me a reverse shell when the user logs in. That user has control over another service account that is meant to a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: PivotAPI

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![PivotAPI] (https://0xdfimages.gitlab.io/img/pivotapi-cover.png) PivotAPI had so many steps. It starts and ends with Active Directory attacks, first finding a username in a PDF metadata and using that to AS-REP Roast. This user has access to some binaries related to managing a da
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Infiltrator

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Infiltrator] (/img/infiltrator-cover.png) Infiltrator is a very long box. It starts out with some people on a website. I’ll use those names to make usernames and brute force to find the username format. Then I’ll AS-REP-Roast to get initial creds. That user doesn’t have much, bu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Administrator

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Administrator] (/img/administrator-cover.png) Administrator is a pure Active Directory challenge. I’ll start with creds for a user, and use them to collect Bloodhound data on the domain. I’ll find that I can modify a user’s password, and that user can modify another user’s passw
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Puppy

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Puppy] (/img/puppy-cover.png) Puppy is a Windows Active Directory pentest simulation. It starts with a set of creds in the HR group, which a common target of phishing attacks. That user has GenericWrite over the Developers group, so I’ll add my user and get access to SMB shares
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
