# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`linux-privilege-escalation-nfs-and-share-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Slonik

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Slonik showcases some interesting Linux techniques around NFS and PostgreSQL. I’ll start with an insecurely configured NFS mount where I can list and read files from anywhere on the filesystem as any user except root. I’ll find hashes for a service account in the shadow file and
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Scepter

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Scepter starts with an open NFS share exposing some client authentication certificates. Most have been revoked, but I’m able to crack the password on the other and authenticate with it. That user can change the password of the next user, and from there I’ll abuse ESC14 to get aut
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Squashed

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Squashed abuses a couple of NFS shares in a nice introduction to NFS. First I'll get access to a web directory, and, after adjusting my local userid to match that one required by the system, upload a webshell and get execution. Then I'll get an X11 magic cookie from a different N
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: NFS No Root Squash Misconfiguration Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # NFS No Root Squash Misconfiguration Privilege Escalation {{#include ../../banners/hacktricks-training.md}} ## Squashing Basic Info NFS will usually (specially in linux) trust the indicated 'uid' and 'gid' by the client conencting to access the files (if kerberos is not used). H
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
