# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-artifact-forensics-event-log-artifacts`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB Sherlock: Reaper

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Reaper is the investigation of an NTLM relay attack. The attacker works from within the network to poison an LLMNR response when a victim has a typo in the host in a share path. This results in the victim authenticating to the attacker, who relays the authentication to another wo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB Sherlock: Logjammer

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Logjammer] (/icons/sherlock-logjammer.png) Logjammer is a neat look at some Windows event log analysis. I’ll start with five event logs, security, system, Defender, firewall, and PowerShell, and use EvtxECmd.exe to convert them to JSON. Then I’ll slice them using JQ and some Bas
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB Sherlock: i-like-to

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![i-like-to] (/icons/sherlock-i-like-to.png) i-like-to is the first Sherlock to retire on HackTheBox. It’s a forensics investigation into a compromised MOVEit Transfer server. I start with a memory dump and some collection from the file system, and I’ll use IIS logs, the master fi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Trump Trump

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-345`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Trump Trump (crypto 100) In the task we get access to remote RSA signature service. We also get a picture we are supposed to sign with this service. But the server refuses to sign this specific payload. We can send some random payloads and check how it's signed since we know th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Windows Event IDs and Others for Situational Awareness

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-345`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Windows Event IDs and Others for Situational Awareness Below is a living list of Windows event IDs and other miscellaneous snippets, that may be useful for situational awareness, once you are on a box: / Activity / Powershell to read event logs for the / / --- / --- / / **Lock/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: 4765F3B9-7659-4688-82FC-4CD3224218A2

- **Provenance:** Source: `CYBER_CPT/vcdb` | CWE: `CWE-345`
- **Context / Surface:** Source: vcdb (en)
- **Root Cause / Analysis:** # 4765F3B9-7659-4688-82FC-4CD3224218A2 MEDICAL notes have been found on clear display in a car which was parked in a residential street for almost a week. Mark Atkins said he and other residents of Lowen Bre near Royal Cornwall Hospital at Treliske had been fed up with vehicles b
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
