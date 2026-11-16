# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-artifact-forensics-file-system-artifacts`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB Sherlock: Tick Tock

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** A new employee gets a call from the “IT department”, who is actually a malicious actor. They get a TeamViewer connection and launch a Merlin C2 agent. I’ll see through the logs the processes it runs, where Defender catches it, and how it tries to mess with forensics by constantly
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB Sherlock: BFT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** BFT is all about analysis of a Master File Table (MFT). I’ll use Zimmerman tools MFTECmd and Timeline Explorer to find where a Zip archive was downloaded from Google Drive. It is then unzipped to get another zip, which is unzipped to get another zip. That final zip has a Windows
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB Sherlock: i-like-to

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![i-like-to] (/icons/sherlock-i-like-to.png) i-like-to is the first Sherlock to retire on HackTheBox. It’s a forensics investigation into a compromised MOVEit Transfer server. I start with a memory dump and some collection from the file system, and I’ll use IIS logs, the master fi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Active Directory - Recycle Bin

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-345`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Active Directory - Recycle Bin ## Details * Deleted objects have a default retention time of 180 days * Recycle Bin path: 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=example,DC=com' Enable Active Directory Recycle Bin in PowerShell 'ps1 Enable-ADOption
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Why Perimeter Firewall is Not Enough: Lessons from the GoAnywhere MFT Zero-Day

- **Provenance:** Source: `CYBER_CPT/vmware_security` | CWE: `CWE-345`
- **Context / Surface:** Source: vmware_security (en)
- **Root Cause / Analysis:** In September 2025, the cybercriminal group Storm-1175 exploited a zero-day vulnerability in GoAnywhere Managed File Transfer to deploy Medusa ransomware across multiple organizations. The attack succeeded despite perimeter defenses because no signature existed to detect it, and b
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Fortra GoAnywhere MFT Deserialization of Untrusted Data Vulnerability

- **Provenance:** Source: `CYBER_CPT/cisa_kev` | CWE: `CWE-345`
- **Context / Surface:** Source: cisa_kev (en)
- **Root Cause / Analysis:** # CVE-2025-10035: Fortra GoAnywhere MFT Deserialization of Untrusted Data Vulnerability > **Jargon: CVE** — A standardized, public identifier for a known cybersecurity vulnerability, acting like a unique name tag for the flaw. > **Jargon: MFT (Managed File Transfer)** — A type of
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
