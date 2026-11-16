# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-privilege-escalation-credential-and-config-exposure`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Windows Credential Manager

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Windows Credential Manager **ID**: T1555.004 **Type**: Technique **Tactics**: Credential Access **Platforms**: Windows Adversaries may acquire credentials from the Windows Credential Manager.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Unwrapping GPP: Exposing the cPassword Attack Vector using Active (HTB Machine)

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Unwrapping GPP: Exposing the cPassword Attack Vector using Active (HTB Machine) # What is GPP ? Imagine you’re the boss of a big company, and you have a bunch of computers that need to do specific things. Now, instead of running around to each computer and setting everything up
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: T1555.004 - Credentials from Password Stores: Windows Credential Manager

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1555.004 - Credentials from Password Stores: Windows Credential Manager Adversaries may acquire credentials from the Windows Credential Manager. Think of the Windows Credential Manager as a digital wallet built into the operating system; it stores your usernames and passwords
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: 🛠️ Windows Credential Manager

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-269`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # Windows Credential Manager ## Theory Windows Credential Manager is a built-in feature that securely stores sensitive login information for websites, applications, and networks. It houses login credentials such as usernames, passwords, and web addresses. There are four distinct
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Windows Ad No Laps Cpassword

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Local (Admin) password in GPO in windows AD without LAPS [MS LEARN] (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN) 'powershell try { $Cpassword="LjFWQMzS3GWDeav7+0Q0oSoOM43VwD30YZDVaItj8e0" #Ap
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Credential Manager Allows Storing of Plain Text Passwords

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-269`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Credential Manager Allows Storing of Plain Text Passwords Checks if the system allows storage of plain text passwords in Credential Manager. - **Template ID**: windows-credential-manager-plaintext-passwords-allowed - **Severity**: high - **Author**: princechaddha - **Category**
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: client_id

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-269`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # client_id - **Template ID**: dot-credentials-exposure - **Severity**: high - **Author**: theamanrawat - **Category**: Http - **Tags**: exposure, config, credentials, sensitive, token 'yaml id: dot-credentials-exposure info: name: Dot Credentials - Exposure author: theamanrawa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
