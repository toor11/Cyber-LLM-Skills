# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`lolbins-and-signed-binary-abuse-execution-proxies`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: T1218.004 - Signed Binary Proxy Execution: InstallUtil

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-284`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1218.004 - Signed Binary Proxy Execution: InstallUtil ## Description from ATT&CK > Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. > **Jargon: Proxy Execution** — Running malicious code by hiding it behind a legitimate, trusted pro
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: T1218.011 - Signed Binary Proxy Execution: Rundll32

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-284`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1218.011 - Signed Binary Proxy Execution: Rundll32 Adversaries may abuse rundll32.exe to proxy execution of malicious code. > **Jargon: Proxy Execution** — Using a legitimate, trusted program to run malicious code on your behalf, acting like a decoy to bypass security checks.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: T1218.005 - Signed Binary Proxy Execution: Mshta

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-284`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1218.005 - Signed Binary Proxy Execution: Mshta > **Jargon: Signed Binary Proxy Execution** — A technique where an attacker abuses a trusted, Microsoft-signed executable to run their malicious code, effectively hiding behind the legitimacy of a built-in Windows tool. Think of
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: T1218.010 - Signed Binary Proxy Execution: Regsvr32

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-284`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1218.010 - Signed Binary Proxy Execution: Regsvr32 *Analogy:* Imagine a highly trusted courier who is always waved through a building's security checkpoint because they have a VIP badge. An adversary doesn't try to sneak past the guard themselves; instead, they hand their mali
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: InstallUtil

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-284`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # InstallUtil ## Execution First of, let's generate a C# payload (with [InstallUtil script] (https://github.com/khr0x40sh/WhiteListEvasion)) that contains shellcode from msfvenom and upload the temp.cs file to victim's machine: 'csharp python InstallUtil.py --cs_file temp.cs --e
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
