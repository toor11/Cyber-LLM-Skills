# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sql-injection-postgres-variants`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Zetta

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-89`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Zetta starts off different from the start, using FTP Bounce attacks to identify the IPv6 address of the box, and then finding RSync listening on IPv6 only. I'll use limited RSync access to get the size of a user's password, and then brute force it to get access to the roy home di
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Hack into Skynet

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-89`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # RootMe CTF writeup ![\\"M.] (\\"https://miro.medium.com/v2/da:true/resize:fill:88:88/0*PwAnIgOV6vliAnLl\\") M. Jalil Ahmad, · Follow 4 min read · Oct 28, 2023 1 Listen Share RootMe is a beginner level ctf on tryhackme. Where you are required to get root level access of provided
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: SQL injection vulnerability in Jeecg-boot v.3.5.0 and before allows a local attacker to cause a deni

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-89`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # SQL injection vulnerability in Jeecg-boot v.3.5.0 and before allows a local attacker to cause a denial of service via the Benchmark, PG_Sleep, DBMS_Lock.Sleep, Waitfor, DECODE, and DBMS_PIPE.RECEIVE_M - **CVE**: CVE-2023-38905 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
