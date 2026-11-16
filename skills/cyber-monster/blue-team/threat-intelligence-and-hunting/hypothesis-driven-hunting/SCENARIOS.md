# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`hypothesis-driven-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: An issue was discovered in py-lmdb 0.97. There is a divide-by-zero error in the function mdb_env_ope

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in py-lmdb 0.97. There is a divide-by-zero error in the function mdb_env_open2 if mdb_env_read_header obtains a zero value for a certain size field. NOTE: this outcome occurs w - **CVE**: CVE-2019-16228 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: An issue was discovered in py-lmdb 0.97. For certain values of mn_flags, mdb_cursor_set triggers a m

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in py-lmdb 0.97. For certain values of mn_flags, mdb_cursor_set triggers a memcpy with an invalid write operation within mdb_xcursor_init1. NOTE: this outcome occurs when acces - **CVE**: CVE-2019-16227 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: An issue was discovered in py-lmdb 0.97. For certain values of md_flags, mdb_node_add does not prope

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in py-lmdb 0.97. For certain values of md_flags, mdb_node_add does not properly set up a memcpy destination, leading to an invalid write operation. NOTE: this outcome occurs wh - **CVE**: CVE-2019-16224 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Lua 5.3.5 has a use-after-free in lua_upvaluejoin in lapi.c. For example, a crash outcome might be a

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Lua 5.3.5 has a use-after-free in lua_upvaluejoin in lapi.c. For example, a crash outcome might be achieved by an attacker who is able to trigger a debug.upvaluejoin call in which the arguments have c - **CVE**: CVE-2019-6706 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Sandbox component in Avast Antivirus prior to 20.4 has an insecure permission which could be abused

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Sandbox component in Avast Antivirus prior to 20.4 has an insecure permission which could be abused by local user to control the outcome of scans, and therefore evade detection or delete arbitrary sys - **CVE**: CVE-2021-45335 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: AIOHTTP 3.8.1 can report a "ValueError: Invalid IPv6 URL" outcome, which can lead to a Denial of Ser

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # AIOHTTP 3.8.1 can report a "ValueError: Invalid IPv6 URL" outcome, which can lead to a Denial of Service (DoS). NOTE: multiple third parties dispute this issue because there is no example of a context - **CVE**: CVE-2022-33124 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
