# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssti-node-and-client-engines`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Client Side Template Injection (CSTI)

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Client Side Template Injection (CSTI) Summary It is like a [**Server Side Template Injection**] (ssti-server-side-template-injection/index.html) but in the **client**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Client Side Template Injection (CSTI)

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-1336`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Client Side Template Injection (CSTI) ## Summary It is like a [**Server Side Template Injection**] (ssti-server-side-template-injection/index.html) but in the **client**. The **SSTI** can allow you to **execute code** on the remote server, the **CSTI** could allow you to **execu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Catalog

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-1336`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Catalog (easy) - Web Exploitation 'node Error: /app/views/cat.ejs:21 19/ 20/ >> 21/ 22/ 23/ 24/ Could not find the include file "descriptions/asd" at getIncludePath (/app/node_modules/ejs/lib/ejs
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: valentine

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-1336`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** Please see original writeup here: https://www.youtube.com/watch?v=diln4KD57xA Solution: 1. Bypass filtering with delimiter on nodejs render call 2. SSTI into EJS 3. Profit if you see string ctftimecanary or 6fc9b35adab50fbbacb1d44cf61727db54554218 send your environment to 'http
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
