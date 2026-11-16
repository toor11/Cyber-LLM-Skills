# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`client-side-security-bypasses`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Hidden Input

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-602`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** **Web - Hidden input - 50pts** Enoncé : ' Login if you can :) ' **Résolution :** Un champs caché **debug** est présent sur la page de login, par défaut il est défini à 0. Après plusieurs tests d'authentification aucune erreur n'est renvoyée. Par contre le si on défini le cham
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Hidden Input

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-602`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Hidden Input, Web, 50pts ## Problem Can you log in? ## Solution Getting a hint from the name of the question, it has something to do with hidden input. On viewing the source code, we find that there is a hidden input, **debug**. On turning it to **1** and entering random values
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: An issue was discovered in xdLocalStorage through 2.0.5. The receiveMessage() function in xdLocalSto

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-602`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in xdLocalStorage through 2.0.5. The receiveMessage() function in xdLocalStorage.js does not implement any validation of the origin of web messages. Remote attackers who can en - **CVE**: CVE-2015-9545 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: An issue was discovered in xdLocalStorage through 2.0.5. The postData() function in xdLocalStoragePo

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-602`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in xdLocalStorage through 2.0.5. The postData() function in xdLocalStoragePostMessageApi.js specifies the wildcard (*) as the targetOrigin when calling the postMessage() functi - **CVE**: CVE-2020-11610 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: OpenClaw's dashboard leaked gateway auth material via browser URL/query and localStorage

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-602`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # OpenClaw's dashboard leaked gateway auth material via browser URL/query and localStorage OpenClaw's dashboard leaked gateway auth material via browser URL/query and localStorage - **OSV ID**: GHSA-rchv-x836-w7xp - **CVSS**: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N - **Publi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: @fastify/static vulnerable to route guard bypass via encoded path separators

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-602`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # @fastify/static vulnerable to route guard bypass via encoded path separators - **OSV ID**: GHSA-x428-ghpx-8j92 - **CVE**: CVE-2026-6414 - **CVSS**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N - **Published**: 2026-04-16T22:34:03Z - **Modified**: 2026-04-16T22:51:44.453228Z - *
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
