# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`prototype-pollution-server-side`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: n8n has XML Node Prototype Pollution that to RCE

- **Provenance:** Source: `CYBER_CPT/gh_security_lab`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Impact An authenticated user with permission to create or modify workflows could achieve global prototype pollution via the XML Node leading to RCE when combined with other nodes exploiting the prototype pollution. Patches The issue has been fixed in n8n versions 1.123.32, 2.17.4, and 2.18.1.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Haraka affected by DoS via '__proto__' email header

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1321`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary Sending an email with '__proto__:' as a header name crashes the Haraka worker process. ### Details The header parser at 'node_modules/haraka-email-message/lib/header.js:215-218' stores headers in a plain '{}' object: 'javascript _add_header(key, value, method) { thi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Locutus has Prototype Pollution via __proto__ Key Injection in unserialize()

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-1321`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Locutus has Prototype Pollution via __proto__ Key Injection in unserialize() - **OSV ID**: GHSA-4mph-v827-f877 - **CVE**: CVE-2026-33993 - **Published**: 2026-03-27T17:57:39Z - **Modified**: 2026-03-30T20:34:55.046784Z - **Affected Packages**: locutus - **Ecosystem**: npm ## Su
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: LangSmith Client SDKs has Prototype Pollution in langsmith-sdk via Incomplete '__proto__' Guard in I

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1321`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # GHSA-fw9q-39r9-c252: Prototype Pollution via Incomplete Lodash 'set()' Guard in 'langsmith-sdk' **Severity:** Medium (CVSS ~5.6) **Status:** Fixed in 0.5.18 --- ## Summary The LangSmith JavaScript/TypeScript SDK ('langsmith') contains an incomplete prototype pollution fix in it
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Locutus has Prototype Pollution via __proto__ Key Injection in unserialize()

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1321`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The 'unserialize()' function in 'locutus/php/var/unserialize' assigns deserialized keys to plain objects via bracket notation without filtering the '__proto__' key. When a PHP serialized payload contains '__proto__' as an array or object key, JavaScript's '__proto__' s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1321`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Denial of Service via **proto** Key in mergeConfig ### Summary The 'mergeConfig' function in axios crashes with a TypeError when processing configuration objects containing '__proto__' as an own property. An attacker can trigger this by providing a malicious configuration objec
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-1321`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig - **OSV ID**: GHSA-43fc-jf86-j433 - **CVE**: CVE-2026-25639 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H - **Published**: 2026-02-09T17:46:14Z - **Modified**: 2026-03-03T05:27:19.212052Z - **A
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
