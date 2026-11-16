# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`graphql-security-introspection-and-schema`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Graphql introspection is enabled and leaks details about the schema

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi team ! i've found a misconfiguration in your graphql Api on the endpoint https://www.on-running.com/en-in/graphql in which an attacker is able to run a graphql interospection query to fetch schemas , types , fields , available query operations , after running...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: GraphQL Armor Max-Depth Plugin Bypass via Introspection Query Obfuscation

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-20`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary A query depth restriction using the 'max-depth' property can be bypassed if 'ignoreIntrospection' is enabled (which is the default configuration) by naming your query/fragment '__schema'. ### Details At the start of the 'countDepth' function, we have the following che
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: GraphQL API Detection

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-20`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # GraphQL API Detection - **Template ID**: graphql-detect - **Severity**: info - **Author**: nkxxkn,elsfa7110,ofjaaah,exceed - **Category**: Http - **Tags**: tech, graphql, discovery 'yaml id: graphql-detect info: name: GraphQL API Detection author: nkxxkn,elsfa7110,ofjaaah,exc
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: GraphQL Armor Cost-Limit Plugin Bypass via Introspection Query Obfuscation

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-20`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # GraphQL Armor Cost-Limit Plugin Bypass via Introspection Query Obfuscation - **OSV ID**: GHSA-733v-p3h5-qpq7 - **CVSS**: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L - **Published**: 2025-04-25T15:14:36Z - **Modified**: 2025-04-29T16:45:56Z - **Affected Packages**: @escape.tech
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: GraphQL Armor Max-Depth Plugin Bypass via Introspection Query Obfuscation

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-20`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # GraphQL Armor Max-Depth Plugin Bypass via Introspection Query Obfuscation - **OSV ID**: GHSA-hmfr-rx46-4jx2 - **CVSS**: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L - **Published**: 2025-08-26T18:42:37Z - **Modified**: 2025-08-26T18:42:37Z - **Affected Packages**: @escape.tech/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Parse Server - GraphQL Schema Information Disclosure

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-20`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Parse Server - GraphQL Schema Information Disclosure / - **Template ID**: CVE-2025-53364 - **Severity**: medium - **Author**: securitytaters - **CVE**: CVE-2025-53364 - **Category**: Http - **Tags**: cve, cve2025, parse, graphql, exposure, vuln, vkev 'yaml id: CVE-2025-53364
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Apollo Server GraphQL Introspection - Detect

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-20`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Apollo Server GraphQL Introspection - Detect Apollo Server GraphQL introspection was detected. - **Template ID**: apollo-server-detect - **Severity**: info - **Author**: idealphase - **Category**: Http - **Tags**: apollo, detect, graphql, tech, discovery 'yaml id: apollo-serv
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
