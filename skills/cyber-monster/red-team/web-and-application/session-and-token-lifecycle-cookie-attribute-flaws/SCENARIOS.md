# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`session-and-token-lifecycle-cookie-attribute-flaws`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Cookie Tossing

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Cookie Tossing Description If an attacker can **control a subdomain or the domain of a company or finds an XSS in a subdomain** he will be able to perform this attack.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Cookie Tossing

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-384`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Cookie Tossing ### Description If an attacker can **control a subdomain or the domain of a company or finds an XSS in a subdomain** he will be able to perform this attack. As it was indicated in the Cookies Hacking section, when a **cookie is set to a domain (specifying it) it
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Cross site scripting (XSS) in JupyterHub via Self-XSS leveraged by Cookie Tossing

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-384`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Cross site scripting (XSS) in JupyterHub via Self-XSS leveraged by Cookie Tossing - **OSV ID**: GHSA-7r3h-4ph8-w38g - **CVE**: CVE-2024-28233 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N - **Published**: 2024-03-28T17:08:10Z - **Modified**: 2024-04-03T11:41:34.55489
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Lack of protection against cookie tossing attacks in fastify-csrf

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-384`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Lack of protection against cookie tossing attacks in fastify-csrf Lack of protection against cookie tossing attacks in fastify-csrf - **OSV ID**: GHSA-rc4q-9m69-gqp8 - **CVE**: CVE-2021-29624 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N - **Published**: 2021-05-17T2
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: github.com/gitpod-io/gitpod vulnerable to Cookie Tossing

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-384`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # github.com/gitpod-io/gitpod vulnerable to Cookie Tossing github.com/gitpod-io/gitpod vulnerable to Cookie Tossing - **OSV ID**: GHSA-8pgc-65mj-53h5 - **CVE**: CVE-2024-21583 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N - **Published**: 2024-07-19T06:31:13Z - **Modif
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: github.com/gitpod-io/gitpod vulnerable to Cookie Tossing

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-384`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** Versions of the package github.com/gitpod-io/gitpod/components/server/go/pkg/lib before main-gha.27122; versions of the package github.com/gitpod-io/gitpod/components/ws-proxy/pkg/proxy before main-gha.27122; versions of the package github.com/gitpod-io/gitpod/install/installer/p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Lack of protection against cookie tossing attacks in fastify-csrf

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-384`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact Users that used fastify-csrf with the "double submit" mechanism using cookies with an application deployed across multiple subdomains, e.g. "heroku"-style platform as a service. ### Patches Version 3.1.0 of the fastify-csrf fixes it. See https://github.com/fastify/fast
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
