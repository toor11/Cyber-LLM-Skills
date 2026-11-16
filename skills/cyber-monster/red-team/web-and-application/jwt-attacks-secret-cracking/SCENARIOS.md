# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`jwt-attacks-secret-cracking`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Craft

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-347`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Craft] (https://0xdfimages.gitlab.io/img/craft-cover.png) Craft was a really well designed medium box, with lots of interesting things to poke at, none of which were too difficult. I’ll find credentials for the API in the Gogs instance, as well as the API source, which allows me
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Authentication Bypass via Default JWT Secret in NocoBase docker-compose Deployments

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Authentication Bypass via Default JWT Secret in NocoBase docker-compose Deployments - **OSV ID**: GHSA-mv7p-34fv-4874 - **CVE**: CVE-2025-13877 - **Published**: 2025-12-09T17:42:53Z - **Modified**: 2025-12-09T17:57:52.568117Z - **Affected Packages**: @nocobase/auth - **Ecosyste
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Dpanel's hard-coded JWT secret leads to remote code execution

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Dpanel's hard-coded JWT secret leads to remote code execution - **OSV ID**: GHSA-j752-cjcj-w847 - **CVE**: CVE-2025-30206 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - **Published**: 2025-04-15T14:17:25Z - **Modified**: 2025-04-23T15:09:48Z - **Affected Packages**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: InfluxDB Empty JWT Secret Key Authentication Bypass (CVE-2019-20933)

- **Provenance:** Source: `CYBER_CPT/vulhub` | CWE: `CWE-347`
- **Context / Surface:** Source: vulhub (en)
- **Root Cause / Analysis:** # InfluxDB Empty JWT Secret Key Authentication Bypass (CVE-2019-20933) InfluxDB is an open-source time series database developed by the company InfluxData. InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in 'services/httpd/handler.go'
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Apache Superset Hardcoded JWT Secret Key Leads to Authentication Bypass (CVE-2023-27524)

- **Provenance:** Source: `CYBER_CPT/vulhub` | CWE: `CWE-347`
- **Context / Surface:** Source: vulhub (en)
- **Root Cause / Analysis:** # Apache Superset Hardcoded JWT Secret Key Leads to Authentication Bypass (CVE-2023-27524) Apache Superset is an open-source data exploration and visualization platform designed to be visual, intuitive, and interactive. Apache Superset contains a hardcoded JWT secret key vulnerab
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Flowise: Weak Default JWT Secrets

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-347`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** **Detection Method:** Kolega.dev Deep Code Scan / Attribute / Value / /---/---/ / Severity / Critical / / Location / packages/server/src/enterprise/middleware/passport/index.ts:29-34 / / Practical Exploitability / High / / Developer Approver / faizan@kolega.ai / ### Description J
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
