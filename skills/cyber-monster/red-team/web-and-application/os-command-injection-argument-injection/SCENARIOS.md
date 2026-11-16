# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`os-command-injection-argument-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Grafana RCE via SMTP server parameter injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: This report is similar to #1180653, except with different parameter injection entrypoint. SMTP server password configuration setting accepts new line characters. This can be used to set non-exported configuration variables.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: GraphQL node interface for ActiveResource models lacks encoding for resource identifier, enabling paramet

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** HackerOne exposes a small number of ActiveResource objects through its GraphQL 'node' interface. ActiveResource objects use HTTP as transport layer in order to fetch data.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Gotenberg has ExifTool stdin argument injection via metadata value newlines (bypass of key sanitizat

- **Provenance:** Source: `CYBER_CPT/gh_security_lab` | CWE: `CWE-20`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Vulnerability Details **CWE**: CWE-20 - Improper Input Validation The metadata value sanitization introduced in v8.30.1 (commit 405f106) only validates metadata KEYS via safeKeyPattern regex.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Mitel SIP Phones Argument Injection Vulnerability

- **Provenance:** Source: `CYBER_CPT/cisa_kev`
- **Context / Surface:** CISA KEV Advisory (en)
- **Root Cause / Analysis:** CVE-2024-41710: Mitel SIP Phones Argument Injection Vulnerability > **Jargon: CVE** — Common Vulnerabilities and Exposures, a standardized public identifier for known cybersecurity vulnerabilities.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Wildcards Spare Tricks

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Wildcards Spare Tricks > Wildcard (aka *glob*) **argument injection** happens when a privileged script runs a Unix binary such as 'tar', 'chown', 'rsync', 'zip', '7z', … with an unquoted wildcard like '*'.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: Tekton Pipeline: Git Resolver Unsanitized Revision Parameter Enables git Argument Injection Leading

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-78`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The git resolver's 'revision' parameter is passed directly as a positional argument to 'git fetch' without any validation that it does not begin with a '-' character. Because git parses flags from mixed positional arguments, an attacker can inject arbitrary 'git fetch'
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Tekton Pipeline: Git Resolver Unsanitized Revision Parameter Enables git Argument Injection Leading

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-78`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Tekton Pipeline: Git Resolver Unsanitized Revision Parameter Enables git Argument Injection Leading to RCE - **OSV ID**: GHSA-94jr-7pqp-xhcq - **CVE**: CVE-2026-40938 - **CVSS**: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H - **Published**: 2026-04-21T20:28:36Z - **Modified**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Sun Java Web Start Plugin Command Line Argument Injection (2012)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-78`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # siunam\'s Website My personal website Home Writeups Research Blog Projects About # #corCTF 2023 Writeup > CTFTime event link: https://ctftime.org/event/1928 ![\\"\\"] (\\"https://raw.githubusercontent.com/siunam321/CTF- Writeups/main/corCTF-2023/images/banner.png\\"/) ## ##Write
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
