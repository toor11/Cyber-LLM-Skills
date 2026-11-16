# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssti-jinja2-and-twig`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Talkative

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-1336`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Talkative is about hacking a communications platform. I’ll start by abusing the built-in R scripter in jamovi to get execution and shell in a docker container. There I’ll find creds for the Bolt CMS instance, and use those to log into the admin panel and edit a template to get co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Jinja2 SSTI

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-1336`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Jinja2 SSTI ## **Lab** 'python from flask import Flask, request, render_template_string app = Flask(__name__) @app.route("/") def home(): if request.args.get('c'): return render_template_string(request.args.get('c')) else: return "Hello, send someting inside the param 'c'!" i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Craft CMS vulnerable to Potential Remote Code Execution via missing path normalization & Twig SSTI

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-1336`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Craft CMS vulnerable to Potential Remote Code Execution via missing path normalization & Twig SSTI Craft CMS vulnerable to Potential Remote Code Execution via missing path normalization & Twig SSTI - **OSV ID**: GHSA-f3cw-hg6r-chfv - **CVE**: CVE-2024-52293 - **CVSS**: CVSS:3.1
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Craft CMS vulnerable to Potential Remote Code Execution via missing path normalization & Twig SSTI

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1336`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary Missing 'normalizePath' in the function 'FileHelper::absolutePath' could lead to Remote Code Execution on the server via twig SSTI. '(Post-authentication, ALLOW_ADMIN_CHANGES=true)' ### Details Note: This is a sequel to [CVE-2023-40035] (https://github.com/craftcms/cms
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Craft CMS Vulnerable to Authenticated RCE via Twig SSTI - create() function + Symfony Process gadget

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-1336`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Craft CMS Vulnerable to Authenticated RCE via Twig SSTI - create() function + Symfony Process gadget Craft CMS Vulnerable to Authenticated RCE via Twig SSTI - create() function + Symfony Process gadget - **OSV ID**: GHSA-94rc-cqvm-m4pw - **CVE**: CVE-2026-28695 - **Published**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
