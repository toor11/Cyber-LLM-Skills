# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`serverless-and-function-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Securing AWS Lambda function URLs

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-269`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** AWS recently launched [Lambda function URLs] (https://aws.amazon.com/blogs/aws/announcing-aws-lambda-function-urls-built-in-https-endpoints-for-single-function-microservices/), a [new feature] (https://aws.amazon.com/blogs/aws/announcing-aws-lambda-function-urls-built-in-https-endp
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: h3: SSE Event Injection via Unsanitized Carriage Return ('\r') in EventStream Data and Comment Field

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The 'EventStream' class in h3 fails to sanitize carriage return ('\r') characters in 'data' and 'comment' fields. Per the SSE specification, '\r' is a valid line terminator, so browsers interpret injected '\r' as line breaks. This allows an attacker to inject arbitrary
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Google Calendar Event Injection with MailSniper

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-269`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Google Calendar Event Injection with MailSniper > **Jargon: Event Injection** — The ability for an attacker to insert unauthorized appointments or events into a victim's calendar application without their explicit consent or interaction. > **Jargon: MailSniper** — A PowerShell
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: h3: SSE Event Injection via Unsanitized Carriage Return ('\r') in EventStream Data and Comment Field

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-269`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # SSE Event Injection via Unsanitized Carriage Return ('\r') in EventStream Data and Comment Fields (Bypass of CVE Fix) - **OSV ID**: GHSA-4hxc-9384-m385 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N - **Published**: 2026-03-20T20:50:38Z - **Modified**: 2026-03-20T21:0
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: AWS - Lambda Function URL Public Exposure (AuthType NONE + Public Invoke Policy)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # AWS - Lambda Function URL Public Exposure (AuthType NONE + Public Invoke Policy) Turn a private Lambda Function URL into a public unauthenticated endpoint by switching the Function URL AuthType to NONE and attaching a resource-based policy that grants lambda:InvokeFunctionUrl t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Serverless / FaaS Security Cheat Sheet

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Serverless / FaaS Security Cheat Sheet ## Introduction Serverless computing (Functions as a Service — FaaS) platforms such as AWS Lambda, Azure Functions, and Google Cloud Functions simplify application development and scaling. However, the execution model (short-lived, event-d
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
