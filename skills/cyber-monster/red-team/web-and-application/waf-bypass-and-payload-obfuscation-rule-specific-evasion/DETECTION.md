# Detection Signals and Blue-Team Handoff

> Sub-skill: [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Response headers such as `cf-ray`, `x-amzn-waf-action`, or `x-sucuri-id` queried repeatedly by one client enumerating the WAF vendor.
- A burst of requests that each elicit a 403 or 406 block page followed by one 200 on the same parameter.
- 429 or CAPTCHA challenge events clustered by source IP, indicating rate-based defence engagement.
- WAF rule-hit logs showing the canonical signature firing while a near-identical variant on the same route does not.
- Request bodies padded just beyond the configured `request_body_limit` recorded by the edge.
- Access to paths listed in the rule-set exemption config correlated with unscanned payloads at the origin.
- User-Agent or path patterns matching known WAF-fingerprinting tools such as wafw00f or nuclei waf tags in access logs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
