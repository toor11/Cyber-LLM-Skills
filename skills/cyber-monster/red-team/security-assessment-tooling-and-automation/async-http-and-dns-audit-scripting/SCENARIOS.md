# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`async-http-and-dns-audit-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Scope Slip Through a Wildcard CNAME

- **Surface & Preconditions:** An audit script enumerates a subdomain list; one name is a CNAME to a third-party SaaS endpoint outside the engagement.
- **Root Cause & Impact:** Without a post-resolution scope check the script follows the CNAME and sends traffic to a host the client does not control.
- **Verification & Fix:** Abort on any resolved address outside the authorised ranges, log the CNAME chain, and report the exception to the engagement owner before continuing.

## Case 2: Rate Limit Breach From a Retry Loop

- **Surface & Preconditions:** A probe retries every failed request three times with no per-host ceiling, multiplying load on one origin.
- **Root Cause & Impact:** The retry loop is the cause of the incident, not the target's behaviour; the client sees an outage it created.
- **Verification & Fix:** Replace global retries with a per-host token bucket, record the retry count in the JSONL row, and re-run at the agreed rate.
