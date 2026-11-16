# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](SKILL.md) | Family: **Web and Application**

Representative diagnostic case structure for this sub-skill:

## Case 1: WAF Bypass and Payload Obfuscation Comment and Whitespace Assessment & Verification

- **Surface & Preconditions:** Input, identity, or configuration boundary involving `/**/`.
- **Root Cause & Impact:** Missing server-side invariant enforcement or absent telemetry validation across trust boundaries.
- **Verification & Fix:** Confirm with a non-destructive baseline differential and apply the idiomatic control in [`SKILL.md`](SKILL.md).
