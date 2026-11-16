# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`authentication-bypass-header-and-proxy-trust`](SKILL.md) | Family: **Web and Application**

Representative diagnostic case structure for this sub-skill:

## Case 1: Authentication Bypass Header and Proxy Trust Assessment & Verification

- **Surface & Preconditions:** Input, identity, or configuration boundary involving `X-Original-URL`.
- **Root Cause & Impact:** Also Check This Things While Testing 1. Add two 'HOST:' in Request. 2. Try this Headers X-Original-Url: X-Forwarded-Server: X-Host: X-Forwarded-**Host**: X-Rewrite-Url: 3.
- **Verification & Fix:** Confirm with a non-destructive baseline differential and apply the idiomatic control in [`SKILL.md`](SKILL.md).
