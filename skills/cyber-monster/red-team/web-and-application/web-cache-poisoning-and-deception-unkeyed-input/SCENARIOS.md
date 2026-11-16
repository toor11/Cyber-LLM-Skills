# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-cache-poisoning-and-deception-unkeyed-input`](SKILL.md) | Family: **Web and Application**

Representative diagnostic case structure for this sub-skill:

## Case 1: Web Cache Poisoning and Deception Unkeyed Input Assessment & Verification

- **Surface & Preconditions:** Input, identity, or configuration boundary involving `unkeyed header`.
- **Root Cause & Impact:** Missing server-side invariant enforcement or absent telemetry validation across trust boundaries.
- **Verification & Fix:** Confirm with a non-destructive baseline differential and apply the idiomatic control in [`SKILL.md`](SKILL.md).
