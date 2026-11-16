# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ai-assisted-offensive-tooling`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Fabricated CVE in a Draft

- **Surface & Preconditions:** A model summarising scanner output cites a CVE that does not exist for the product.
- **Root Cause & Impact:** The identifier looks plausible and would damage the report's credibility if delivered.
- **Verification & Fix:** Check every identifier against the vendor advisory, drop unsupported claims, and record the verification in the assist log.

## Case 2: Generated Payload Wider Than Intended

- **Surface & Preconditions:** A model drafts a test payload that deletes a resource rather than testing access to it.
- **Root Cause & Impact:** Running it would cause the outage the assessment is meant to avoid.
- **Verification & Fix:** Review every generated payload for scope and destructiveness, run only against a lab copy, and keep the reviewed payload in the assist log.
