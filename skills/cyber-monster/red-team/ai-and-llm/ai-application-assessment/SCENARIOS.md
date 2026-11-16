# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ai-application-assessment`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Assessment That Only Tested Prompts

- **Surface & Preconditions:** A report states low risk after twenty jailbreak attempts, and the application renders model output as HTML.
- **Root Cause & Impact:** The output surface was never assessed, and a stored response executes in a victim's browser.
- **Verification & Fix:** Add the output probe, escape at render, and re-issue the assessment as a surface matrix with the gap recorded.

## Case 2: Tool With Broader Credentials Than the User

- **Surface & Preconditions:** A retrieval tool uses a service account with read access to every tenant.
- **Root Cause & Impact:** Any user whose query reaches that tool can retrieve another tenant's documents.
- **Verification & Fix:** Scope the credential per user, apply the tenant filter inside the query, and test with two accounts.
