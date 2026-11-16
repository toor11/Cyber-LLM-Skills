# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`llm-data-exfiltration-and-leakage`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Answer Contains Another Tenant's Document

- **Surface & Preconditions:** Retrieval applies no tenant filter and the context includes a foreign chunk.
- **Root Cause & Impact:** The model incorporates the foreign content into an answer the user receives, which is a data breach.
- **Verification & Fix:** Filter in the query, assert chunk tenants, test with two accounts, and review logs for prior disclosures.

## Case 2: Client Fetches a Model-Supplied Image URL

- **Surface & Preconditions:** The chat client renders images from URLs in the model's answer.
- **Root Cause & Impact:** An injected instruction makes the model emit a URL containing sensitive context as a query parameter, which the client fetches.
- **Verification & Fix:** Apply an outbound allowlist before any fetch, stop auto-fetching model-supplied URLs, and test with a non-allowlisted host.
