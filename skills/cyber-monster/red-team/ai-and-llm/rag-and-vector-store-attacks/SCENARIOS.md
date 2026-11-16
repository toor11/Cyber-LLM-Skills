# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`rag-and-vector-store-attacks`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Foreign Chunk Occupies a Result Slot

- **Surface & Preconditions:** Retrieval filters by tenant after the vector search returns top-k.
- **Root Cause & Impact:** A foreign chunk consumes one of the slots, and the caller either loses their own result or sees metadata from another tenant.
- **Verification & Fix:** Move the tenant filter into the search call, assert every returned chunk's tenant, and re-run the cross-tenant test.

## Case 2: Open Ingestion Endpoint

- **Surface & Preconditions:** The ingestion API accepts documents from any authenticated caller with no per-source authorisation.
- **Root Cause & Impact:** Any user can place text in the index that later appears in another user's context.
- **Verification & Fix:** Require per-source write authorisation, record owner metadata on every chunk, and test ingestion from an unauthorised account.
