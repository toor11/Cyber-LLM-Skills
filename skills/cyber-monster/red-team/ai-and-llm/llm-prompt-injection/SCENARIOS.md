# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`llm-prompt-injection`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Retrieved Chunk Redirects a Tool Call

- **Surface & Preconditions:** A support assistant reads a knowledge-base article and has an email tool available.
- **Root Cause & Impact:** An article containing an instruction to forward the conversation causes a tool call to an external address.
- **Verification & Fix:** Remove the email tool from the retrieval path, test the injected article again, and require the tool call to be absent in the differential.

## Case 2: Stored Injection in Shared Memory

- **Surface & Preconditions:** An assistant stores user notes in a shared memory store read by other users' sessions.
- **Root Cause & Impact:** One user's note contains instructions that affect another user's later answers.
- **Verification & Fix:** Scope memory per user, test with two accounts, and confirm the second account's answer is unaffected by the first account's note.
