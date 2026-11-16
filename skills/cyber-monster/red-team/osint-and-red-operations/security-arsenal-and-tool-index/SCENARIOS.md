# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`security-arsenal-and-tool-index`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Stale Invocation in the Index

- **Surface & Preconditions:** An entry's flags were valid two releases ago and now error out.
- **Root Cause & Impact:** The tool changed a flag name and the index was not version-pinned.
- **Verification & Fix:** Pin the version in the entry, re-run the invocation against a lab target, and record the new flags.

## Case 2: Silent Negative From a Blind Spot

- **Surface & Preconditions:** A tool reports no open ports and the report states the host exposes nothing.
- **Root Cause & Impact:** The invocation used an explicit port list, so unlisted ports were never checked.
- **Verification & Fix:** Record the blind spot in the index, broaden the port argument or add a second tool, and re-run before drawing a negative conclusion.
