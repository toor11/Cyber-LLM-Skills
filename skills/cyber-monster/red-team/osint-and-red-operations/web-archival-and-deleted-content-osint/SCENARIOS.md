# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-archival-and-deleted-content-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Claim About 2023 Content Cited to a 2026 Capture

- **Surface & Preconditions:** A report states what a page said in 2023 and links the archive's default playback.
- **Root Cause & Impact:** The default playback resolves to a recent capture, which shows different content.
- **Verification & Fix:** List captures for the range, pick the one bracketing 2023, and cite that timestamp explicitly.

## Case 2: Missing Content Attributed to Never Existing

- **Surface & Preconditions:** A page's key section is absent from every capture, and the report concludes it was never there.
- **Root Cause & Impact:** The section was rendered client-side and never entered the archived HTML.
- **Verification & Fix:** Note the rendering model, check the crawl index for a rendered capture, and state the limitation rather than concluding absence.
