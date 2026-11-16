# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sarif-and-assessment-report-automation`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Trend Line Reset Every Run

- **Surface & Preconditions:** A dashboard shows every finding as new after each scan.
- **Root Cause & Impact:** The normaliser omitted `partialFingerprints`, so the consumer treated each result as unfamiliar.
- **Verification & Fix:** Compute fingerprints from path, rule, and normalised snippet, and confirm the set is identical across two runs on unchanged code.

## Case 2: Two Tools' Findings Collapsed Into One

- **Surface & Preconditions:** A merged report shows a single SQL injection finding where two scanners reported different sinks.
- **Root Cause & Impact:** Both tools used the same bare `ruleId`, and deduplication keyed on it.
- **Verification & Fix:** Namespace the rule id per tool, deduplicate on location plus fingerprint, and keep both rule ids on the merged finding.
