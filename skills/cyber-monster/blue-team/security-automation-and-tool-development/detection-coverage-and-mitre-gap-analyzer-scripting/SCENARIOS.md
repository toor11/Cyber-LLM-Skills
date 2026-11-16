# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`detection-coverage-and-mitre-gap-analyzer-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative coverage-analysis failures, each with the artifact that proves the diagnosis.

## Case 1: 92% coverage, zero detections on the technique that mattered

- **Surface & Preconditions:** a coverage dashboard counts rules per ATT&CK tag without checking whether each rule's log source is collected.
- **Root cause & impact:** a large block of rules depends on a log source that was never onboarded, so the number describes content that cannot fire. The gap is invisible precisely because the count is high.
- **Verification & fix:** join every rule's `logsource` to the datasource inventory and report a rule with no matching source as dead content, separately from an actual gap.

## Case 2: One sub-technique covered the whole parent

- **Surface & Preconditions:** the analyzer rolls sub-techniques up to their parent and marks the parent covered when any child has a rule.
- **Root cause & impact:** the parent technique reports as covered while every other sub-technique is undetected. Leadership sees a covered row; the SOC has coverage for one narrow variant.
- **Verification & fix:** report per-sub-technique verdicts, and emit the rollup separately with an explicit note that it is informational only.

## Case 3: Collected but not forwarded

- **Surface & Preconditions:** the inventory records the log source as available on the endpoint while the forwarding policy excludes that channel.
- **Root cause & impact:** rules appear covered because the source "exists". Nothing reaches the SIEM, and investigations find no data for a technique the dashboard calls covered.
- **Verification & fix:** model the inventory as forwarding state, not installability, and represent "configured but disabled" as its own verdict with its own owner.

## Case 4: Rule matched, field never populated

- **Surface & Preconditions:** a rule keys on a field the normalizer does not emit for that vendor.
- **Root cause & impact:** the rule is syntactically valid and its log source is present, but the field is always null, so it never matches. This is a content gap that only shows under field-level analysis or measured validation.
- **Verification & fix:** combine the matrix with field-completeness checks from the normalizer skill, and with measured validation for high-priority techniques.
