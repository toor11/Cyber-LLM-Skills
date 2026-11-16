# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`purple-team-telemetry-validation-harnesses`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative validation failures, each with the artifact that proves the diagnosis.

## Case 1: Coverage reported from rule inventory

- **Surface & Preconditions:** a coverage script counts rules whose ATT&CK tag matches a technique and reports that technique as covered.
- **Root cause & impact:** the rule may reference a field the log source never populates, or the log source may not be collected at all. The report says covered; an actual execution produces nothing.
- **Verification & fix:** execute a benign case with a correlation id and require the event to appear. Rule inventory is a starting list of hypotheses, not evidence.

## Case 2: The lab was left dirty

- **Surface & Preconditions:** a case creates a test service or registry value, and the cleanup call sits after the assertion that can raise.
- **Root cause & impact:** a failed case skips cleanup, the artefact persists, and the next run's "no alert" result may be caused by the leftover state rather than by a real gap. Every subsequent measurement is suspect.
- **Verification & fix:** put cleanup in a `finally` block, verify host baseline afterwards, and treat cleanup failure as exit code `2` that stops the run.

## Case 3: Collection gap misattributed to detection

- **Surface & Preconditions:** a case produces no alert, and the team opens a detection-engineering ticket.
- **Root cause & impact:** the raw event was never collected — the agent did not forward that channel. Detection engineering cannot fix it, and the ticket bounces between teams while the gap persists.
- **Verification & fix:** assert three separate verdicts (collected, fired, fields) so the gap is attributed to the correct owner on the first pass.

## Case 4: Layer that will not import

- **Surface & Preconditions:** a layer is hand-built with `"layer": "4.0"` or a missing `domain`.
- **Root cause & impact:** the Navigator refuses or silently upgrades the layer, so the reported scores do not match the file the team reviews.
- **Verification & fix:** emit `versions.layer: "4.5"` with a valid `domain` and validate with `mitreattack-python` before publishing.
