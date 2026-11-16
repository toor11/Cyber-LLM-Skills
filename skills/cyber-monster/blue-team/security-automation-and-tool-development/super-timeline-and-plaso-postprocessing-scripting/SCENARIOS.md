# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`super-timeline-and-plaso-postprocessing-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative timeline-reduction failures, each with the artifact that proves the diagnosis.

## Case 1: The timeline showed nothing happened

- **Surface & Preconditions:** a reducer pivots ±15 minutes around a seed expressed in local time, against a UTC export.
- **Root cause & impact:** the windows land three hours off, so no rows qualify and the report states that nothing occurred around the incident. The most dangerous failure mode in timeline work is a confident empty result.
- **Verification & fix:** parse seeds with an explicit offset, assert that each seed appears in the output, and fail the run when a seed is not found inside its own window.

## Case 2: The persistence entry was filtered as noise

- **Surface & Preconditions:** a noise rule drops rows whose message contains "defender" or "prefetch", and a persistence mechanism writes into a prefetch-adjacent path.
- **Root cause & impact:** the row that proves persistence is deleted by a rule written to reduce volume, and the reduction is invisible because it was never counted.
- **Verification & fix:** exempt registry and service-related sources from suppression, and report per-rule drop counts so an over-broad rule is visible immediately.

## Case 3: An import that silently lost fields

- **Surface & Preconditions:** a post-processor emits only `datetime`, `message`, and a custom `host` column.
- **Root cause & impact:** Timesketch requires `timestamp_desc`, so the import fails or is mapped by hand with a default value — after which every event claims the same timestamp type and the timeline is misleading.
- **Verification & fix:** validate the three mandatory columns before emitting; carry `timestamp_desc` through the reduction.

## Case 4: New Plaso, empty post-processor

- **Surface & Preconditions:** a reducer keys on `computer_name` and `body`.
- **Root cause & impact:** Plaso 20260720 renamed them to `hostname` and `message_body`, so those fields resolve to nothing and the host and message columns are blank across the whole report.
- **Verification & fix:** resolve either name at load time and record which schema was detected.
