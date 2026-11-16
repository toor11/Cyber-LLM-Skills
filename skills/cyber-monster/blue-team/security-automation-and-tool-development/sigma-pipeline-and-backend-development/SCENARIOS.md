# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sigma-pipeline-and-backend-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative pipeline failures, each with the artifact that proves the diagnosis.

## Case 1: Double-mapped process command line

- **Surface & Preconditions:** Elasticsearch backend already applies its own ECS Windows pipeline; the team adds a custom `FieldMappingTransformation` for the same fields.
- **Root cause & impact:** `CommandLine` becomes `process.command_line`, then the mapping runs again on the already-renamed key, producing `process.process.command_line`. Every process-creation rule compiles cleanly and matches nothing.
- **Verification & fix:** print the compiled query and inspect the field path; remove the redundant `ProcessingItem` or select the backend's built-in pipeline only. See [`QUERIES.md`](QUERIES.md) for the golden-file gate that would have caught it.

## Case 2: Correlation rule silently dropped from the build

- **Surface & Preconditions:** a `correlation:` document references a base rule by `name`, and the loader is called without `collect_errors=True`.
- **Root cause & impact:** the unresolved reference raises during parse; with error collection off the exception surfaces as a generic traceback for the directory, so one broken correlation hides the whole rule file.
- **Verification & fix:** `SigmaCollection.load_ruleset([...], collect_errors=True)` and iterate `collection.errors`, mapping each message back to its source path.

## Case 3: Rule passes lint, never fires

- **Surface & Preconditions:** `sigma check` is green, the compiled SPL looks correct, and the alert never triggers.
- **Root cause & impact:** the logsource category (`process_creation`) is not collected on the host fleet, or the field is a `text`-analyzed field where the query assumes a keyword.
- **Verification & fix:** confirm sensor logsource coverage first (see [`detection-coverage-and-mitre-gap-analyzer-scripting`](../detection-coverage-and-mitre-gap-analyzer-scripting/SKILL.md)), then confirm the field mapping in [`ocsf-and-ecs-log-normalizer-development`](../ocsf-and-ecs-log-normalizer-development/SKILL.md).

## Case 4: Backend upgrade changes every golden file

- **Surface & Preconditions:** a routine `pip install --upgrade pysigma-backend-splunk` lands in the CI image.
- **Root cause & impact:** backend releases legitimately change emitted query text, so a golden-file diff appears across dozens of rules at once and looks like detection drift.
- **Verification & fix:** pin backend and pySigma versions in the pipeline lockfile; update goldens in a dedicated commit that bumps only the compiler.
