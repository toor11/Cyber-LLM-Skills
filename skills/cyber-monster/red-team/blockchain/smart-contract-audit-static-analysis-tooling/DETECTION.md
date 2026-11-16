# Detection Signals and Blue-Team Handoff

> Sub-skill: [`smart-contract-audit-static-analysis-tooling`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- CI pipelines running `slither` with no failing threshold, indicating analysis that nobody reads.
- Analysis runs against an unpinned compiler, producing results that cannot be reproduced.
- Detector output committed to a repository containing internal paths and contract names.
- Slither runs against dependencies, inflating reports with upstream findings.
- A drop to zero findings after a configuration change, which usually means the run stopped covering the target.
- Analyser installations from unofficial sources on a build agent.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md) | Query authoring, triage, and hardening |
