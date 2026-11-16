# Detection Signals and Blue-Team Handoff

> Sub-skill: [`security-arsenal-and-tool-index`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Concurrent execution of many scanning tools from one host, characteristic of index validation.
- Tool version checks followed immediately by scans, indicating a method being rehearsed.
- Installation of assessment tooling on a host outside the authorised toolkit image.
- Downloads of tool archives from unofficial mirrors, a supply-chain risk.
- Processes matching known tool names running from user-writable paths.
- Index files or tool manifests committed to a production repository.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
