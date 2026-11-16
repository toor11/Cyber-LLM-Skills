# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ghidra-headless-and-pcode-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- `analyzeHeadless` process start on a workstation that is not a reverse-engineering host.
- Ghidra project directories (`*.gpr`, `*.rep`) appearing on shared storage beside production binaries.
- JVM processes with `-Djava.awt.headless=true` and a Ghidra classpath on a server.
- Large temporary directories under the analysis host's temp path, matching decompiler caches.
- Script console logs naming production binary paths, from the Ghidra user settings directory.
- PyGhidra imports in Python processes on hosts with no analysis tooling installed.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
