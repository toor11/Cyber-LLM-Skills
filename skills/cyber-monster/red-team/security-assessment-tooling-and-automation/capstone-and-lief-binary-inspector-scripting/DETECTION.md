# Detection Signals and Blue-Team Handoff

> Sub-skill: [`capstone-and-lief-binary-inspector-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- File-read events on build artefacts from an analyst workstation, matching inspection of a binary that was not staged for review.
- Python processes importing lief or capstone on hosts without a build toolchain.
- Hash of a production binary appearing in an analyst's working directory per DLP file classification.
- Repeated opens of the same PE/ELF with no writes, characteristic of header-only inspection.
- Archive creation containing binaries and a report, indicating exfiltration of build artefacts.
- EDR module loads for capstone/lief shared libraries in a non-development process.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
