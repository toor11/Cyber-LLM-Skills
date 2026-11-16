# Detection Signals and Blue-Team Handoff

> Sub-skill: [`idapython-automation-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- `idat` or `ida64` process starts with `-A -S` on a host that is not a reverse-engineering workstation.
- `.i64` or `.idb` database files created beside production binaries on shared storage.
- `IDAUSR` or plugin directory writes on a server, indicating a scripted install.
- Licence checkout events for IDA from an unexpected user or host.
- Python script files containing `idautils.XrefsTo` appearing in a repository unrelated to tooling.
- Large databases copied to removable media, which is a data-handling event rather than a technical one.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`static-pe-elf-apk-feature-extractor-scripting`](../../../blue-team/security-automation-and-tool-development/static-pe-elf-apk-feature-extractor-scripting/SKILL.md) | Query authoring, triage, and hardening |
