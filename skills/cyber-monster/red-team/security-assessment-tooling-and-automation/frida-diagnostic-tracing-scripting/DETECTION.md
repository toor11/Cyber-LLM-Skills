# Detection Signals and Blue-Team Handoff

> Sub-skill: [`frida-diagnostic-tracing-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Processes mapping `frida-agent` or `gum-js-loop` threads, visible in `/proc/<pid>/maps` or an EDR module inventory.
- A named pipe or abstract socket on port 27042 (the default frida-server port) on a managed device.
- `ptrace` attach events against a production app process from a non-debug build host.
- Unexpected `libgadget.so` in an application bundle, indicating a repackaged build with an embedded gadget.
- Thread creation immediately followed by a debugger attach on mobile platforms, characteristic of spawn-and-attach.
- App code paths taking measurably longer with a single function dominating the delta, matching a hooked hot path.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
