# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-protocol-grammar-fuzzer-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A single source address opening many short-lived TCP connections to one port with near-identical first payloads.
- Connections closed immediately after the server's first response, without the client reading a full payload.
- Daemon restart events correlated with inbound connection bursts, the signature of a crash-restart fuzz loop.
- Frames whose length field matches the payload exactly while the payload content varies, indicating a sizer-aware fuzzer.
- Repeated connections from loopback or a lab subnet to a production service port.
- Core dumps or service-manager restart counts increasing on a host during an unauthorised assessment window.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
