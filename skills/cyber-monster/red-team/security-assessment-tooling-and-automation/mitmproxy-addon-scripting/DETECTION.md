# Detection Signals and Blue-Team Handoff

> Sub-skill: [`mitmproxy-addon-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A client trusting an unexpected root CA, visible in certificate chain telemetry for outbound connections.
- CONNECT requests to many distinct hosts from one internal address within a short window.
- TLS client hellos with cipher ordering matching mitmproxy's Python TLS stack rather than the native client.
- Proxy authentication failures at a corporate egress proxy from a client that bypasses it.
- Certificate pinning failures reported by a mobile app whose traffic was previously accepted.
- `mitmdump` processes on a developer workstation with a `-p` port bound on all interfaces.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
