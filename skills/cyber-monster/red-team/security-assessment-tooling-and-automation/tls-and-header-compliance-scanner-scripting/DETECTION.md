# Detection Signals and Blue-Team Handoff

> Sub-skill: [`tls-and-header-compliance-scanner-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- TLS client hellos from one address cycling through protocol versions in sequence, the signature of version enumeration.
- Handshakes that abort immediately after the server hello, characteristic of a cipher probe.
- Repeated CONNECT or GET requests to the same URL within seconds with no session reuse.
- Scanner user-agents or `sslyze` default fingerprints in web logs.
- Egress to a certificate transparency or revocation endpoint from an assessment host in bulk.
- Multiple handshakes to the same host with different SNI values from one client.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
