# Detection Signals and Blue-Team Handoff

> Sub-skill: [`burp-montoya-and-jython-extension-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- HTTP requests carrying Montoya-style extension headers or a `Burp` user-agent from a non-tester source address.
- A single client address issuing requests to many vhosts on one host header value, characteristic of Repeater-driven extension work.
- Scanner-generated request patterns: identical body with a single parameter mutated across a short window.
- Extension registration logged in Burp's own event log, correlated with the session start time.
- JVM processes with `-Djava.awt.headless=false` on a server, indicating a GUI proxy where none is expected.
- TLS client hello fingerprints matching Java's default cipher ordering from an unexpected host.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
