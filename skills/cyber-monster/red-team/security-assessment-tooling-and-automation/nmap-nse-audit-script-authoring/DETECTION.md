# Detection Signals and Blue-Team Handoff

> Sub-skill: [`nmap-nse-audit-script-authoring`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Nmap service probes in firewall logs: SYN to a small port set with the characteristic NSE timing profile.
- `User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)` in web logs, which identifies NSE http requests directly.
- Requests for paths no browser requests (`/HNAP1/`, `/evox/about`), the signature of http-title and http-enum.
- Version-detection probes that open and immediately close a connection without sending a request.
- A single source address scanning a /24 with uniform inter-host delay.
- `--script` runs leaving `nmap-services` cache writes on the scanning host's filesystem.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
