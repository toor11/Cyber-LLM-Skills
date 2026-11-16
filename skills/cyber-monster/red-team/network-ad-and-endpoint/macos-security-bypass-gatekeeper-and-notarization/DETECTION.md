# Detection Signals and Blue-Team Handoff

> Sub-skill: [`macos-security-bypass-gatekeeper-and-notarization`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Unified log `com.apple.syspolicy.exec` entries showing `Skipping XProtect scan` for a notarized app on macOS 26.
- `spctl` rejection events in the unified log, with the bundle path and the reason.
- Removal or rewriting of `com.apple.quarantine`, visible to file integrity monitoring on the Downloads path.
- Notarization revocation checks: a bundle whose ticket fails to validate at launch, logged by `securityd`.
- MDM compliance report for Gatekeeper and notarization policy drift across the fleet.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
