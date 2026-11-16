# Detection Signals and Blue-Team Handoff

> Sub-skill: [`access-control-and-initialization`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Calls to `initialize` on a deployed contract from an address other than the deployer.
- `RoleGranted` events for the default admin role granting it to a new address.
- Proxy admin slot changes followed by a logic upgrade in the same window.
- A privileged selector called by an address with no role, visible in a trace even when the call reverts.
- `OwnershipTransferred` to the zero address followed by a re-grant attempt.
- Multiple deployments of the same implementation with different initialisers within minutes.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
