# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-protocol-attacks-layer-two-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Cisco `%SPANTREE-2-ROOTGUARD_BLOCK` or `%SPANTREE-2-BLOCK_BPDUGUARD` syslog, the direct record of a BPDU arriving on a host port.
- `show mac address-table count` approaching the CAM limit, or `%MAC_MOVE` notifications for many MACs on one port.
- DTP frames arriving on an access port, visible in switch debugging or a SPAN capture.
- Topology change notifications in the STP log outside a change window.
- Native VLAN mismatch warnings, `%CDP-4-NATIVE_VLAN_MISMATCH`, which record the configuration that enables double tagging.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
