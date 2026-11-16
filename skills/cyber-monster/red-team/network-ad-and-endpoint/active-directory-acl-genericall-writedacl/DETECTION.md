# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-acl-genericall-writedacl`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4670 with `Object Type` and `Permissions` fields showing a DACL replacement on a privileged object.
- Windows Security 5136 for `nTSecurityDescriptor` changes, with the SDDL difference in `Attribute Value`.
- Windows Security 4662 for `WriteDacl` or `Control Access Right` by a trustee that does not normally modify ACLs.
- Directory diagnostic 1644 for DACL reads at high volume, the collection pattern that precedes ACL abuse.
- Windows Security 4728 immediately following an ACL change, the sequence that indicates a granted right was just exercised.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
