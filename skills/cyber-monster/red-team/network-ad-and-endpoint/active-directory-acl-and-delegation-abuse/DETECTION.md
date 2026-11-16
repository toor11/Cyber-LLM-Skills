# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-acl-and-delegation-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 5136 for a modified `nTSecurityDescriptor` with the new SDDL in `Attribute Value`, the audit record of any ACL change.
- Windows Security 4662 with `Access Mask 0x100` (`Control Access Right`) or `WriteDACL`, indicating a permission change attempt.
- Windows Security 4670 for a permission change on an object, which records the previous and new security descriptor.
- Windows Security 4728 or 4732 for group membership changes that create new reachability immediately after an ACL change.
- Directory diagnostic 1644 for the LDAP query shape used by ACL collectors, especially `nTSecurityDescriptor` reads at scale.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
