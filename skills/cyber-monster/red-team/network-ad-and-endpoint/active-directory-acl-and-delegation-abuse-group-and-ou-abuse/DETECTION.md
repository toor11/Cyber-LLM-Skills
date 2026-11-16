# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4728 and 4732 for a member added to a security or global group, with `Member Name` and `Subject User Name`.
- Windows Security 5136 for a modified `member` attribute on a group object, which records direct writes as well as cmdlet use.
- Windows Security 4662 for `WriteProperty` on the `member` attribute GUID by a trustee that does not normally manage groups.
- Directory diagnostic 1644 for high-volume recursive group expansion, the collection pattern behind membership-based path finding.
- Windows Security 4670 for a DACL change on a group object, which usually precedes a membership change in an abuse chain.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
