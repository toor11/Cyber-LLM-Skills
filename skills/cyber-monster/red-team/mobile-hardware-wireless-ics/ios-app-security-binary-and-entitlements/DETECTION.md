# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ios-app-security-binary-and-entitlements`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Signing pipeline event: a distribution build signed with development entitlements, caught by comparing the profile type to the entitlement set.
- Build audit: `get-task-allow` present in a release variant, detectable at signing time.
- Binary scan: `cryptid 0` in a store submission, which indicates an unencrypted payload.
- Profile expiry: an embedded profile whose `ExpirationDate` has passed, which is a distribution defect and often an outage.
- Entitlement drift: a new keychain group or application group added in a build, reviewed at release.
- Mobile threat defence: a debugger attached to the app on a managed device, which the get-task-allow entitlement permits.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
