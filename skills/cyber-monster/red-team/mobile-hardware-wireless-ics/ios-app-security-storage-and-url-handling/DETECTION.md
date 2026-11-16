# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ios-app-security-storage-and-url-handling`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Container audit: a preferences plist containing a value matching a token pattern, from a managed-device inspection.
- Backup audit: an encrypted versus unencrypted backup containing the app's container, which the device policy decides.
- Keychain query audit: a `kSecAttrAccessibleAlways` in the source, flagged at review.
- App log: a WebView navigating to a host outside the allowlist, which the app can log itself.
- Device event: an app opening the scheme owned by a managed app with a parameter that names an external URL.
- Extension audit: a shared container read by an extension whose entitlements were not reviewed with the app's.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
