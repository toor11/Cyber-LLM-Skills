# Detection Signals and Blue-Team Handoff

> Sub-skill: [`android-app-security-storage-and-network`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Manifest or config audit: a release build shipping `cleartextTrafficPermitted="true"`, caught by a build check.
- Log audit: a release build emitting a log line containing a token pattern, caught by a static rule at PR time.
- Backup audit: an app with `allowBackup="true"` and no `backup_rules.xml` excluding credential files.
- Device management event: an app data extraction or `adb backup` against a managed device.
- Network telemetry: an HTTP (not HTTPS) request from the app, visible at the egress proxy.
- Certificate telemetry: a TLS connection to the app's domain presenting a certificate that does not chain to a public root.
- Keystore audit: a key created with `setUserAuthenticationRequired(false)` on a device that supports hardware-backed keys.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
