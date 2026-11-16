# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ios-app-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Device management event: an app opening a URL scheme owned by another managed app, which is the cross-app invocation signal.
- App log: a scheme handler rejecting a URL, which is the validation control firing.
- Entitlement diff: a distribution build carrying `get-task-allow`, caught at signing time.
- Container audit: a preferences plist containing a token-shaped value, detectable from a managed-device inspection.
- Attestation metric: App Attest assertions failing for a client that otherwise authenticates, which indicates a repackaged or scripted client.
- Keychain audit: an item with `kSecAttrAccessibleAlways` in a security review of the app's keychain queries.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
