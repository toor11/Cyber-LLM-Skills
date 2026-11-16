# Detection Signals and Blue-Team Handoff

> Sub-skill: [`android-app-security-component-and-deeplink`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Device telemetry: a deep link arriving from a browser or a messaging app rather than from the expected referrer, which is the impersonation signal.
- App log: the handler rejecting a URI, which is the validation control firing.
- Play Integrity verdict: a failing verdict correlated with deep-link invocations, which indicates a repackaged client.
- Manifest diff: a release that drops `autoVerify` from a host filter, which unclaims the host silently.
- Build audit: a dependency contributing a host filter to the merged manifest.
- Device event: `am start` with `-d` against the package from an unexpected UID, visible in a managed-device audit.
- WebView audit: a `loadUrl` call whose argument traces to an intent extra, flagged by a static rule.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
