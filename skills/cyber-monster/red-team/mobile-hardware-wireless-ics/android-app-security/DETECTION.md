# Detection Signals and Blue-Team Handoff

> Sub-skill: [`android-app-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Mobile threat defence event: a sideloaded app invoking an exported component of a managed app.
- Play Console or internal telemetry: an `ActivityNotFoundException` or `SecurityException` spike, which indicates probing.
- Log field: `Permission Denial` naming a component, which is the platform refusing an invocation and therefore the control working.
- Build audit: a release variant with `android:debuggable` true or `allowBackup` true, caught at build time.
- Manifest diff: a new `android:exported="true"` in a dependency's merged manifest, which is the supply-chain version of the same finding.
- Device event: `adb backup` or `run-as` against the app's data directory on a managed device.
- App-integrity signal: Play Integrity verdict failing while an exported component is invoked, which pairs the two signals.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
