# Detection Signals and Blue-Team Handoff

> Sub-skill: [`android-app-security-static-analysis`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Build audit: an obfuscation or shrinking step disabled in a release variant, detectable from the build file.
- Repository event: a `mapping.txt` published to a public location, which undoes obfuscation.
- Distribution signal: a repackaged APK whose signing certificate differs from the published one.
- Static-rule alert: a string resource matching a credential pattern added in a commit.
- Dependency audit: a new library contributing an exported component, visible in the merged manifest diff.
- Native artefact signal: a new `.so` in a release with exported symbols not present in the previous version.
- Store listing: a version published with `debuggable` set, which the store may reject and which a build check should catch.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
