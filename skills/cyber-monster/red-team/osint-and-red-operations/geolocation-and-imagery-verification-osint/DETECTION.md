# Detection Signals and Blue-Team Handoff

> Sub-skill: [`geolocation-and-imagery-verification-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Overpass or map-tile queries in bulk from a single client, characteristic of location enumeration.
- Repeated downloads of the same image from different mirrors, indicating metadata comparison.
- EXIF tooling executed on a downloaded media set.
- Tile-server requests around a small bounding box at high zoom, the signature of a verification pass.
- Access to satellite imagery APIs above the free tier for one key.
- Sun-position or astronomy library imports in a process handling media files.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
