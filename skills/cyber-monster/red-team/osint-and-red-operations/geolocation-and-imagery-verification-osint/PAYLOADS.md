# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`geolocation-and-imagery-verification-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `geolocation-and-imagery-verification-osint`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Shadow geometry baseline

Baseline: the measured azimuth from the image. Probe: the computed azimuth at the candidate location and time. Differential: an angular difference above the stated tolerance rejects the candidate.

```bash
exiftool -a -G1 -s image.jpg
python -c "from astral import LocationInfo; from astral.sun import elevation; print('compute sun position for candidate date/time')"
```

## Feature existence check

Baseline: the candidate coordinate. Probe: the map query for the visible feature. Differential: the feature must exist at the coordinate with matching orientation.

```bash
curl -sS -G 'https://overpass-api.de/api/interpreter' --data-urlencode 'data=[out:json];node(around:50,51.40,0.12)["name"~"Tower"];out;'
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
