# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`geolocation-and-imagery-verification-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Landmark Match in the Wrong City

- **Surface & Preconditions:** A distinctive building is matched to a candidate city and reported as the location.
- **Root Cause & Impact:** The same chain architecture exists in several cities, and the surrounding street layout was not compared.
- **Verification & Fix:** Add the surrounding feature comparison from map data, check the shadow azimuth, and reject the candidate when either disagrees.

## Case 2: Metadata Coordinates Contradict the Image

- **Surface & Preconditions:** EXIF gives coordinates that place the camera in a location where the visible sun position is impossible.
- **Root Cause & Impact:** The file inherited metadata from another capture or was edited.
- **Verification & Fix:** Reject the coordinates, derive the time from shadows, and record the metadata conflict as a finding about the artefact.
