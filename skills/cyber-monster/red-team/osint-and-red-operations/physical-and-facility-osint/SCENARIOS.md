# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`physical-and-facility-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Single-Tenant Assumption

- **Surface & Preconditions:** A site is described as solely occupied by the target based on the company's website.
- **Root Cause & Impact:** The register lists two additional entities at the same address, one of them active.
- **Verification & Fix:** Query the address, list all occupants with their status, and revise the description to multi-occupancy.

## Case 2: Imagery Predates a Change of Use

- **Surface & Preconditions:** A description of the site's layout is based on imagery that predates an approved change of use.
- **Root Cause & Impact:** The planning record shows a 2024 decision while the imagery is from 2022.
- **Verification & Fix:** Record both dates, describe the layout as of the imagery date, and note the approved change as a separate observation.
