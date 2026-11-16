---
name: geolocation-and-imagery-verification-osint
description: "Performs passive visual geolocation and media verification: EXIF/XMP metadata inspection, sun-angle/shadow chronolocation (`SunCalc`), OpenStreetMap Overpass turbo feature queries, utility/road-sign regional markers, and reverse-image frame verification. Use for imagery geolocation or media authenticity tasks."
family: osint-and-red-operations
tier: core
triggers: ["geolocation osint", "chronolocation", "overpass turbo", "suncalc", "image verification osint"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Geolocation and Imagery Verification OSINT - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Establishing where an image or video was captured by combining shadow geometry, visible landmarks, map data, and metadata where it survives. The method is convergent: each technique independently narrows the location, and a conclusion requires agreement between at least two that do not share a failure mode.

- **Shadows give time, then place.** Sun position constrains the capture time from the shadow azimuth, and the elevation constrains latitude, which narrows candidate locations before any landmark work.
- **Metadata is corroboration, not proof.** EXIF is trivially editable and stripped by most platforms; treat it as one signal among several.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the image shows a clear shadow **THEN** derive azimuth and elevation first, because they eliminate most of the globe before landmark matching starts.
2. **IF** EXIF survives **THEN** record it with the retrieval path, and verify the claimed coordinates against a visible feature before trusting them.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the original file, at least one geometric constraint (shadow or skyline), and a map source with imagery — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Sun-position calculation for the capture date, Overpass or map data for feature queries, and a provenance record for every artefact used
- **First Check:** `exiftool -a -G1 -s image.jpg`

1. Confirm the target surface: obtain the original file where possible, record its hash, and note whether metadata survived the platform.
2. Choose the branch: shadow analysis when the sun is visible, landmark matching when a distinctive structure is present, and horizon or terrain matching when neither is available.
3. Define the differential: for each candidate location, compute the shadow azimuth expected at the claimed time and compare with the observed azimuth; the differential is the angular difference, and only a location within a few degrees survives.
4. Name the stop condition: two independent techniques agreeing within their stated tolerance, or an explicit statement that the location is unresolved.
5. Prove it: the report shows the shadow measurement, the sun-position calculation, the map comparison, and the metadata (if any) with its provenance.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Shadow azimuth and elevation from a known object` | Constrains capture time and latitude independently of any map. |
| `Overpass query for a named feature` | Confirms that a structure visible in the image exists at a candidate coordinate. |
| `EXIF timestamp and GPS with retrieval path` | Corroboration that must be checked against a visible feature, never used alone. |
| `Skyline or terrain profile match` | Narrows location when no distinctive structure exists, using horizon shape as the signal. |

## Worked Contrast

**Location Asserted From a Single Landmark:**

```text
Image shows a distinctive tower.
Search for the tower, find a match, state the location.
# BUG: no shadow check, no capture-time check, no verification that the tower's surroundings match
```

**Convergent Location With Stated Tolerances:**

```text
Shadow: azimuth 118 degrees, elevation 41 degrees (measured from a known-height object at 15:40 local).
Sun position for that date and time gives latitude 51.4N +/- 0.7 and confirms the azimuth within 2 degrees.
Map: the tower silhouette in the image matches the candidate building's outline on satellite imagery at 51.40N 0.12W.
Metadata: EXIF stripped; platform confirms the upload date, which matches the sun-position date.
Conclusion: location resolved to the candidate block; latitude corroborated by two independent methods.
```

**Why this matters:** A landmark match alone routinely finds similar-looking structures in other cities, and without a time constraint the sun position cannot be used. Deriving the shadow geometry first and requiring the map match to fit inside the resulting latitude band means the conclusion rests on two techniques with different failure modes, and the stated tolerance shows how strong it is.

## When It Is NOT This Issue

- **Landmark that exists in several cities.** Chain stores and repeated architecture produce false matches; require a surrounding-feature match.
- **EXIF coordinates without a visible feature.** Metadata can be edited or inherited from another capture; check against the image content.
- **Unknown capture date making sun position unusable.** Without a date, azimuth gives a time-latitude trade-off rather than a location.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `geolocation-and-imagery-verification-osint` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `geolocation-and-imagery-verification-osint` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: geolocation-and-imagery-verification-osint
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `geolocation-and-imagery-verification-osint` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 28 |
| Distinct dataset sources | 2 |
| Top sources | osint-tool-database (16), osint-ctf-corpus-fr (12) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
