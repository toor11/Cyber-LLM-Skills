---
name: browser-and-application-forensics
description: "Analyses browser and application artefacts: history, downloads, cache, extensions, saved credentials and web app storage. Use when user activity through a browser is relevant."
family: digital-forensics
tier: core
triggers: ["browser forensics", "chrome history forensics", "browser artifacts"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# Browser and Application Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Chromium-family browsers keep per-profile state in SQLite databases under a `User Data` tree: `History` holds `urls`, `visits` and `downloads`; `Web Data` holds autofill and, on some builds, tokens; `Login Data` holds credential rows; `Cookies` holds the cookie jar. Each is written in WAL mode, so the `-wal` and `-shm` sidecars beside the database are part of the same evidence and frequently contain the most recent visits — opening only the base file silently drops the current session. Timestamps in the History and Cookies databases are WebKit time: microseconds since 1601-01-01 UTC, converted with `visit_time/1000000 - 11644473600` for Unix seconds; `downloads.start_time` and `end_time` use the same epoch, while the `last_access_time` on some tables and the file's own NTFS times use different bases entirely. Firefox uses Unix microseconds in `places.sqlite` (`moz_historyvisits.visit_date`) and stores timestamps in `moz_annos` with yet another unit, so a query ported between browsers without changing the epoch produces dates centuries off. The databases record what the rendering engine committed — a visit row exists after a navigation entry was created, not when a byte left the network — so they prove interaction with a URL, and prove nothing about what was served, whether a download completed, or which human was at the keyboard. Deletion is soft: the row's bytes remain in freelist pages and freeblocks until reused, so "cleared history" often means "moved to unallocated space", not "destroyed".

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the browser is Chromium-family **THEN** read the WebKit epoch (microseconds from 1601) for `visits`, `downloads` and cookies; **IF** the browser is Firefox or Safari **THEN** switch epochs before comparing — Firefox `places.sqlite` uses Unix microseconds and Safari `History.db` uses Mac absolute time (seconds from 2001-01-01), so a mixed timeline built without conversion will place the same event in different centuries.
2. **IF** the profile may have been in use at acquisition **THEN** copy the database together with its `-wal` and `-shm` before opening it, and open the copy with `file:...?immutable=1`; **IF** the profile was collected after a clean browser shutdown **THEN** the WAL is normally gone and the base file is authoritative — record which case you have, because it changes whether recent visits are recoverable at all.
3. **IF** the artifact location is unclear **THEN** branch on OS: Chromium on Windows lives under `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>`, on macOS under `~/Library/Application Support/Google/Chrome/<Profile>`, on Linux under `~/.config/google-chrome/<Profile>`; Firefox equivalents are `%APPDATA%\Mozilla\Firefox\Profiles\<p>\places.sqlite`, `~/Library/Application Support/Firefox/Profiles/<p>/places.sqlite` and `~/.mozilla/firefox/<p>/places.sqlite`.
4. **IF** the question is what the user did **THEN** join `visits` to `urls` on `visits.url = urls.id` and read `transition` rather than counting `urls.visit_count`, because `visit_count` is a lifetime counter with no time dimension and cannot be placed on a timeline.
5. **IF** the question is whether a file was fetched **THEN** read `downloads` and treat `state` (0 in progress, 1 complete, 2 cancelled, 3 interrupted) and `danger_type` as the finding; a `state=2` row proves the user attempted the download, not that bytes reached disk.
6. **IF** the browser profile has been cleared **THEN** pivot to `-wal` frames, freelist recovery and the OS-level corroboration (USN journal for the History file, prefetch for the browser binary) before concluding the history is gone.
7. **IF** telemetry source covering `History DB` / `downloads` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the visit/download queries themselves | [`QUERIES.md`](QUERIES.md) | Epoch-correct SQL, one class per artifact |
| Need flags for headless parsing at scale | [`TOOLS.md`](TOOLS.md) | Hindsight, sqlite3, TSK, Plaso |
| Profile cleared, or history suspiciously short | [`QUERIES.md`](QUERIES.md) (recovery class) | WAL and freelist recovery instead of live-table reads |
| Need to know which "no results" means | [`SCENARIOS.md`](SCENARIOS.md) | Cases where an empty profile was the correct answer |
| Containment and handoff after a browser-borne intrusion | [`PLAYBOOK.md`](PLAYBOOK.md) | Preservation order and profile scope |
| Scripted extraction pipeline | [`sqlite-wal-and-browser-artifact-scripting`](../../security-automation-and-tool-development/sqlite-wal-and-browser-artifact-scripting/SKILL.md) | Script ownership of WAL handling stays there |
| Need the filesystem context for the profile directory | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | USN and MFT evidence around profile writes |
| Need download destination analysis | [`file-carving-and-recovery`](../file-carving-and-recovery/SKILL.md) | Deleted download targets |

## Procedure

1. **Confirm the evidence source and its integrity.** Record the SHA-256 of every file you copy, and record whether the profile was acquired live or after shutdown. Open with `immutable=1` so SQLite does not create a `-journal` or checkpoint the WAL into the base file — the single most common way an analyst destroys the newest visits before reading them.
2. **Choose the branch by browser family and OS.** The branch fixes the epoch, the schema and the path. Write the branch into the output: "Chromium, Windows, `Default` profile, WAL present" is a defensible statement; "browser history" is not.
3. **Establish a baseline-versus-probe differential.** Baseline is the profile's own earlier period, or a peer profile on the same build with the same extensions. Probe is the incident window. A URL that appears once is not a finding; a navigation pattern that appears only in the probe window, or an extension installed in the probe window that changed the search provider, is.
4. **Name the stop condition.** Declare `Inconclusive` when the WAL was checkpointed and deleted before acquisition, when the database fails `PRAGMA integrity_check` and only fragments survive, when the profile is a synced copy that mirrors another device's activity, or when the only remaining evidence is carved rows without rowid or table attribution. Do not describe carved fragments as a record of activity.
5. **State what counts as proof.** Proof is two independent artifacts naming the same URL or file inside one stated tolerance: a `visits` row plus the `downloads` row for that host inside the same minute; or a visit plus a filesystem record of the browser writing its cache at that time. A single database row proves the browser recorded it, nothing more.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `visits.visit_time` joined to `urls.url` with `transition` unset to typed | Chromium History SQLite (`visits`, `urls`) | A navigation was committed at that WebKit timestamp; `typed_count` distinguishes deliberate entry from a followed link |
| `downloads` row with `state=1`, `danger_type>0` and a `target_path` under a temp directory | Chromium History SQLite (`downloads`) | A completed download the browser itself flagged; the path proves where the browser wrote, not where the file ended up |
| `-wal` frames holding visit rows absent from the base file | SQLite WAL (`History-wal`) | Activity after the last checkpoint; the newest evidence on a live-acquired profile |
| Cookie row with a creation time after the profile's last legitimate change | Chromium `Cookies` SQLite | A session was established with that host at that time on that OS profile |
| Extension row in `Preferences` JSON with an install time and a broad host permission | Chromium profile `Preferences` / `Secure Preferences` | An extension with that permission set was present from that time; the JSON is authoritative, not the `Extensions` directory listing |
| Autofill or saved-login entry referencing a domain never visited in `urls` | Chromium `Web Data` / `Login Data` | A credential or form value for that origin existed in the profile, which no navigation can explain on its own |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# Copies only the database, opens it in place, and lists the raw table.
sqlite3 "C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\History" \
  "select url, visit_count from urls order by visit_count desc;"
# No epoch conversion, so no timeline. Opens the live profile so SQLite
# checkpoints the WAL and deletes it: the newest visits are gone before reading.
```

**High-Signal Grounded Artifact:**

```sql
-- Read-only open of a copied profile with both sidecars present.
-- WebKit epoch: microseconds since 1601-01-01 UTC.
ATTACH DATABASE 'file:C:\cases\01\History?immutable=1' AS h;
SELECT datetime(v.visit_time/1000000 - 11644473600, 'unixepoch') AS utc,
       u.url, v.transition, v.visit_duration, u.typed_count, v.from_visit
FROM h.visits v JOIN h.urls u ON u.id = v.url
WHERE v.visit_time/1000000 - 11644473600 BETWEEN 1767225600 AND 1767312000
ORDER BY v.visit_time;
```

**Why this matters:** the strong form opens a copy with the sidecars in place and converts the epoch in the query, so the result is a placeable timeline instead of a lifetime counter — and it cannot checkpoint away the WAL it is trying to read.

## When It Is NOT This Issue

- **Profile sync from another device:** a signed-in Chromium or Firefox profile receives visits, bookmarks and open tabs from other machines, so activity appears on a host where nobody typed it. Compare `visits.originator_cache_guid` and the account's sync state before attributing the row to this endpoint.
- **Preloaded and background navigations:** session restore, prerendering, captive-portal probes and extension background pages create visit rows with no human present. `transition` core types (`auto_subframe`, `reload`) separate these from `typed` and `link` navigations.
- **Clock and epoch mistakes:** a whole-decade or three-century offset is the classic wrong-epoch render (1601 versus 1970 versus 2001); a uniform one-to-three hour offset is a timezone render. Neither is a finding about the user, both are findings about the report.
- **Antivirus or EDR rewriting profile files:** endpoint scanning can quarantine and restore `History` or `Cookies`, producing fresh file times and an interrupted WAL. Check the endpoint product's own log for the path.
- **Extension updates and policy-deployed extensions:** managed browsers install and update extensions on schedule, and enterprise policy can set the search provider and homepage. Read `Preferences` and the OS policy keys before treating a changed default search as user action.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `History DB` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** every profile file used carries a recorded SHA-256, was copied before opening, and was opened with `immutable=1` or an equivalent read-only path.
- [ ] **Sidecars accounted for:** the presence or absence of `-wal`, `-shm` and `-journal` is stated, and the output says whether recent activity was recoverable from them.
- [ ] **Epoch and branch stated:** the browser family, OS and timestamp epoch used are named, and at least one converted timestamp was sanity-checked against a known event.
- [ ] **Stop condition cleared or declared:** checkpoint loss, integrity failure, sync origin and carved-only evidence were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: browser-and-application-forensics
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `browser-and-application-forensics` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 19 |
| Distinct dataset sources | 9 |
| Top sources | CYBER_CPT/ctf_search (6), Forensic_Toolkit_Dataset (5), CYBER_CPT/github_security_md (2), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 7 det / 5 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
