---
name: forensic-imaging-and-tooling
description: "Performs defensible acquisition: write blocking, imaging formats, verification hashing and tool validation. Use when acquiring evidence that may be challenged."
family: digital-forensics
tier: leaf
triggers: ["forensic imaging", "write blocker", "acquisition tooling", "image verification"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# Forensic Imaging and Tooling - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Defensible acquisition rests on one principle — minimize change to the source — and on a chain of records that lets a stranger reproduce your result. Write blocking is the mechanism: a hardware blocker refuses write commands regardless of what the attached workstation attempts, while a software or OS-level read-only configuration depends on correct driver behaviour and on the operator not mounting read-write by accident. A hardware blocker must be validated on a scratch device before the day's first real acquisition, and the validation recorded, because a blocker that silently passes writes produces an image whose hash may still match while the source has already changed. Hashing is the second mechanism, and it has a subtlety: hashing the source before imaging is not always possible (failing media, no device-level hash support), and when it is not, the image hash alone cannot establish that the image equals the source — it only establishes that the image has not changed since it was written. Container format determines what a reviewer can verify independently: EWF stores per-segment hashes and case metadata inside the file, raw images carry nothing and need a sidecar digest, and AFF4 layers verifiable storage with arbitrary metadata. None of them makes a bad acquisition good. Coverage is the third mechanism and the one most often overstated: damaged sectors, a Host Protected Area, a Device Configuration Overlay, or a vendor-reserved region can prevent a tool from reading areas it does not report as errors, so a "verified" acquisition may be a verified acquisition of the readable subset. The practical rule is that every acquisition report must state what was blocked, what was hashed when, which format was used, and which regions could not be read.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the source is a physical disk **THEN** use a hardware write blocker and validate it on a scratch device before the real acquisition; **IF** the source is an NVMe device, a soldered embedded part or a virtual disk with no compatible blocker **THEN** record the software read-only method you used, the test that validated it, and the fact that it is not a hardware block.
2. **IF** the tool can hash the source during acquisition **THEN** record both source and image hashes and compare them; **IF** it cannot **THEN** hash the image immediately after acquisition, store the digest with the image, and state in the report that source verification was not possible and why.
3. **IF** the evidence may be challenged **THEN** prefer a container with embedded metadata and per-segment hashes (EWF `E01`/`Ex01`, or AFF4) over raw; **IF** the request requires raw **THEN** keep a `.sha256` sidecar and a written acquisition log, because the file itself carries no self-check.
4. **IF** the media reports read errors **THEN** switch to an imaging tool that records an error map (`ddrescue` with a map file, or the acquisition tool's own log) and hash the image rather than claiming source verification; **IF** the media reads cleanly **THEN** a straight sequential acquisition is sufficient.
5. **IF** the acquisition is logical rather than physical **THEN** state that metadata, slack and unallocated space are outside the image, and collect timestamps and permissions separately — a logical copy that silently drops them changes what can be proven.
6. **IF** the format is EWF or AFF4 **THEN** verify with the container's own verifier (`ewfverify`, the AFF4 tool) before analysis, and record the verifier output; a container that opens is not a container that verified.
7. **IF** telemetry source covering `write blocker` / `E01` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need acquisition and verification commands | [`QUERIES.md`](QUERIES.md) | One class per acquisition mode |
| Need tool flags, container formats and verifiers | [`TOOLS.md`](TOOLS.md) | `dc3dd`, `ewfacquire`, `guymager`, AFF4 |
| Need to analyse the image afterwards | [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) | Parsing, offsets and timelines |
| Need cloud-native acquisition instead | [`cloud-forensics-and-acquisition`](../cloud-forensics-and-acquisition/SKILL.md) | Snapshots, log export and provider limits |
| Need chain-of-custody handling | [`evidence-handling-and-chain-of-custody`](../../incident-response/evidence-handling-and-chain-of-custody/SKILL.md) | Custody forms and transfer records |
| Need volatile data before disk acquisition | [`memory-forensics`](../memory-forensics/SKILL.md) | Memory-first ordering |
| Need case shapes for challenged acquisitions | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |
| Need to validate a tool's own behaviour | [`lab-and-tooling-setup`](../../../red-team/osint-and-red-operations/lab-and-tooling-setup/SKILL.md) | Test-bed construction |

## Procedure

1. **Confirm the evidence source and its integrity before writing a byte.** Record the device identity (make, model, serial, capacity, firmware if visible), the blocker's model and firmware, the workstation's state, the tool and version, the operator, and the UTC start and end time. This record is what makes the image defensible; the hash alone is not.
2. **Choose the branch from the media and the requirement.** Healthy physical disk with a compatible blocker goes to hardware-blocked physical imaging; failing media goes to an imaging tool with an error map; a virtual or embedded device without a compatible blocker goes to a documented software read-only method; a live system goes to memory first and a documented live-acquisition method for disk.
3. **Establish a baseline-versus-probe differential on the tooling itself.** Baseline is the tool's known-correct behaviour on a scratch device with a known hash; probe is the same tool on this acquisition. A tool that has never been validated on known content produces output you cannot defend, and validating each time costs minutes.
4. **Name the stop condition.** Declare the acquisition inadequate when the blocker validation failed, when the source changed during imaging in a way the error map does not explain, when the verifier disagrees with the acquisition hash, or when regions were unreadable and the report cannot say which. Re-acquire rather than reasoning around a failed verification.
5. **State what counts as proof.** Proof of a sound acquisition is three records agreeing: the acquisition log's source and image hashes, the container's own verification output, and a re-computed hash of the stored image at analysis time. Two of the three is a lead; one alone is an assumption.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Blocker validation log showing a write attempt refused on a scratch device | Write-blocker test record | The block was functioning at that time on that workstation; says nothing until the source was attached |
| `dc3dd` log containing `hash=sha256` output for input and output | Raw acquisition log | The source and the image produced the same digest during that run, for the sectors actually read |
| `ewfverify` result reporting all segments verified | EWF container internal hash chain | The container's stored hashes match its data; combined with the acquisition log, the image equals the source |
| `ddrescue` map file with a non-empty bad-sector region | Failing-media acquisition map | Which byte ranges were unreadable, so the report can state the acquisition's coverage boundary |
| Raw image with a `.sha256` sidecar created at acquisition | Raw container plus sidecar digest | The image has not changed since the digest was taken; a sidecar created later proves nothing about acquisition |
| Logical acquisition manifest listing files and their metadata | Logical acquisition record | Which files were captured and that timestamps were preserved; unallocated space and slack are outside it |
| Two images of the same quiescent device with identical hashes | Repeat acquisition record | Reproducibility of the acquisition method on that device; a difference on a live device is expected instead |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`write blocker`):**

```text
# Images through a bridge the operator believes is read-only, then hashes the output.
sudo dd if=/dev/sdb of=evidence.img bs=4M status=progress
sha256sum evidence.img | tee evidence.sha256
# No blocker validation, no source hash, no error log, and the digest was taken
# after the fact: it proves the file has not changed since, nothing more.
```

**High-Signal Grounded Artifact:**

```bash
set -euo pipefail
SRC=/dev/sdb; CASE=/cases/21; mkdir -p "$CASE"

# 1. Record the kernel's read-only view of the device and the device identity.
blockdev --getro "$SRC" | tee "$CASE/blocker-readonly-flag.txt"   # expect 1
lsblk -o NAME,SERIAL,MODEL,SIZE,RO "$SRC" | tee "$CASE/device-identity.txt"
# A hardware blocker is validated separately on a scratch device, out of band;
# record that test's result here before relying on it for this acquisition.
echo "blocker self-test (scratch device): <result, date, operator>" | tee -a "$CASE/blocker-selftest.txt"

# 2. Acquire with hashing, error logging and a split target.
dc3dd if="$SRC" of="$CASE/disk.img" hash=sha256 log="$CASE/dc3dd.log" \
      bufsz=1M retry=2

# 3. Record device identity and the run window beside the log.
blockdev --getsize64 "$SRC" | tee "$CASE/source-size.txt"
date -u +%FT%TZ | tee -a "$CASE/acquisition-window.txt"

# 4. Verify against the image, not against memory.
sha256sum "$CASE/disk.img" | tee "$CASE/disk.img.sha256"
grep -E 'input.*sha256|output.*sha256' "$CASE/dc3dd.log"
```

**Why this matters:** the strong form validates the control before relying on it, produces a hash pair during acquisition rather than after, and records device identity and the UTC window — the four things a reviewer needs in order to accept that the image equals the source.

## When It Is NOT This Issue

- **A matching hash with an unwritten acquisition record:** identical digests prove the file is internally consistent, not that the source was blocked. A hash mismatch is an integrity failure, but a hash match is not by itself proof of sound acquisition.
- **Virtual and cloud disks:** a hypervisor snapshot with memory is atomic and often better evidence than a live block copy, but it is not a bit-for-bit match to the guest's view of its disk. State which you have before comparing hashes.
- **Failing media and firmware-remapped sectors:** a drive that remaps a bad sector returns data from a spare area, so two acquisitions of the "same" device can differ while both are honest. The error map is the evidence, not a mismatch.
- **Host Protected Areas and overprovisioning:** the addressable capacity a tool reports may be smaller than the physical media, and hidden regions can hold data the acquisition never touched. Record the reported capacity and the tool's attempt to read beyond it.
- **Live acquisitions of an active system:** any hash mismatch between two passes is expected because the volume is being written. A live acquisition supports content questions, not reproducible-equality claims.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `write blocker` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** device identity, blocker model, tool and version, operator and the UTC acquisition window are all recorded.
- [ ] **Block method stated:** the output says whether a hardware blocker or a documented software read-only method was used, and whether it was validated before this acquisition.
- [ ] **Hash chain complete:** acquisition-time hash pair, container verification output and an analysis-time re-hash are each present or explicitly declared missing.
- [ ] **Coverage boundary declared:** any unreadable region, capacity limit or logical-only scope is stated, so the report does not imply coverage it does not have.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: forensic-imaging-and-tooling
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `forensic-imaging-and-tooling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — never write to a source device, never image onto the evidence volume, and never treat a software read-only mount as equivalent to a hardware block without recording that decision.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 3 |
| Top sources | Forensic_Toolkit_Dataset (16), ctf-solver-dataset (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 1 cases |
| Grounding | multi-dataset corpus-grounded |
