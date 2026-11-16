---
name: disk-forensics-and-artifacts
description: "Collects and analyses disk evidence: imaging with verification, filesystem parsing, deleted file recovery and artefact interpretation. Use when acquiring or examining storage media."
family: digital-forensics
tier: core
triggers: ["disk forensics", "disk image analysis", "filesystem forensics", "deleted file recovery"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [windows-artifact-forensics, linux-forensics, macos-forensics, memory-forensics]
---

# Disk Forensics and Artifacts - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Disk work begins with a container and a filesystem, and both decide what questions are answerable later. The image container determines provenance: raw `dd` output is a bit copy with no internal metadata, while EWF (`E01`/`Ex01`) embeds case metadata, per-segment hashes and compression, and AFF4 layers verifiable storage and arbitrary metadata — but none of them repairs a source that was read through a write-enabled path. The filesystem determines what survives deletion. NTFS clears the in-use flag at offset `0x16` of the MFT record and frees the cluster bits in `$Bitmap`, while the record's `$STANDARD_INFORMATION`, `$FILE_NAME` and `$DATA` attributes normally remain intact until the record is reused, so a resident file is recoverable from the MFT record alone; non-resident data survives only until its clusters are reallocated, and the runlist plus `$Bitmap` are what tell you whether it still holds. FAT sets the first directory-entry byte to `0xE5` and zeroes the cluster chain, leaving the name, size and starting cluster, so recovery assumes contiguity and fails predictably on fragmentation. ext4 zeroes the extent entries in the deleted inode and sets the size to zero, which usually leaves carving as the only option even though the directory block may still carry the name. Two further distinctions matter throughout: a partition offset reported by `mmls` is in 512-byte sectors while `mount` wants bytes, and mixing them silently produces "no filesystem"; and an alternate data stream, a sparse region or a compressed attribute means the byte count in the directory entry is not the number of bytes you can read from a naive copy.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the media is still attached **THEN** acquire through a validated write blocker and hash the source before and the image after; **IF** the media is NVMe or embedded with no compatible blocker **THEN** record the software read-only configuration you used, the test you ran on a scratch device, and the fact that source hashing may not be possible — do not present a software block as equivalent without that record.
2. **IF** the container is EWF or AFF4 **THEN** expose it read-only (`ewfmount`, or the container's own reader) and treat the exposed node as the device; **IF** the container is raw **THEN** keep a `.sha256` sidecar and re-verify before every analysis session, because a raw file carries no self-check.
3. **IF** the partition layout is unknown **THEN** run `mmls` first and carry the start sector into every subsequent command as `-o <sector>`; `mount` needs `offset=<sector*512>` instead, and using one where the other belongs yields a mount that appears empty rather than an error.
4. **IF** acquisition mode is live **THEN** accept that the volume is changing while you copy and record the copy window; **IF** acquisition mode is a dead-box image **THEN** the volume is frozen and your timeline is internally consistent — say which case applies, because a live copy cannot support sub-second ordering claims.
5. **IF** the filesystem is NTFS **THEN** parse `$MFT` before anything else and use it as the spine for paths, sizes and timestamps; **IF** the filesystem is ext4 **THEN** parse inodes and the journal, and expect deleted-file recovery to require carving rather than metadata.
6. **IF** the only remaining evidence is unallocated space **THEN** report recovered fragments as content without paths or timestamps, and never as events.
7. **IF** telemetry source covering `dd image` / `E01` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need partition, inode and timeline commands | [`QUERIES.md`](QUERIES.md) | One class per filesystem layer |
| Need imaging flags and verification steps | [`TOOLS.md`](TOOLS.md) | `dc3dd`, `ewfacquire`, TSK, MFTECmd |
| Need Windows-specific artifact semantics | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | Registry, execution and event artifacts |
| Need to recover deleted files from unallocated space | [`file-carving-and-recovery`](../file-carving-and-recovery/SKILL.md) | Carving ownership and validation |
| Need the acquisition to withstand challenge | [`forensic-imaging-and-tooling`](../forensic-imaging-and-tooling/SKILL.md) | Chain of custody and tool validation |
| Need cross-source ordering | [`log-and-timeline-analysis`](../log-and-timeline-analysis/SKILL.md) | Super-timeline construction |
| Need the volume's cloud equivalent | [`cloud-forensics-and-acquisition`](../cloud-forensics-and-acquisition/SKILL.md) | Snapshot restoration and mounting |
| Need case shapes for tampered or wiped media | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |

## Procedure

1. **Confirm the evidence source and its integrity.** Record the make, model, serial and capacity of the source device, the write-blocking method, and the SHA-256 of the image with the tool version that produced it. Verify the image hash against the acquisition hash before the first analysis command; an unverified image makes every later conclusion provisional.
2. **Choose the branch by filesystem and question.** NTFS with a Windows question goes to `$MFT` plus `$J`; ext4 goes to inode and journal parsing plus auditd; APFS goes to the unified log and FSEvents; a deleted-file question goes to metadata recovery first and carving only when metadata is exhausted. Write the branch into the output.
3. **Establish a baseline-versus-probe differential.** Baseline is the volume's own earlier period or a peer build's artifact population — the normal set of files in `System32`, the normal number of prefetch entries, the normal directory depth. Probe is the incident window. A single unusual file is not a finding; a population that shifts is.
4. **Name the stop condition.** Declare `Inconclusive` when the image failed verification, when the partition table is damaged beyond recovery and the filesystem cannot be located, when the only evidence is unallocated clusters whose original owner cannot be determined, when heavy fragmentation makes a carved file a reconstruction rather than a recovery, or when the filesystem is encrypted and the key is not available.
5. **State what counts as proof.** Proof is two independent structures agreeing inside a stated tolerance: an MFT record plus the `$J` entry that created or renamed it; an inode plus the directory entry that named it; a carved file plus a reference hash match. A path from one structure and a timestamp from another, with nothing tying them together, is a lead — label it as one.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| MFT record with the in-use flag cleared and `$DATA` still resident | NTFS `$MFT` record | The file's content is recoverable from the record on NTFS without carving, because resident data lives inside the record |
| `$Bitmap` bits free for clusters a runlist still points to | NTFS `$Bitmap` plus `$MFT` runlist | The clusters were released and not yet reallocated; whether the content survives is a separate question answered by reading them |
| ext4 inode with zeroed extent entries and size 0, name still in the directory block | ext4 inode and directory block | The file was deleted on ext4 and its data location is lost, so metadata recovery will fail and carving is the remaining route |
| `mmls` start sector of 2048 for the first data partition | Partition table (MBR or GPT) | The filesystem begins 1,048,576 bytes into the image, which is the offset every later command must use |
| Directory entry with first byte `0xE5` and an intact name, size and start cluster | FAT directory entry | A FAT file was deleted with its chain zeroed; contiguous recovery is possible, fragmented recovery is not |
| Files under a directory whose `$SI` creation times cluster within one second while `$FN` times differ | NTFS `$MFT` attribute pair | A bulk write or extraction created the set at one moment; a single member with a divergent pair is the anomaly worth examining |
| Image sector readable in one acquisition and erroring in another | Acquisition error map / bad-sector log | The source has failing media; a difference between two images of the same device is hardware, not tampering |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# Mounts the image read-write and lists what the OS can see.
sudo mount -o loop,offset=2048 evidence.dd /mnt/evidence
ls -la /mnt/evidence/home/*/
# Sector offset used as a byte offset, no read-only flag, and the deleted-file
# question is never asked because the OS view cannot see deleted entries.
```

**High-Signal Grounded Artifact:**

```bash
set -euo pipefail
IMG="/cases/14/disk.dd"
mmls "$IMG"                                   # sectors, not bytes
START=$(mmls "$IMG" | awk '/NTFS|Linux/ {print $3; exit}')
echo "filesystem starts at sector $START"

fls -r -m / -o "$START" "$IMG" > body.txt      # read-only, includes deleted entries
istat -o "$START" "$IMG" 42 | head -20         # inode/MFT record for one candidate
icat  -o "$START" "$IMG" 42 > recovered.bin    # extract by inode, no mount at all
mactime -b body.txt -d -y "$(date -u -d "$START_D" +%Y-%m-%d)".."$(date -u -d "$END_D" +%Y-%m-%d)"
sha256sum recovered.bin | tee -a manifest.txt
```

**Why this matters:** the strong form derives the partition offset from the image rather than assuming it, never mounts the evidence, keeps deleted entries in scope by using `fls`, and produces an extracted file with its digest — so the result is reviewable and the source was never writable.

## When It Is NOT This Issue

- **Timezone rendering of filesystem times:** NTFS stores UTC FILETIME, FAT stores local time with no zone, and a tool that renders one as the other shifts whole directories by hours. A uniform offset across a directory is a report error, not tampering.
- **Installer and update bursts:** OS servicing writes thousands of files in a few minutes with clustered timestamps, and feature updates move files between directories. A burst that coincides with a build change is expected.
- **Backup, restore and archive extraction:** `$SI` times copied from a source, `$FN` times from the restore, and cluster allocation that does not match the file's apparent age are all normal after a restore. Ask whether the path was restored.
- **Antivirus and endpoint agents:** scanning can modify access times, quarantine can move and rewrite files, and the agent's own cache churns the MFT. Check the product's log for the path before treating the change as user or adversary action.
- **Sparse, compressed and deduplicated files:** the logical size, the allocated size and the readable byte count differ, and a naive copy of a sparse file produces zeros that look like deliberate wiping. Compare allocated size and runlist before concluding content was destroyed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `dd image` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** source device identity, write-blocking method, image format and SHA-256 are recorded, and the image hash was verified before analysis.
- [ ] **Filesystem and branch stated:** filesystem type, partition offset in sectors and the parsing branch are named, and the output says which structures were available.
- [ ] **Differential defined:** artifact populations were compared against the volume's earlier state or a peer build, and the finding is the shift rather than a single file.
- [ ] **Stop condition cleared or declared:** verification failure, damaged partition table, unallocated-only evidence, fragmentation and encryption were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: disk-forensics-and-artifacts
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)
- [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `disk-forensics-and-artifacts` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — never mount evidence read-write, never run a repair utility against an image, and never write carved output onto the evidence volume.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/ctf_search (4), CYBER_CPT/L5/ctf_search (2), Forensic_Toolkit_Dataset (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 1 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
