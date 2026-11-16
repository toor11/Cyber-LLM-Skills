# Artifacts and Queries

> Sub-skill: [`forensic-imaging-and-tooling`](SKILL.md) | Family: **Digital Forensics**

Acquisition and verification commands owned by `forensic-imaging-and-tooling`, grouped by acquisition mode. Each class states the expected hit and the false-positive note that must be cleared before the result is treated as a sound acquisition. Nothing here writes to a source device; the only writes are to the case output volume.

## Class 1 — Pre-acquisition gate

Expected hit: a device identity, a read-only state and a recorded blocker test before the first byte is read. An acquisition started without these produces an image whose provenance cannot be reconstructed afterwards.

```bash
SRC=/dev/sdb
lsblk -o NAME,SERIAL,MODEL,SIZE,RO,TRAN "$SRC" | tee device-identity.txt
blockdev --getro "$SRC"                    # expect 1 through a hardware blocker
hdparm -I "$SRC" 2>/dev/null | grep -E 'Model|Serial|Firmware' | tee -a device-identity.txt
date -u +%FT%TZ | tee acquisition-start.txt
```

False-positive note: `blockdev --getro` reports the kernel's view, which a software read-only mount also sets; it does not prove a hardware block. If the blocker is hardware, the validation was performed on a scratch device and must appear in the case notes separately.

## Class 2 — Raw acquisition with hashing and error logging

Expected hit: a hash pair (input and output) in the tool's own log, plus an error log that is empty on healthy media.

```bash
CASE=/cases/21
dc3dd if=/dev/sdb of="$CASE/disk.img" hash=sha256 log="$CASE/dc3dd.log" \
      bufsz=1M retry=2
sha256sum "$CASE/disk.img" | tee "$CASE/disk.img.sha256"
grep -Ei 'sha256|error|bad sector' "$CASE/dc3dd.log" | tail -20
```

False-positive note: `retry=2` makes the tool re-read a failing sector, which can produce a different result than a single pass on marginal media. Record the retry count, because it changes what "the source read" means.

## Class 3 — EWF container creation and verification

Expected hit: a segment set with case metadata, an acquisition hash, and a verifier run that reports every segment verified.

```bash
CASE=/cases/21
ewfacquire -u -t "$CASE/disk" -C 21 -D "Seizure 2026-11-14" -E 1 \
  -e "analyst" -f encase6 -c deflate:best -d sha256 \
  -l "$CASE/acquire.log" /dev/sdb
ewfverify -d sha256 -l "$CASE/verify.log" "$CASE/disk.E01"
tail -6 "$CASE/verify.log"
sha256sum "$CASE"/disk.E* | tee "$CASE/ewf-segments.sha256"
```

False-positive note: `ewfverify` validates the container against the hashes stored inside it. If the acquisition wrote the wrong bytes and hashed them consistently, verification passes; only the acquisition log's source hash makes the chain complete.

## Class 4 — Failing media with an error map

Expected hit: an image plus a map file naming unreadable ranges, so the report can state its coverage boundary instead of implying a complete read.

```bash
ddrescue -d -r3 /dev/sdb /cases/22/disk.img /cases/22/disk.map
ddrescuelog -t /cases/22/disk.map | tail -20
sha256sum /cases/22/disk.img | tee /cases/22/disk.img.sha256
```

False-positive note: a non-zero error count is a fact about the media, not about tampering, and a subsequent successful read of a previously failing sector is normal remapping. Never present an error map as evidence of deliberate destruction.

## Class 5 — AFF4 and other container formats

Expected hit: an AFF4 volume with an external container hash, recorded as the acquisition baseline because the container is the artifact.

```bash
aff4imager -i /dev/nvme0n1 -o /cases/23/nvme.aff4
sha256sum /cases/23/nvme.aff4 | tee /cases/23/nvme.aff4.sha256
```

False-positive note: an AFF4 container's internal streams are verifiable individually but the container file grows as it is written; take the external hash only after the imager exits cleanly, or the stored baseline describes a partial volume.

## Class 6 — Analysis-time re-verification

Expected hit: the stored image still matching the digest recorded at acquisition, checked before every analysis session.

```bash
cd /cases/21 && sha256sum -c disk.img.sha256 && sha256sum -c ewf-segments.sha256
findmnt -no OPTIONS /mnt/evidence          # confirm ro before any parser runs
```

False-positive note: `sha256sum -c` succeeding proves the copy you hold is the copy you hashed. It does not prove the acquisition was sound; that claim lives in the acquisition log and the blocker record.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, for every acquisition, the blocker method and its validation, the tool and version, the hash chain and the coverage boundary; an acquisition report missing any one of those is not defensible.
