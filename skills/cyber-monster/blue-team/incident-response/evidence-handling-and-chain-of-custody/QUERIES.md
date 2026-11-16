# Evidence and Attestation Queries

> Sub-skill: [`evidence-handling-and-chain-of-custody`](SKILL.md) | Family: **Incident Response**

Queries owned by `evidence-handling-and-chain-of-custody`, grouped by the evidentiary question they answer. These are attestation queries over the case record itself: they show whether integrity was demonstrated, whether custody is continuous, and whether a hold actually suspended deletion. They read acquisition logs, hash manifests and custody records rather than endpoint telemetry.

## Class 1 — Integrity attestation at acquisition

Expected hit: a source digest and a copy digest recorded together with the tool and version, and equal. An acquisition record without a source digest cannot demonstrate integrity at all, only afterwards.

```text
integrity_attestation:
  item_id:            FS-01-system-volume
  source_sha256:      recorded from the read stream at acquisition time
  copy_sha256:        computed over the written image
  tool:               name and version, recorded
  write_blocker:      model and firmware, recorded
  read_errors:        count and offsets, or "none"
  expected:           source_sha256 == copy_sha256, errors enumerated
  invalidating:       copy verified only after analysis, or digest taken from
                      a filesystem copy rather than the stream
```

False-positive note: a mismatch caused by a known bad sector is documented evidence of media condition, not of tampering; without the read-error list the two are indistinguishable.

## Class 2 — Custody continuity

Expected hit: an unbroken sequence of transfers for each item, each with item id, from, to, and timestamp. An interval with no entry is the gap a challenger will name.

```sql
SELECT item_id, seq, transferred_utc, from_party, to_party, location, purpose
FROM custody_log
WHERE case_id = 'INC-2026-1114'
ORDER BY item_id, seq;
-- Gap check: consecutive entries whose intervals do not abut.
SELECT a.item_id, a.seq AS gap_after, a.transferred_utc AS held_from,
       b.transferred_utc AS held_to,
       b.transferred_utc::time - a.transferred_utc::time AS gap
FROM custody_log a
JOIN custody_log b
  ON a.item_id = b.item_id AND b.seq = a.seq + 1
WHERE b.transferred_utc::time - a.transferred_utc::time > interval '7 days';
```

False-positive note: long intervals between transfers are normal when evidence sits sealed in a store; the finding is a gap with no storage entry, not elapsed time alone.

## Class 3 — Re-verification across the retention period

Expected hit: a digest computed at acquisition and re-computed at each access, all matching. A single verification at acquisition proves the copy then, not the copy now.

```bash
# Re-verify a stored image against the manifest recorded at acquisition.
sha256sum -c "${CASE_DIR}/SHA256SUMS" \
  --ignore-missing 2>&1 | tee "${CASE_DIR}/reverify-$(date -u +%Y%m%dT%H%M%SZ).log"
```

False-positive note: re-verification of a mounted or partially restored image will fail because the restore wrote to it; verify the stored artefact, never the working copy.

## Class 4 — Legal hold effect

Expected hit: a hold record naming custodians, categories, date range and covered systems, plus evidence that deletion jobs were suspended for those categories. A hold that was issued but never applied to the retention engine is the common failure.

```kusto
let hold = LegalHoldRecords
  | where CaseId == "INC-2026-1114"
  | project Custodian, DataCategory, ScopeStart, ScopeEnd, AppliedAtUtc;
union
  (RetentionJobLog
   | where TimeGenerated > ago(30d)
   | where DataCategory in (hold.DataCategory)
   | summarize deletions = count() by DataCategory, bin(TimeGenerated, 1d)),
  (hold | extend DataCategory = DataCategory, deletions = 0)
| order by DataCategory, TimeGenerated asc
```

False-positive note: a retention job that ran but deleted zero objects is not a hold failure; compare the deletion count, not the job's presence in the log.

## Class 5 — Acquisition completeness and its limits

Expected hit: the tool's own log listing every region read and every region skipped. This class exists so that no later claim implies completeness the acquisition never had.

```text
integrity_attestation:
  tool_log_present:   yes/no
  regions_read:       enumerated (start LBA / offset, length)
  regions_skipped:    enumerated with cause (bad sector, HPA, DCO, timeout)
  encrypted_regions:  noted (BitLocker, LUKS, vendor encryption)
  expected:           every claim about the media scoped to regions_read only
  invalidating:       a conclusion drawn over a skipped region as if it were read
```

False-positive note: host-protected areas and device configuration overlays are commonly skipped by acquisition tools; their absence from the image is a documented limitation, not an omission by the examiner.

## Class 6 — Analysis-environment separation

Expected hit: a record showing the analysis host, its sanitisation state, and that the analysed artefact was the verified copy. Analysis on the original, or on a host carrying prior case data, undermines both integrity and confidentiality.

```text
integrity_attestation:
  analysis_host:        identifier and image version
  sanitised_before_use: yes/no, with method
  artefact_analysed:    copy digest (must match Class 1)
  writes_to_artefact:   none, or documented with the tool and purpose
  expected:             analysed digest equals acquisition digest
  invalidating:         analysis performed against the original, or on a host
                        where prior-case data remained resident
```

False-positive note: a read-only loop mount still updates access timestamps at the filesystem layer; document the mount options rather than claiming byte-identical access.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record beside each class which artefact it attests, so a case cannot present a complete-looking custody record that verifies nothing about the image itself.
