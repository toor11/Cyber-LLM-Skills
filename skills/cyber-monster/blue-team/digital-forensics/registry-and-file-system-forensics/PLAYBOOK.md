# Operational Triage and Response Playbook

> Sub-skill: [`registry-and-file-system-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `registry-and-file-system-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `registry analysis`.
- Alert, hunt outlier, or review request matching `mft analysis`.
- Alert, hunt outlier, or review request matching `hive parsing`.
- Alert, hunt outlier, or review request matching `filesystem timeline`.
- An investigation requires a defensible statement about a file's or a configuration key's history.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Key `LastWrite` inside the window joined to a registry-write event naming the writing process | Confirmed Configuration Change | Preserve the replayed hive and the event; scope the same key across peer hosts |
| Journal `FileCreate` and `$MFT` creation time agreeing within a second for the same path | Confirmed File Lifecycle | Export the file and its `$MFT` record; the agreement rules out a copy with preserved times |
| Hive parsed without transaction logs and a value reported absent | Inconclusive (Stale Hive) | Re-collect with `.LOG1`/`.LOG2` and re-parse before reporting any absence |
| Journal USN range starting after the incident window | Inconclusive (Coverage Boundary) | Reconstruct from `$LogFile` if it reaches, otherwise state the gap explicitly |
| Non-NTFS volume with no journal branch available | Not Applicable | Record the filesystem and pivot to filesystem-specific artefacts rather than reporting a clean history |

## Containment and Recovery

1. **Preserve before mutating:** capture hives with their `.LOG1`/`.LOG2`, plus `$MFT`, `$J` and `$LogFile` from the same acquisition, and hash both originals and any replayed copies.
2. **Order the collection:** replay logs before parsing, print boundaries before interpreting, and tag provenance before joining; reversing that order produces a merged table with no auditable basis.
3. **Record the precondition:** the filesystem type and each hive's dirty state belong in the report, because a reviewer cannot recompute them from a derived CSV.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
