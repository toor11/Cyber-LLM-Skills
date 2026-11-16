# Operational Triage and Response Playbook

> Sub-skill: [`browser-and-application-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `browser-and-application-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

The scope is one question: what did this browser profile do, and what can the profile still prove. Browsers are the most volatile application on a workstation and the most frequently "cleaned" — by the user, by the browser's own privacy features, and by the adversary. Acquisition order therefore matters more here than in most artifact families: a browser left running while you image the disk checkpoints away the very WAL you need.

## Triggers

- Alert, hunt outlier, or review request matching `browser forensics`.
- Alert, hunt outlier, or review request matching `chrome history forensics`.
- Alert, hunt outlier, or review request matching `browser artifacts`.
- A download-policy or proxy alert names a workstation, and the question is whether the file was fetched and where it went.
- A credential-dumping or session-theft alert implicates a browser profile, and the question is which origins were authenticated from this host.
- A user reports "my search results changed" or "I did not install that", and the profile holds the answer.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `visits` row plus matching `downloads` row for the same host inside one minute, with `state=1` | Confirmed activity | Preserve the profile plus sidecars; pivot to the download destination path and the OS-level record of the browser writing it |
| `-wal` present and holding rows the base file lacks | Recent activity recovered | Copy base, `-wal` and `-shm` together before anything opens the profile; record the sidecar inventory in the report |
| `History` recovered rows only from freelist, no rowid, no visit table entry | Partial, not placeable | Report as recovered content, not as an event; corroborate with USN or cache artifact before asserting a time |
| Profile activity explained by `originator_cache_guid` from another device | Benign Baseline (sync) | Record the sync origin; exclude those rows from the on-host timeline |
| Extension present in `Preferences` but absent from disk, or the reverse | Control Gap | Preserve both states; treat the extension's permissions as the exposure to scope, not as proof of execution |
| Database fails `PRAGMA integrity_check` and only fragments survive | Inconclusive (Integrity Failure) | Stop querying, acquire a fresh copy from the image, and state that live-table reads are unavailable |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes. Browser memory holds decrypted cookies and session tokens that the on-disk database does not, so memory capture before profile capture is not optional.
2. **Capture the profile as a directory, not as a file.** The `History`, `History-wal` and `History-shm` trio plus `Preferences`, `Cookies`, `Login Data` and `Web Data` must be copied with base names intact and digested individually.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
4. **Invalidate what the profile proves:** a browser profile on a compromised host means every session cookie it held is suspect. Scope the identity provider's sign-in log to that profile's account and revoke sessions from the profile's own last-seen time, not from the alert time.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If a malicious extension was the vector, remove it by policy rather than by hand on one host, and record the policy so the next host is covered before the user logs in.
