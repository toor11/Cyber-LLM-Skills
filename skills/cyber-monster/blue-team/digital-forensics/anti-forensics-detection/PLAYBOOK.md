# Operational Triage and Response Playbook

> Sub-skill: [`anti-forensics-detection`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `anti-forensics-detection`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

The question this runbook answers is narrow and should stay narrow: was evidence altered or destroyed, which of it, and can the hole be bounded in time. It does not try to explain the intrusion, and it must not start remediation before the volatile and journal evidence is captured, because every containment action overwrites exactly what the reconstruction depends on.

## Triggers

- Alert, hunt outlier, or review request matching `anti forensics`.
- Alert, hunt outlier, or review request matching `timestomping detection`.
- Alert, hunt outlier, or review request matching `log tampering detection`.
- A channel reports zero events for a window in which peer hosts of the same build, same site, same policy report thousands.
- The change journal is minutes old on a host with weeks of uptime, or its ID changes between two of your own acquisitions of the same volume.
- A responder finds an endpoint tool, EDR agent or backup client disabled and its own log truncated, without a corresponding change record.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `$SI`/`$FN` inversion for a scoped path, plus a `BasicInfoChange` USN record inside the same second | Confirmed tampering | Capture `$MFT`, `$J` and the file itself as images before any AV action; record the USN of the change |
| 1102 or 104 is the oldest surviving record in a channel, with an unexplained service stop nearby | Confirmed log clearing | Preserve the whole `winevt\Logs` tree plus `$LogFile`; pivot to SIEM/forwarder copies of the same window |
| Channel short but `MaximumSizeInBytes` full, retention mode set, and peer hosts look identical | Benign Baseline (rollover) | Record the configured size and the peer comparison; no further action on the channel |
| Journal ID recreated but a `fsutil usn createjournal` is visible in process or prefetch evidence | Confirmed tampering | Preserve the journal file and the parent process record; treat the missing window as unknowable rather than empty |
| Prefetch sparse while `EnablePrefetcher` is `0` in the SYSTEM hive | Configuration, not tampering | Record the setting and its owner; remove prefetch from the evidence basis for this host |
| Source has no recorded digest, or was mounted read-write before analysis | Inconclusive (Integrity Gap) | Stop analysis, re-acquire from the original media, and state the gap in the report |
| Required log channel disabled or rotated out | Inconclusive (Telemetry Gap) | Do NOT close as clean; open high-priority log-onboarding action |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot volatile memory, active tokens/sessions, and raw logs with SHA-256 hashes. On NTFS also capture `$MFT`, `$Extend\$UsnJrnl:$J` and `$LogFile` as raw file copies, because a live acquisition after containment has already advanced the journal past the incident.
2. **Order the acquisition by what disappears first:** memory and network state, then journal and event logs, then the volume. Never reimage or rebuild the host until the journal has been copied and its digest recorded — a rebuilt host destroys the only ordered record of what was removed.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval.
4. **Repair the telemetry, not just the host:** after preservation, restore channel size, audit policy and forwarder health, and record the before/after configuration so the next gap can be attributed. A rebuilt host that keeps the same undersized channels will lose the evidence of the next intrusion in exactly the same way.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If an adversary had the rights to clear logs or rewrite timestamps, treat all credentials used on that host as exposed.
