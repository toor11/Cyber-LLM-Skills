# Operational Triage and Response Playbook

> Sub-skill: [`linux-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `linux-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Linux hosts vary more than any other family in what they record: a default cloud image with volatile journaling and no auditd has almost no historical record, while a hardened server with persistent journal, a full audit ruleset and remote syslog has more than you can read. The runbook's first job is therefore to establish which record exists, and only then to interpret it. The second job is to protect the weakest sources — utmp and shell history — from being treated as stronger than they are.

## Triggers

- Alert, hunt outlier, or review request matching `linux forensics`.
- Alert, hunt outlier, or review request matching `linux artifacts`.
- Alert, hunt outlier, or review request matching `bash history forensics`.
- Alert, hunt outlier, or review request matching `systemd forensics`.
- An unexpected unit, timer or cron entry appears on a server.
- A host reboots without a change ticket, and the question is what ran before and after.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Unit file with no owning package and an `ExecStart` outside system paths | Confirmed persistence | Preserve the unit, its timestamps and the target binary; scope the service account it runs as |
| auditd `EXECVE` and a journal entry agree on a binary execution inside one second | Confirmed execution | Preserve both sources with hashes; pivot to network and file evidence for the same window |
| Session present in `wtmp` but absent from auth log and audit | Anomalous record | Check whether utmp was rebuilt at boot; only then consider record removal |
| Journal exists only under `/run/log/journal` | Inconclusive (Volatile Journal) | Pivot to syslog, auditd and filesystem evidence; state the narrower record in the report |
| Shell history empty while audit and file times show commands ran | Expected (History Not Written) | Record the `history -c` or `SIGKILL` possibility; do not treat history as the command record |
| Syslog line without year or zone cannot be placed | Inconclusive (Timestamp Inference) | State the inferred year and zone, or leave the event out of the ordered timeline |
| Package verification reports a modified unit owned by a package | Benign Baseline (upgrade) | Confirm the package version change in the package log before any other explanation |

## Containment and Recovery

1. **Preserve before mutating:** capture the journal directory, `/var/log/audit`, utmp/btmp/wtmp, shell histories and the unit inventory before any restart. A `systemctl restart` rotates logs and rewrites utmp; there is no way to recover what it overwrote.
2. **Image or snapshot before remediation.** Rebuild-from-image is the right recovery for a compromised Linux host, but it destroys the evidence. Snapshot, verify, then rebuild.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and on Linux specifically, never restart `systemd-journald`, `auditd` or `rsyslog` on a suspect host before copying their files.
4. **Scope by credential and key:** an intruder with root can read every `authorized_keys`, every service token and every secret in the environment files. Enumerate them from the image, then rotate from a clean host — not from the suspect one.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the vector was an exposed service, close it and re-derive which other hosts expose the same service; if it was a weak credential, rotate the class, not the instance.
