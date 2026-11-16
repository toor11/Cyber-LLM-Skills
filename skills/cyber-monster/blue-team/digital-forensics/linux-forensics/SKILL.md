---
name: linux-forensics
description: "Analyses Linux hosts: log review, bash history, persistence locations, package and file integrity, and container-adjacent artefacts. Use when examining a Linux system."
family: digital-forensics
tier: core
triggers: ["linux forensics", "linux artifacts", "bash history forensics", "systemd forensics"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, macos-forensics, memory-forensics]
---

# Linux Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Linux keeps several independent records of the same activity, and they disagree in useful ways. The systemd journal is a binary, indexed store with microsecond UTC timestamps and trusted fields journald itself adds (`_PID`, `_UID`, `_COMM`, `_EXE`, `_SYSTEMD_UNIT`, `_BOOT_ID`); its persistence depends entirely on configuration — with `Storage=auto` it writes to `/var/log/journal` only if that directory exists, otherwise to the volatile `/run/log/journal` which disappears at shutdown. `wtmp`, `btmp` and `utmp` are plain arrays of fixed-size `struct utmp` records, appended by `login`, `sshd` and `systemd`, with a `USER_PROCESS` record at login and a `DEAD_PROCESS` record at logout; because they are just arrays, root can delete a record cleanly, and `utmpdump -r` can convert edited text back to binary. Traditional syslog lines (`Sep 20 03:14:07`) carry no year and no timezone, so they must be interpreted against the image's `/etc/localtime` and rotation order, while rsyslog on recent Debian and Ubuntu defaults to RFC 3339 with an explicit offset and RHEL sets the traditional template explicitly. auditd, when running, is the most detailed source — it can record logins, command execution and file access depending on the rules in `/etc/audit/rules.d/`, with epoch-second timestamps inside `msg=audit(...)` that carry no timezone ambiguity at all. Shell history is the weakest record: bash writes `~/.bash_history` at shell exit by default, without timestamps unless `HISTTIMEFORMAT` was set, so `history -c` followed by an exit leaves a file that never contained the session at all. Persistence lives in `/etc/systemd/system`, user units under `~/.config/systemd/user`, timers, `/etc/cron.*` and `/var/spool/cron`, plus `/etc/ld.so.preload`, PAM modules and `authorized_keys`; each is an ordinary file with a timestamp, which makes the filesystem timeline the frame that holds them together.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the acquisition is a disk image **THEN** mount it read-only (`-o ro,loop,offset=<bytes>`) or parse it with TSK, and read logs from the mount rather than from the running host; **IF** the host is live **THEN** capture `journalctl --list-boots`, `last -F -x`, the audit log and `/proc` state before any service restart, because a restart rotates the journal and rewrites utmp.
2. **IF** the journal is under `/run/log/journal` only **THEN** it will not survive a reboot: state that in the output and pivot to syslog, auditd and filesystem evidence; **IF** it is under `/var/log/journal` **THEN** copy the directory including the machine-ID subdirectory and read it with `journalctl --file=` or `--directory=`.
3. **IF** the question is who logged in **THEN** read `wtmp` with `last -F -i -x -f <copy>` and cross-check against `auth.log`/`secure` and the journal, because `wtmp` is trivially editable with root; **IF** the question is who authenticated and how **THEN** go to auditd (`USER_LOGIN`, `USER_AUTH`) or the distro's auth log, not to utmp.
4. **IF** shell history is the only command record **THEN** treat it as a hint and corroborate with auditd `EXECVE`, the journal, and file times in `/tmp` and `/dev/shm`; a `# ` prefixed epoch line only exists if `HISTTIMEFORMAT` was set, so its absence proves nothing about whether commands ran.
5. **IF** persistence is suspected **THEN** diff the unit and cron inventory against the package manager's knowledge (`rpm -V`, `dpkg -V`) and against a baseline; a unit file with no owning package is the finding, not a unit file with a recent mtime.
6. **IF** the timestamp format has no year or zone **THEN** derive the year from rotation order and file times and the zone from `/etc/localtime` before placing the line on a timeline, and say which inference you used.
7. **IF** telemetry source covering `auth.log` / `bash_history` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need log, utmp and audit commands | [`QUERIES.md`](QUERIES.md) | One class per log source |
| Need journal and audit tool flags | [`TOOLS.md`](TOOLS.md) | `journalctl`, `ausearch`, `aureport`, `utmpdump` |
| Need to fold this into a host timeline | [`log-and-timeline-analysis`](../log-and-timeline-analysis/SKILL.md) | Cross-source normalisation |
| Need filesystem structures underneath | [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) | Inodes, journals, offsets |
| Container workload on the host | [`container-and-kubernetes-forensics`](../container-and-kubernetes-forensics/SKILL.md) | Runtime and node evidence |
| Need kernel-level process evidence | [`memory-forensics`](../memory-forensics/SKILL.md) | Volatile artifacts |
| Need to understand the persistence techniques | [`host-persistence-linux-and-macos-persistence`](../../../red-team/network-ad-and-endpoint/host-persistence-linux-and-macos-persistence/SKILL.md) | Red counterpart |
| Need real Linux intrusion case shapes | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |

## Procedure

1. **Confirm the evidence source and its integrity.** Record the image hash and the mount options used, and record whether the system was live or dead when acquired. A live system's journal is being appended while you read it, which changes what "the last event" means.
2. **Choose the branch from what the host recorded.** Journal persistent, journal volatile, auditd enabled, syslog only, container host. Write the branch into the output — a host with only volatile journaling has a fundamentally narrower record and the report must say so before any conclusion.
3. **Establish a baseline-versus-probe differential.** Baseline is a peer host of the same distribution and role, or the host's own earlier boots from `journalctl --list-boots`. Probe is the incident window. A new systemd unit is a finding when the peer set has none and the package database owns none of it.
4. **Name the stop condition.** Declare `Inconclusive` when the journal did not survive a reboot, when an audit rule set did not cover the process or path under investigation, when utmp was rebuilt by a boot, when the only command record is a history file without timestamps, or when a container's writable layer has been discarded.
5. **State what counts as proof.** Proof is two independent records agreeing inside a stated tolerance: `auth.log` and the journal agreeing on the same ssh session's source and time; auditd `EXECVE` and a filesystem `atime`/`mtime` agreeing on a script's execution; a systemd unit's `ExecStart` path matching a file the package database does not own. A history line alone is a lead.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Journal entry with `_COMM`, `_EXE`, `_SYSTEMD_UNIT` and a microsecond UTC timestamp | systemd journal (`/var/log/journal/<machine-id>/`) | A unit started that binary at that instant; trusted fields are added by journald, not by the process |
| `wtmp` `USER_PROCESS` record with no matching `DEAD_PROCESS` | utmp record array | A session was opened and either still active or its logout record was removed; only the second is suspicious, and only with corroboration |
| auditd `EXECVE` record with `a0..aN` arguments and an epoch timestamp | auditd `type=EXECVE` | The exact argv of an executed program at that second; proves execution, not who typed it beyond the `auid`/`uid` fields |
| Traditional syslog line with no year and no offset | rsyslog text log | The event happened at that local wall-clock time; the year and zone are inferences you must state |
| Bash history with `# <epoch>` lines before commands | `~/.bash_history` with `HISTTIMEFORMAT` | Commands were recorded with times in that session; a file without these lines carries no per-command timing at all |
| Unit file under `/etc/systemd/system` with no owning package and an `ExecStart` in a temp path | systemd unit inventory plus package verification | A persistence mechanism exists that the OS did not install; the unit's own timestamps place when it was written |
| `audit.log` with a gap in record sequence numbers while the daemon reports running | auditd record stream | Records were lost or removed; the sequence gap localises the window but not the cause |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# Reads the live host's log tail and trusts bash history as a command record.
tail -50 /var/log/auth.log
cat /home/*/.bash_history
# No year or zone applied to syslog lines, no audit correlation, and no
# statement that history is written at shell exit and may never contain the
# session at all — `history -c` leaves a file with nothing to read.
```

**High-Signal Grounded Artifact:**

```bash
set -euo pipefail
MNT=/mnt/case          # read-only mount of the image
J="$MNT/var/log/journal"

# 1. Boot inventory first: it bounds every later query.
journalctl --directory="$J" --list-boots | tail -5

# 2. One window, UTC, with trusted fields rather than message text.
journalctl --directory="$J" --utc --since "$START" --until "$END" \
  -o json-pretty _COMM=sshd _SYSTEMD_UNIT=ssh.service \
  | jq -r '[.__REALTIME_TIMESTAMP, ._HOSTNAME, ._PID, ._EXE, .MESSAGE] | @tsv' \
  | head -40

# 3. Independent corroboration for the same sessions.
last -F -i -x -f "$MNT/var/log/wtmp" | head -20
ausearch -if "$MNT/var/log/audit/audit.log" -m USER_LOGIN,USER_AUTH -i 2>/dev/null | head -20
```

**Why this matters:** the strong form bounds the analysis to a boot from the journal's own index, queries by trusted field rather than message text, renders UTC, and pulls two independent sources for the same question instead of trusting one.

## When It Is NOT This Issue

- **Volatile journal after a reboot:** a host with `Storage=auto` and no `/var/log/journal` loses its journal entirely at shutdown. "No journal" is a configuration fact, and treating it as deletion is a common and serious error.
- **utmp rebuilt at boot:** `wtmp` records are appended by boot and login, and some distributions rebuild or rotate the file. A short `wtmp` after a reboot is normal.
- **Package updates and configuration management:** `systemctl daemon-reload`, ansible/puppet runs and package upgrades rewrite unit files with fresh timestamps in bulk. Verify ownership in the package database before calling a unit rogue.
- **Log rotation and journald caps:** `SystemMaxUse`, `MaxRetentionSec` and logrotate's `rotate` count determine how far back any source goes. A short log is the configured retention until you can show the configuration changed.
- **Time zone and year inference errors:** a syslog line with no year rendered against the analysis host's clock produces dates in the wrong year, and a container's UTC timestamps rendered in local time shift by hours. Both look like tampering and are report errors.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `auth.log` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the image hash and read-only mount options are recorded, and the output states whether the host was live or dead at acquisition.
- [ ] **Log sources enumerated:** for each conclusion, the output names which of journal, syslog, auditd, utmp and history were present, and which were absent by configuration.
- [ ] **Differential defined:** a peer host or the host's earlier boots were compared, and the finding is a delta rather than a single new file.
- [ ] **Stop condition cleared or declared:** journal volatility, audit rule coverage, rotation limits and timestamp-inference limits were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: linux-forensics
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
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)
- [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `linux-forensics` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — never run a query that mutates state on a live host (`last -w`, `systemctl restart`, `journalctl --rotate`), and never mount an image read-write.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 23 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/oxdf (11), CYBER_CPT/expku (7), CYBER_CPT/L5/ctf_search (2), hackerone_disclosed_reports (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
