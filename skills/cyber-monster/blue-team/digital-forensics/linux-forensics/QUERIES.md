# Artifacts and Queries

> Sub-skill: [`linux-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction commands owned by `linux-forensics`, grouped by log source. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Everything here reads from a read-only mount or the live host without mutating it: no `--rotate`, no service restarts, no `last -w` on a live utmp.

## Class 1 — Source inventory and integrity gate

Expected hit: a statement of which log sources exist on this host and how far back each goes. Everything later depends on knowing whether an absence is a gap or a configuration choice.

```bash
CASE_ROOT=/mnt/case
ls -la "$CASE_ROOT/var/log/journal" 2>/dev/null | head -5   # persistent journal?
ls -la "$CASE_ROOT/run/log/journal" 2>/dev/null | head -5    # volatile only?
journalctl --directory="$CASE_ROOT/var/log/journal" --list-boots 2>/dev/null | tail -6
grep -E '^\s*(Storage|SystemMaxUse|MaxRetentionSec)=' "$CASE_ROOT/etc/systemd/journald.conf" 2>/dev/null
ls -la "$CASE_ROOT/var/log/audit/" "$CASE_ROOT/var/log/wtmp" "$CASE_ROOT/var/log/btmp" 2>/dev/null
```

False-positive note: `Storage=auto` with no `/var/log/journal` directory means the journal lives on tmpfs and is gone after a reboot. That is a configuration fact, and reporting it as log deletion is a factual error the other side will find.

## Class 2 — Authentication and session records

Expected hit: `USER_LOGIN`/`USER_AUTH` in auditd, `sshd`/`sudo` lines in the auth log, and `USER_PROCESS` records in `wtmp`, all agreeing on source address and time for the same session.

```bash
CASE_ROOT=/mnt/case
last -F -i -x -f "$CASE_ROOT/var/log/wtmp" | head -25
lastb -F -i -f "$CASE_ROOT/var/log/btmp" 2>/dev/null | head -15
utmpdump "$CASE_ROOT/var/log/wtmp" 2>/dev/null | tail -20    # fields `last` hides

ausearch -if "$CASE_ROOT/var/log/audit/audit.log" -m USER_LOGIN,USER_AUTH -i \
  --start "$START_DATE" --end "$END_DATE" 2>/dev/null | head -40
```

False-positive note: `wtmp` is a plain record array and root can remove a single record; `utmpdump -r` converts edited text back to binary. A session present in `wtmp` but absent from the auth log and audit is the anomaly — not a short `wtmp` by itself, which a reboot explains.

## Class 3 — Journal queries by trusted field

Expected hit: entries bounded to one boot, filtered on fields journald itself added (`_COMM`, `_EXE`, `_SYSTEMD_UNIT`), rendered in UTC. Message-text searches miss entries whose text the attacker controlled.

```bash
JDIR=/mnt/case/var/log/journal
journalctl --directory="$JDIR" --utc --since "$START" --until "$END" -o json-pretty \
  _SYSTEMD_UNIT=ssh.service \
| jq -r '[.__REALTIME_TIMESTAMP, ._PID, ._UID, ._EXE, .MESSAGE] | @tsv' | head -30

journalctl --directory="$JDIR" --utc --boot -1 -p warning --no-pager | tail -40
```

False-positive note: `_EXE` and `_COMM` are captured at message time; a process that renamed itself after exec still shows the original path, which is the point — but a legitimate wrapper script shows the interpreter, not the script. Do not read `_EXE` as "what the user ran".

## Class 4 — auditd command and file-access records

Expected hit: `EXECVE` records with argv, `SYSCALL` records with `auid`/`uid`, and `PATH` records for the watched file — all sharing an `event ID` so they can be joined.

```bash
A=/mnt/case/var/log/audit/audit.log
ausearch -if "$A" -m EXECVE -i --start "$START_DATE" --end "$END_DATE" | head -40
ausearch -if "$A" -k exec_priv -i 2>/dev/null | tail -20
aureport -if "$A" --login --summary -i 2>/dev/null | head -20
aureport -if "$A" -au -i 2>/dev/null | head -20
```

False-positive note: `-i` resolves numeric UIDs against the *analysis host's* user database unless the log was written in enriched format. Check resolved names against the image's `/etc/passwd` before quoting a username. `--start` also parses in the analysis host's locale.

## Class 5 — Shell history and its limits

Expected hit: a history file whose usefulness you can state precisely — with `# <epoch>` lines if `HISTTIMEFORMAT` was set, without them otherwise, and with a stated possibility that the session never wrote anything.

```bash
CASE_ROOT=/mnt/case
for h in "$CASE_ROOT"/home/*/.bash_history "$CASE_ROOT"/root/.bash_history; do
  [ -f "$h" ] || continue
  echo "== $h  lines=$(wc -l < "$h")  epoch_marks=$(grep -c '^#[0-9]\{10\}$' "$h" || true)"
  tail -15 "$h"
done
ls -la "$CASE_ROOT/home"/*/.zsh_history 2>/dev/null
```

False-positive note: bash writes history at shell exit by default, so a session killed with `SIGKILL` leaves nothing; `history -c` in the same session empties the in-memory list before it is ever written. Absence of history is not absence of activity — correlate with auditd and file times in `/tmp` and `/dev/shm`.

## Class 6 — Persistence inventory and package verification

Expected hit: units and cron entries that the package database owns. Anything unowned, or owned but modified, is the candidate.

```bash
CASE_ROOT=/mnt/case
ls -la "$CASE_ROOT"/etc/systemd/system/*.service "$CASE_ROOT"/etc/systemd/system/*.timer 2>/dev/null
find "$CASE_ROOT/home" -path '*/.config/systemd/user/*' -name '*.service' 2>/dev/null
cat "$CASE_ROOT"/etc/crontab 2>/dev/null | tail -10
ls -la "$CASE_ROOT"/var/spool/cron/crontabs/ 2>/dev/null

# Package ownership and modification, using the image's own database.
chroot "$CASE_ROOT" rpm -Va --nofiles --nodigest 2>/dev/null | head -30 || \
  chroot "$CASE_ROOT" dpkg -V 2>/dev/null | head -30
```

False-positive note: `rpm -Va` reports configuration files as modified by design, and `dpkg -V` flags files whose mtime changed. A modified config file is expected; a unit file with no owning package is not. Filter before reporting.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, beside every Linux finding, which log sources existed on that host and whether the journal was persistent; a conclusion from a host with volatile journaling has a much narrower basis.
