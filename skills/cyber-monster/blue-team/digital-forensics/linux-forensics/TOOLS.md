# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`linux-forensics`](SKILL.md) | Family: **Digital Forensics**

Read-only entry points for Linux host evidence. Never invent undocumented flags — confirm with `man <tool>` on the distribution you are analysing, because `journalctl`'s output options and `ausearch`'s date parsing differ across versions and locales. Nothing here mutates a live host: no rotation, no service restart, no write to utmp.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `journalctl` | `journalctl --directory=<dir> --utc --since <t> --until <t> -o json-pretty` | Query a copied journal by trusted field, in UTC, with structured output | Linux |
| `journalctl --list-boots` | `journalctl --directory=<dir> --list-boots` | Enumerate boots with their first and last entry — the cheapest system timeline | Linux |
| `last` / `lastb` | `last -F -i -x -f <wtmp copy>` | Login, logout, reboot and runlevel records with full timestamps and years | Linux |
| `utmpdump` | `utmpdump <wtmp copy>` | Render every utmp record, including fields `last` hides | Linux |
| `ausearch` | `ausearch -if <audit.log> -m EXECVE -i --start <t>` | Join audit records by message type with interpreted fields | Linux |
| `aureport` | `aureport -if <audit.log> --login --summary -i` | Aggregate authentication and execution events for a quick shape | Linux |

## Minimal Script Shape

The shape below establishes which sources exist and how far back they reach before it answers anything, and it refuses to draw a conclusion on a host whose journal was never persistent.

```bash
#!/usr/bin/env bash
# linux-source-gate.sh — enumerate log sources and their coverage; no host mutation.
set -euo pipefail

MNT="${1:?usage: linux-source-gate.sh <read-only mount>}"
J_PERSIST="$MNT/var/log/journal"
J_VOLATILE="$MNT/run/log/journal"

report() { printf '%-28s %s\n' "$1" "$2"; }

if [ -d "$J_PERSIST" ]; then
  report "journal" "persistent at /var/log/journal"
  journalctl --directory="$J_PERSIST" --list-boots | tail -3 | sed 's/^/  /'
elif [ -d "$J_VOLATILE" ]; then
  report "journal" "VOLATILE only - lost on reboot -> narrower record"
else
  report "journal" "absent -> INCONCLUSIVE for journal questions"
fi

for f in var/log/audit/audit.log var/log/wtmp var/log/btmp var/log/secure var/log/auth.log; do
  if [ -e "$MNT/$f" ]; then report "$f" "$(stat -c '%s bytes, mtime %y' "$MNT/$f")"; else report "$f" "absent"; fi
done

grep -E '^\s*(Storage|SystemMaxUse|MaxRetentionSec)=' "$MNT/etc/systemd/journald.conf" 2>/dev/null \
  | sed 's/^/journald: /' || report "journald.conf" "no explicit limits (defaults apply)"
echo "gate complete: state which sources were absent before interpreting any gap"
```

## Notes That Prevent Wrong Runs

- `journalctl --directory=` reads a copied journal without touching the host's own journal. `--file=` works for a single `.journal` file; both need the machine-ID directory intact.
- Traditional syslog timestamps have no year and no zone. Derive the year from rotation order and mtimes, and the zone from `/etc/localtime`, then say in the report that you inferred both.
- `last -F` adds the year; `-x` adds shutdown and runlevel records; `-i` prints IPs rather than resolved names, which avoids a DNS lookup on an analysis host that should not be resolving anything.
- `ausearch -i` interprets UIDs using the analysis host's database. Cross-check any resolved username against the image's `/etc/passwd`.
- `chroot` into a mounted image runs that image's binaries, which is convenient for `rpm -V` and `dpkg -V` but executes untrusted code. Prefer running the package tool with an explicit `--root`-style option where available, or verify on a copy.
- Never run `journalctl --rotate`, `logrotate -f` or a service restart against a live host you are investigating; each destroys the record you were asked to preserve.
