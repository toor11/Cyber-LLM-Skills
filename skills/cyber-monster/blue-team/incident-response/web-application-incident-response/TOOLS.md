# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-application-incident-response`](SKILL.md) | Family: **Incident Response**

Verified collection and verification tooling for a web tier. Everything here reads or copies; nothing modifies the served tree, restarts a service or replays a request. Confirm flags with `<tool> --help`.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tar` | `tar czf case-web01-$(date -u +%Y%m%dT%H%MZ).tgz /var/www/app /etc/nginx` | Preserve code, config and served content in one hashed archive | Linux |
| `sha256sum` | `sha256sum -c manifest.sha256` | Verify a preserved archive or a tree against a known-good list | Linux / macOS |
| `docker save` / `podman save` | `docker save <image>@sha256:<digest> -o tier-image.tar` | Preserve the exact image the tier ran, by digest not tag | Cross-platform |
| `syft` | `syft <image> -o spdx-json > tier-sbom.json` | Component inventory for the running image | Cross-platform |
| `auditctl` / `ausearch` | `ausearch -sc execve -ts <t> -te <t> -m EXECVE` | Worker child-process evidence where no EDR agent exists | Linux |
| `Get-WinEvent` | `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-IIS-Configuration'; StartTime=(Get-Date).AddDays(-7)}` | IIS configuration changes, which often accompany a placed handler mapping | Windows |

## Minimal Script Shape

The shape below preserves the tier before anyone changes it and produces the integrity differential that the leaf skills depend on. It writes only to a case directory.

```bash
#!/usr/bin/env bash
# tier-preserve.sh — copy and verify; change nothing on the tier.
set -euo pipefail

WEBROOT="${WEBROOT:?}"
CASE="${CASE:?case directory}"
MANIFEST="${MANIFEST:-}"
STAMP="$(date -u +%Y%m%dT%H%MZ)"

mkdir -p "$CASE/$STAMP"

# 1. Preserve code, config and the served tree in one archive, then hash the archive.
tar czf "$CASE/$STAMP/webroot.tgz" -C / "$(echo "$WEBROOT" | sed 's|^/||')" 2>/dev/null || \
  tar czf "$CASE/$STAMP/webroot.tgz" "$WEBROOT"

sha256sum "$CASE/$STAMP/webroot.tgz" > "$CASE/$STAMP/webroot.tgz.sha256"

# 2. Preserve the deployment record so the differential is reproducible later.
[ -n "$MANIFEST" ] && cp "$MANIFEST" "$CASE/$STAMP/release-manifest.tsv" || \
  echo "GAP: no release manifest supplied - integrity differential will be heuristic"

# 3. Runtime state: what the worker actually is, without restarting it.
{
  printf 'pid\tppid\tcomm\targs\n'
  ps -eo pid,ppid,comm,args --no-headers | \
    grep -E 'apache2|httpd|nginx|php-fpm|php-cgi|node|java|uwsgi|gunicorn' || true
} > "$CASE/$STAMP/worker-processes.tsv"

# 4. Egress state as it stood at capture time (not a substitute for flow history).
ss -tunap 2>/dev/null | grep -E 'apache2|httpd|nginx|php-fpm|node|java' \
  > "$CASE/$STAMP/worker-sockets.txt" || true

printf 'preserved to %s\n' "$CASE/$STAMP"
printf 'next: differential against release-manifest.tsv, then request reconstruction in the access-log leaf\n'
```

## Notes That Prevent Wrong Runs

- Preserve before you patch, restart or rebuild. A restarted worker loses its child-process tree and its in-memory state, and the placement evidence goes with it.
- `docker save` by tag can capture a different image than the one that ran if the tag moved. Resolve and record the digest first.
- `tar` of a live served tree can capture a torn file. For a single suspect artifact, hash and copy the file itself, then archive the tree as supporting context.
- `sha256sum -c` against a manifest verifies the preserved copy. It does not verify the tier; run the differential against the tier separately and keep the two results distinct.
- `auditctl` rules added after the incident only see forward from that moment. If the audit daemon was not watching `execve` during the window, the correct conclusion is a telemetry gap, not an absence of child processes.
- IIS configuration events reveal handler mappings and module changes, which are frequently how a shell becomes executable in a directory that previously served static content.
