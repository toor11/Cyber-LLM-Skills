# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-application-incident-response-webshell-discovery`](SKILL.md) | Family: **Incident Response**

Verified discovery tooling. Everything here describes, hashes or lists a candidate artifact; nothing executes a shell, issues a request to its path, or edits a file in the served tree. Confirm flags with `<tool> --help`.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sha256sum` | `sha256sum <file>` | Artifact identity before any copy; the hash describes the original | Linux / macOS |
| `find` + `comm` | `find <root> -type f -printf '%P\n'`, `comm -23 present released` | Manifest differential, the core discovery step | Linux / macOS |
| `strings` | `strings -n 6 <file>` | Read a candidate's content without executing it | Linux / macOS |
| `file` | `file <path>` | Actual type versus extension — a shell named `.jpg` still reads as PHP source | Linux / macOS |
| `auditctl` / `auditd` | `ausearch -sc execve -ts <t> -te <t>` | Worker child-process evidence when no EDR agent is installed | Linux |
| `yara` | `yara -r webshell_rules.yar <webroot>` | Candidate scoring against maintained shell rules; a signal, not proof | Cross-platform |

## Minimal Script Shape

The shape below preserves a candidate, describes it without running it, and refuses to call the finding "executed" without a request record or a child process. It never fetches the shell's URL.

```bash
#!/usr/bin/env bash
# shell-preserve.sh — preserve, describe, and state the execution evidence required.
set -euo pipefail

CANDIDATE="${1:?path to candidate file}"
CASE="${CASE:?case directory}"
mkdir -p "$CASE"

# 1. Hash first, then copy. The hash must describe the artifact as found.
hash="$(sha256sum "$CANDIDATE" | cut -d' ' -f1)"
base="$(basename "$CANDIDATE")"
cp -p "$CANDIDATE" "$CASE/${hash:0:12}-$base"

# 2. Describe: real type, size, timestamps, and a bounded string sample.
{
  printf 'path\t%s\n' "$CANDIDATE"
  printf 'sha256\t%s\n' "$hash"
  printf 'size\t%s\n' "$(stat -c %s "$CANDIDATE")"
  printf 'mtime\t%s\n' "$(stat -c %y "$CANDIDATE")"
  printf 'ctime\t%s\n' "$(stat -c %z "$CANDIDATE")"
  printf 'reported_type\t%s\n' "$(file -b "$CANDIDATE")"
} | tee "$CASE/${hash:0:12}-facts.tsv"

strings -n 6 "$CASE/${hash:0:12}-$base" | head -n 120 > "$CASE/${hash:0:12}-strings.txt"

# 3. Execution is a separate determination. Say so rather than assuming.
cat <<'EOF'
EXECUTION NOT ESTABLISHED BY FILE PRESENCE.
To call this an executed shell you need one of:
  a) an access-log record of a request to this exact path, or
  b) a worker child process inside the request window, or
  c) a response body containing command output.
Record which of the three you have. A file match alone is staged capability.
Never request the path to "test" it — that executes the shell.
EOF
```

## Notes That Prevent Wrong Runs

- Never `curl` or browse to a candidate path. That is the execution you are trying to determine, and on a production host it runs arbitrary code under the application identity.
- `sha256sum` must run before `cp`. Copying then hashing describes the copy and leaves the original's identity unrecorded.
- `file` is the fastest way to catch a shell disguised with an image extension; a `.jpg` that reports as PHP source is a finding, and its magic bytes belong in the case record.
- `rpm -Va` and `debsums -c` verify packaged files only. A shell placed in an application directory is invisible to both, which is why the manifest differential is the primary method.
- YARA rules for web shells produce false positives on legitimate back-office admin tools. Treat a match as a candidate ranking input and require Class 1 or Class 2 corroboration.
- `stat -c %z` (ctime) cannot be forged without privilege, whereas mtime can be set arbitrarily. When the two disagree, trust ctime for the dwell-window anchor.
