# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`secrets-management-and-key-custody`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `gitleaks` | `gitleaks detect --source . --redact --report-format sarif --report-path gl.sarif` | History-wide scan with redaction | Cross-platform |
| `trufflehog` | `trufflehog git file://. --only-verified --json` | Verified live credentials only, which removes fixture noise | Cross-platform |
| `vault` | `vault kv get -field=key secret/apps/checkout` and `vault token lookup` | Confirm the reader identity and audit trail | Cross-platform |
| `docker` | `docker history --no-trunc IMAGE` | Show build args and env baked into layers | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Rotation probe: material must be re-readable without rebuilding the image.
set -euo pipefail
path=${1:?secret path}; key=${2:-key}
before=$(vault kv get -field="$key" "secret/$path")
vault kv metadata put -max-versions=2 "secret/$path" >/dev/null
vault kv put "secret/$path" "$key=$(openssl rand -hex 32)" >/dev/null
kubectl rollout restart deploy/checkout >/dev/null
kubectl rollout status deploy/checkout --timeout=120s >/dev/null
after=$(kubectl exec deploy/checkout -- cat /var/run/secrets/app/key)
[ "$before" != "$after" ] && echo "OK: workload picked up the rotated value"
vault audit list >/dev/null && echo "audit device enabled"
```

## Verification

- The probe prints OK only when the running pod reads the new value, which is the difference between rotation and a documented policy.
- `vault audit list` shows an enabled device, so the read is attributable afterwards.
- Re-running without rotating must print nothing (no false OK), proving the comparison is real.
