# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`security-architecture-review`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ss`/`netstat` | `ss -tnp` on the service hosts | Observed connections versus the documented flow | Linux |
| `kubectl` | `kubectl get svc,ingress -A -o yaml` | Ingress paths and which pass through the gateway | Kubernetes |
| `curl` | probe with the authorisation dependency stopped | Failure-mode behaviour | Cross-platform |
| `graphviz` | render the as-built flow to a diagram for review | Shared artefact with the findings attached | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Failure-mode probe: what happens when the authorisation dependency is unavailable.
set -uo pipefail
svc=${SVC:-http://api.internal}
printf 'baseline: '; curl -sS -o /dev/null -w '%{http_code}\n' "$svc/v1/invoices/1"
kubectl scale deploy/authz-sidecar --replicas=0 >/dev/null 2>&1 || true
sleep 5
printf 'dependency down: '; curl -sS -o /dev/null -w '%{http_code}\n' "$svc/v1/invoices/1"
kubectl scale deploy/authz-sidecar --replicas=1 >/dev/null 2>&1 || true
printf 'expected: 200 baseline, 503 with dependency down; 200 on both means fail-open\n'
```

## Verification

- The baseline returns 200 and the dependency-down probe returns 503; a 200 on both is the fail-open finding.
- The sidecar is restored at the end, so the probe is safe to run in a shared environment.
- Re-running after the fix shows the degraded behaviour, proving the failure mode is now explicit.
