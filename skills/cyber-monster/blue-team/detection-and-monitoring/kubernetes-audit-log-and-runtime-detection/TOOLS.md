# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`kubernetes-audit-log-and-runtime-detection`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for reading audit policy, proving runtime coverage, and querying either plane without mutating the cluster. Never invent undocumented flags — check `--help` on the installed version, because `kubectl` output flags and Falco rule fields differ across minor releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `kubectl` (policy) | `kubectl get cm -n kube-system audit-policy -o jsonpath={.data}` | Read the audit policy in force, confirming which resources reach `Request`/`RequestResponse` | Any host with kubeconfig |
| `kubectl auth` | `kubectl auth can-i create clusterrolebindings --as system:serviceaccount:default:probe` | Test whether a service account can perform a binding without performing it | Any host with kubeconfig |
| `jq` (audit slicing) | `jq -c 'select(.objectRef.subresource=="exec")' audit.log` | Reduce a JSONL audit file to exec requests only, preserving principal and pod | Linux, macOS, Windows |
| `falco` | `falco -c /etc/falco/falco.yaml -r /etc/falco/rules.d -L` then `falco --list=k8saudit` | Validate rule load order and list available k8saudit fields before writing a condition | Linux (node or sidecar) |
| `tetra` (Tetragon CLI) | `tetra getevents -o compact --namespace prod-payments` | Stream runtime process events for a namespace to confirm sensor coverage | Linux with Tetragon agent |
| `kube-bench` | `kube-bench run --targets master` | Verify the control plane's audit arguments are set as the policy assumes | Linux control plane |

## Minimal Script Shape

The shape below is the smallest defensible evidence pull: it proves the policy ceiling, then counts exec requests per principal over one window without touching the cluster.

```bash
#!/usr/bin/env bash
# k8s-audit-exec-diff.sh — coverage gate, then per-principal exec counts.
set -euo pipefail

WINDOW_H="${WINDOW_H:-24}"
OUT="${OUT:-./audit-slice.jsonl}"

# 0. Policy ceiling: without Request/RequestResponse the spec rules cannot work.
kubectl get --raw /api/v1/namespaces/kube-system/configmaps/audit-policy \
  | jq -r '.data["audit-policy.yaml"]' > ./audit-policy.yaml
grep -q 'level: Request' ./audit-policy.yaml \
  || echo "GAP: policy is metadata-or-none -> spec-based rules INCONCLUSIVE"

# 1. Slice only accepted interactive subresource requests.
jq -c --argjson w "$WINDOW_H" '
  select(.verb == "create")
  | select(.objectRef.subresource | IN("exec","attach","portforward"))
  | select(.responseStatus.code < 400)
  | {ts: .requestReceivedTimestamp, user: .user.username,
     ns: .objectRef.namespace, pod: .objectRef.name,
     src: (.sourceIPs // []), id: .auditID}' \
  "$OUT"

# 2. Per-principal count, printed as the differential input.
jq -r '.user' "$OUT" | sort | uniq -c | sort -rn
```

## Notes That Prevent Wrong Runs

- `kubectl get --raw` reads the API server directly; it does not need a kubeconfig context switch, but it does need credentials with `get` on `configmaps` in `kube-system`.
- `-L` on `falco` prints the loaded rules and exits; it is the safe way to confirm a rule exists before trusting a quiet alert stream.
- A rule that reads `responseObject` needs `RequestResponse` audit level; at `Metadata` the field is absent and the rule returns empty rather than erroring.
- `tetra getevents` streams until interrupted and does not write state; it is safe on a production node but will emit a continuous volume, so scope it with `--namespace` or `--pods`.
