# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`container-and-kubernetes-forensics`](SKILL.md) | Family: **Digital Forensics**

Read-only entry points for collecting evidence from a cluster and its nodes. Never invent undocumented flags — confirm with `<tool> --help` on the installed build, because `crictl` and `kubectl` both change their output surfaces between minor releases. Nothing here mutates a workload: no `delete`, no `drain`, no `exec` into a suspect container.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `kubectl` (read verbs) | `kubectl get pod <name> -n <ns> -o yaml --show-managed-fields` | Freeze the workload's spec and owner chain before anything is deleted | Cross-platform |
| `kubectl debug` | `kubectl debug -it <pod> --image=<tools> --target=<container>` | Add an inspection container instead of executing in the suspect one | Cross-platform |
| `crictl` | `crictl --runtime-endpoint unix:///run/containerd/containerd.sock inspect <id>` | Read container, image and snapshot state from the node's CRI | Linux node |
| `crictl logs` | `crictl logs --timestamps <id>` | Container stdout/stderr straight from the runtime, independent of the kubelet copy | Linux node |
| `ctr` (containerd) | `ctr -n k8s.io images ls` / `ctr -n k8s.io snapshots ls` | Enumerate image content and snapshot layers on the node | Linux node |
| `jq` | `jq -c 'select(.objectRef.subresource=="exec")' audit.log` | Bounded extraction from an exported audit log | Cross-platform |

## Minimal Script Shape

The below collects the planes in persistence order and refuses to produce a verdict when audit coverage is absent — the failure mode that turns every container investigation into a guess.

```bash
#!/usr/bin/env bash
# k8s-evidence-capture.sh — read-only capture of the planes that survive.
set -euo pipefail

NS="${NS:?namespace}"; POD="${POD:?pod}"; OUT="${OUT:?output dir}"
mkdir -p "$OUT"

# 1. Freeze the workload spec while it still exists.
kubectl get pod "$POD" -n "$NS" -o yaml            > "$OUT/pod.yaml"
kubectl get events -n "$NS" --sort-by=.lastTimestamp > "$OUT/events.txt"

# 2. Audit log: copy the control-plane file as-is, then hash it.
if [ -r /var/log/kubernetes/audit/audit.log ]; then
  cp --reflink=auto /var/log/kubernetes/audit/audit.log "$OUT/audit.log"
else
  echo "GAP: audit log not readable here -> INCONCLUSIVE (Telemetry Gap)" | tee "$OUT/GAP"
fi

# 3. Node stores and pod logs from a mounted copy.
for p in /var/lib/containerd /var/log/pods; do
  [ -d "$p" ] && cp -a --reflink=auto "$p" "$OUT/$(basename "$p")" || echo "GAP: $p absent"
done

find "$OUT" -type f -print0 | xargs -0 sha256sum > "$OUT/manifest.sha256"
[ -f "$OUT/GAP" ] && echo "verdict withheld: see GAP" || echo "capture complete: $OUT"
```

## Notes That Prevent Wrong Runs

- `kubectl debug` needs the `pods/ephemeralcontainers` subresource, so it will itself appear in the audit log. Note your own action in the report so it is not later read as adversary activity.
- `crictl` requires the runtime endpoint; on k3s and some managed nodes it differs from the containerd default. Read the endpoint from the runtime configuration rather than guessing.
- Deleting a pod destroys its writable overlay layer. If you must delete for containment, copy the node snapshot directory first — or accept, and state, that the runtime-written files are gone.
- Managed control planes may not expose the audit file at all; use the provider's control-plane log export instead and record the export's own configuration and retention.
- `kubectl get events` is a live API read bounded by `--event-ttl` (one hour by default). Capture it early; it is the shortest-lived artifact in the whole investigation.
