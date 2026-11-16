# Artifacts and Queries

> Sub-skill: [`container-and-kubernetes-forensics`](SKILL.md) | Family: **Digital Forensics**

Evidence-extraction queries and artifact-location checks owned by `container-and-kubernetes-forensics`. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Collection is read-only: no pod deletion, no `exec` into a suspect container, no node drain. Confirm field names against your cluster's audit policy and runtime before relying on any filter.

## Class 1 — Audit coverage gate (run before any other class)

Expected hit: an audit policy present, an audit log destination configured, and a stated level. Without this, every later class returns a false negative that looks like a clean cluster.

```bash
# Control-plane host; read-only inspection of configuration and file state.
ps -o args= -C kube-apiserver | tr ' ' '\n' | grep -E '^--(audit-log-path|audit-policy-file|audit-log-maxage|audit-log-maxbackup|audit-log-maxsize)='
ls -la /var/log/kubernetes/audit/ 2>/dev/null
head -c 400 /var/log/kubernetes/audit/audit.log 2>/dev/null
```

False-positive note: a managed control plane hides these flags, so an empty result means "not visible from the node", not "not configured". For managed clusters query the provider's control-plane log destination instead, and record which method you used.

## Class 2 — Execution subresources (exec, attach, port-forward)

Expected hit: `objectRef.subresource` of `exec`/`attach`/`portforward`, with `responseStatus.code: 101` for sessions that opened and `403` for attempts RBAC refused. The `command=` parameters name what was invoked.

```bash
# Bounded extraction from an exported audit log (JSON lines).
jq -c 'select(.objectRef.subresource? // "" | test("^(exec|attach|portforward)$"))
       | {ts: .requestReceivedTimestamp, verb, user: .user.username,
          ns: .objectRef.namespace, pod: .objectRef.name,
          uri: .requestURI, code: .responseStatus.code,
          src: .sourceIPs}' audit.log \
| jq -s 'group_by(.user) | map({user: .[0].user, n: length, codes: (map(.code)|unique)})'
```

False-positive note: since WebSocket streaming became the default, the same session can appear as `get` rather than `create`, and long sessions emit both `ResponseStarted` and `ResponseComplete` stages — de-duplicate on `auditID`, or you will count one session several times.

## Class 3 — Ephemeral container injection

Expected hit: a `patch` on `pods/ephemeralcontainers` by an unexpected identity, normally followed by an `attach` to the same pod. This is the stealthier alternative to `exec` and shares the target's namespaces.

```bash
jq -c 'select(.objectRef.subresource? == "ephemeralcontainers")
       | {ts: .requestReceivedTimestamp, verb, user: .user.username,
          ns: .objectRef.namespace, pod: .objectRef.name,
          code: .responseStatus.code, src: .sourceIPs,
          image: (.requestObject.spec.ephemeralContainers // [] | map(.image))}' audit.log
```

False-positive note: platform debugging and some operators inject debug containers legitimately, and admission controllers may re-write the object. Match the identity against the documented operator set and read the injected image before concluding anything about intent.

## Class 4 — Node-level container filesystem evidence

Expected hit: image layers present in the content store, the container's snapshot directory, and a clear statement of which path is image-backed, overlay-backed or volume-backed.

```bash
# Run on a mounted copy of the node filesystem, never on the live node.
CRI=/evidence/node/var/lib/containerd
ls -la "$CRI/io.containerd.content.v1.content/blobs/sha256" | head
find "$CRI/io.containerd.snapshotter.v1.overlayfs/snapshots" -maxdepth 2 -name upper -printf '%p\n' 2>/dev/null | head
find "$CRI/io.containerd.snapshotter.v1.overlayfs/snapshots" -path '*/upper/*' -newermt "$START" -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | head -50
```

False-positive note: `newermt` on the upper layer finds runtime writes, which include application temp files, package caches and log rotation — not only attacker activity. Attribute by path and by ownership, and remember the upper layer disappears with the container, so a node snapshot taken after removal has none of it.

## Class 5 — Kubelet pod logs and lifecycle events

Expected hit: `/var/log/pods/<namespace>_<pod>_<uid>/` directories and their rotated files surviving pod deletion until rotation, plus Events for the same pod inside the event TTL.

```bash
find /evidence/node/var/log/pods -maxdepth 2 -type d -name '*_*_*' \
  -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort | tail -40
kubectl get events -A --sort-by=.lastTimestamp \
  -o custom-columns='TIME:.lastTimestamp,NS:.metadata.namespace,OBJ:.involvedObject.name,REASON:.reason,MSG:.message' \
  | tail -60
```

False-positive note: `kubectl get events` returns only what the API server still holds — one hour by default — so an empty list is a retention statement. Rotated `*.log.*` files under the pod directory may be the only surviving record and are frequently overlooked.

## Class 6 — Identity and secret access

Expected hit: `get`/`list` on `secrets` or `serviceaccounts/token` by a workload service account, or by an unexpected human identity, inside the incident window.

```bash
jq -c 'select(.objectRef.resource? == "secrets" or (.objectRef.subresource? == "token"))
       | select(.verb == "get" or .verb == "list" or .verb == "create")
       | {ts: .requestReceivedTimestamp, verb, user: .user.username,
          ns: .objectRef.namespace, name: .objectRef.name, src: .sourceIPs}' audit.log \
| jq -s 'group_by(.user) | map(select(length > 5) | {user: .[0].user, n: length})'
```

False-positive note: projected service-account tokens are refreshed by the kubelet, and some controllers list secrets as part of normal reconciliation. Baseline the identity's normal rate before treating a burst as enumeration, and note that the audit log records the request, never whether the returned object was used.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the audit policy level and the retention of both the API-server file and the shipped copy next to every container finding; a finding from one without the other is not reviewable.
