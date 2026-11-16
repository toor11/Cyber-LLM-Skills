# Verification Probes and Expected Differentials

> Sub-skill: [`container-escape-mount-and-socket-escapes`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Mount inventory

```text
kubectl get pods -A -o json | jq -r '  # container-escape-mount-and-socket-escapes: class 1 mount inventory
  .items[] | . as $p | ($p.spec.volumes // [])[]
  | select(.hostPath != null)
  | "\($p.metadata.namespace)/\($p.metadata.name) \(.hostPath.path) ro=\(.hostPath.type // "unset")"'
```

Expected differential: a host path of `/`, `/etc`, `/var/lib/kubelet`, `/proc`, or a socket directory is the finding; a host path of a data directory with no credentials is a weaker note.

## Class 2 — Socket reachability probe

```text
# Does the socket answer? Read the runtime version only; do not start anything.
docker -H unix:///var/run/docker.sock version --format '{{.Server.Version}}' 2>&1 | head -1
crictl --runtime-endpoint unix:///run/containerd/containerd.sock version 2>&1 | head -2
```

Expected differential: a version string proves the socket answers and the escape is complete; a permission error means the socket is present but not usable by this user, which changes severity but not the design finding.

## Class 3 — Host filesystem writability

```text
# Read-only checks of what the mount exposes.
test -w /host/etc/passwd && echo "WRITABLE host passwd"
head -c 40 /host/etc/shadow 2>&1 | head -1
ls -l /var/lib/kubelet/pki/ 2>&1 | head -3
```

Expected differential: `WRITABLE` on a host system file or a readable kubelet private key completes the branch; `Permission denied` on both means DAC still separates the container from the host despite the mount.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
