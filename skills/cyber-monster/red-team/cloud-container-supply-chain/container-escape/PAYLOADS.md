# Verification Probes and Expected Differentials

> Sub-skill: [`container-escape`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Control-surface inventory

```text
# Capabilities and namespace inodes inside the container.
capsh --print 2>/dev/null | rg "Current:|Bounding set"
rg -n "NSpid|CapEff|Seccomp" /proc/self/status
ls -l /proc/self/ns/pid /proc/self/ns/net /proc/self/ns/mnt
```

Expected differential: a `CapEff` of `0000000000000000` with distinct namespace inodes from the host is the control; `CapEff` including `a80425fb` (the privileged set) or inodes matching the host is the finding.

## Class 2 — Namespace-sharing proof

```text
# Compare inodes: identical values mean the namespace is shared.
echo "container:"; readlink /proc/self/ns/pid /proc/self/ns/net
echo "host:";      readlink /proc/1/ns/pid /proc/1/ns/net
```

Expected differential: different inode numbers for each namespace is the control; a matching `pid` or `net` inode proves the container shares that namespace with the node.

## Class 3 — Runtime version check

```text
runc --version 2>/dev/null || crictl info 2>/dev/null | rg -i "runc|runtimeVersion"
kubectl get nodes -o json | jq -r '.items[] | "\(.metadata.name) \(.status.nodeInfo.containerRuntimeVersion)"'
```

Expected differential: `runc 1.2.8` or later (or 1.3.3, 1.4.0-rc.3) is the control; an older version with containers using custom mounts is the advisory class, and the report cites the version rather than an exploit.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
