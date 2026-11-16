# Detection Signals and Blue-Team Handoff

> Sub-skill: [`container-escape`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Runtime event: a container started with `privileged: true` outside an approved DaemonSet set.
- Node audit: a mount syscall inside a container referencing a host block device or `/proc/sys`.
- Kubernetes audit log: a pod created with a `hostPath` volume referencing `/var/run` or `/`.
- Runtime log (runc or containerd): the version at startup, compared against the patched set.
- Process event: a container process with `CapEff` equal to the privileged set, from the runtime's own inspection.
- Namespace event: a container sharing the node's PID namespace, detectable from the runtime's namespace records.
- Admission audit: a pod denied by a policy that forbids host namespaces, which is the control firing.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
