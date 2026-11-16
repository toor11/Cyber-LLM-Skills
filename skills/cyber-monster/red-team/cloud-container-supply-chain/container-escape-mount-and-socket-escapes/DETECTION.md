# Detection Signals and Blue-Team Handoff

> Sub-skill: [`container-escape-mount-and-socket-escapes`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Kubernetes audit log: a pod created with a `hostPath` volume referencing `/var/run`, `/`, `/etc`, or `/var/lib/kubelet`.
- Runtime event: a container process connecting to a Unix socket owned by the container runtime, visible in socket-level audit tools.
- Docker daemon log: an API request from a source address inside a container's network, which indicates socket proxying.
- Node audit: a write to `/etc/passwd`, `/etc/cron.d`, or a systemd unit from a process whose cgroup is a container.
- Admission audit: a pod denied by a policy forbidding host paths, which is the control firing.
- Image and manifest scan: a compose file or Helm chart adding `/var/run/docker.sock`, detected at review.
- Runtime version event: runc below the patched set on a node that runs containers with custom mounts.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
