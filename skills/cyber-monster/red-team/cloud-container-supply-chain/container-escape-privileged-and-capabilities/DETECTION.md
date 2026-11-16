# Detection Signals and Blue-Team Handoff

> Sub-skill: [`container-escape-privileged-and-capabilities`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Admission audit: a pod whose `securityContext.capabilities.add` is non-empty, outside an approved DaemonSet allowlist.
- Runtime signal: a container process whose `CapEff` includes bit 21 (`SYS_ADMIN`), read from the runtime's process inspection.
- Image scan: a file capability on a binary in an image layer, which the manifest never shows.
- Node audit: a `mount` syscall from a container process, which requires `SYS_ADMIN` and is the operative step.
- Policy engine log: a `restricted` Pod Security denial naming `capabilities`, which is the control firing.
- Kubernetes audit log: a pod created with `allowPrivilegeEscalation` unset while the namespace enforces `restricted`.
- Process event: `ptrace` from a container process against a process it does not own, which requires `SYS_PTRACE` and is the memory-read step.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
