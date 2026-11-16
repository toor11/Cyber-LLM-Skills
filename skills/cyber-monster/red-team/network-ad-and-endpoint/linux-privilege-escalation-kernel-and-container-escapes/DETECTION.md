# Detection Signals and Blue-Team Handoff

> Sub-skill: [`linux-privilege-escalation-kernel-and-container-escapes`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- auditd `execve` for `unshare`, `nsenter`, `mount` or `setns` from a container process, the escape precursor.
- Runtime security alerts for a container opening the host runtime socket, or for `--privileged` container creation.
- Kubernetes audit log for a pod created with `hostPath`, `privileged: true` or `hostPID: true`.
- Kernel log entries for a null-pointer dereference or an oops on a host that was otherwise stable, the exploit footprint.
- auditd rules on `init_module` and `finit_module`, which record kernel module loading attempts.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-linux-and-macos`](../../../blue-team/vulnerability-and-hardening/hardening-linux-and-macos/SKILL.md) | Query authoring, triage logic, and hardening verification |
