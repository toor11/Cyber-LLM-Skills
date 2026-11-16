# Detection Signals and Blue-Team Handoff

> Sub-skill: [`angr-and-z3-constraint-solver-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Process start of the target under a debugger or angr harness with no listening socket: symbolic runs leave no network trace, so detection keys on the harness process tree instead.
- `ptrace` attach events (auditd `SYSCALL=ptrace` with `request=PTRACE_ATTACH`) from an analyst workstation rather than a build host.
- Very high single-core CPU with near-zero disk IO on the analysis host for minutes to hours, matching the solver loop rather than normal builds.
- Long-lived python processes whose command line names angr, claripy, or z3, observed by EDR process inventory.
- Solver-library load events for `libz3` on hosts that never compile solver code.
- Repeated identical short executions of the same binary with different stdin blobs, matching model replay rather than production traffic.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
