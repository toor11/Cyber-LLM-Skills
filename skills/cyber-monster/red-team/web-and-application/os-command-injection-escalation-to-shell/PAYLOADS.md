# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`os-command-injection-escalation-to-shell`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `os-command-injection-escalation-to-shell`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Interpreter-availability enumeration (read-only)

**Expected differential:** a benign lookup reveals which interpreters resolve, establishing escalation feasibility without spawning anything

```text
cmd=command -v bash python3 perl socat
cmd=uptime
```

### Single-command confirmation before any upgrade

**Expected differential:** a benign identity command confirms the account and context, distinct from the parent in that it scopes escalation potential

```text
cmd=id
cmd=disk
```

### Egress-path feasibility probe

**Expected differential:** a benign hostname resolution confirms whether outbound DNS egress exists for a potential channel, without opening one

```text
cmd=getent hosts probe.<assessor-controlled-host>
cmd=uptime
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
