# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`path-traversal-and-lfi-lfi-to-rce`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `path-traversal-and-lfi-lfi-to-rce`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Read-versus-interpret differential

**Expected differential:** the benign server file returns as inert text while the poisoned sink, if interpreted, evaluates a harmless marker; an identical read with no evaluation means read-only inclusion

```text
view=../../../../etc/hostname
view=../../../../var/log/apache2/access.log
view=../../../../proc/self/environ
```

### Session-file sink probe

**Expected differential:** a session variable set to an inert marker appears when the session file is included by its PHPSESSID path, proving a controllable write surface

```text
Cookie: PHPSESSID=assessor-probe-01
profile_name=marker-ptlfirce-inert
```

### Wrapper boundary check (routes to php-wrappers if positive)

**Expected differential:** a php://filter prefix changes the response versus a plain path, indicating the primitive is a wrapper and belongs to the php-wrappers skill

```text
view=php://filter/read=convert.base64-encode/resource=index
view=index
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
