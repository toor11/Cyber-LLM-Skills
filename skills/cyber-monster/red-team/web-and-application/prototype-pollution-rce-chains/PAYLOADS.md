# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`prototype-pollution-rce-chains`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `prototype-pollution-rce-chains`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Spawn env gadget

**Expected differential:** a child process echoes RC_MARKER from its env only when the spawn inherits the polluted default

```text
{"__proto__":{"env":{"RC_MARKER":"set"}}}
```

### EJS compile-option gadget

**Expected differential:** an inert outputFunctionName token appears in compiled output, proving the compile option is read from the prototype

```text
{"__proto__":{"outputFunctionName":"rc_marker"}}
```

### Shell-default probe

**Expected differential:** a benign shell:false default read at spawn confirms the option is inherited without running a command

```text
{"__proto__":{"shell":false}}
```

### Marker verification

**Expected differential:** RC_MARKER surfaces in the child environment reflected back by the app, confirming the chain inertly

```text
verify RC_MARKER appears in the spawned child environment
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
