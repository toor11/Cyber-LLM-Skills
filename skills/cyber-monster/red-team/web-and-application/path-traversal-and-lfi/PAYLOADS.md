# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`path-traversal-and-lfi`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `path-traversal-and-lfi`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Known-versus-missing read differential

**Expected differential:** a known in-root file returns content while a guaranteed-missing sibling returns not-found, establishing the read channel before escape is tested

```text
file=../../../../etc/hostname
file=../../../../etc/zzz-not-present
```

### Depth-escalation ladder

**Expected differential:** increasing parent-segment depth eventually reaches an out-of-root file, where a confined resolver returns not-found at every depth

```text
file=../etc/hostname
file=../../../../../../etc/hostname
```

### Windows UNC and absolute override

**Expected differential:** a UNC or absolute form resolves outside the local root, where containment confines both to a not-found

```text
file=\\<assessor-controlled-host>\share\marker
file=C:\Windows\win.ini
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
