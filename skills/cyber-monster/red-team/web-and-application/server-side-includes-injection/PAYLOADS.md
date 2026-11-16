# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`server-side-includes-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `server-side-includes-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Literal-versus-directive echo

**Expected differential:** the encoded literal stays as text while the live echo resolves a server variable, proving evaluation

```text
bio field set to an HTML-encoded echo directive for DATE_LOCAL
bio field set to a raw echo directive for DATE_LOCAL
```

### Benign variable disclosure

**Expected differential:** a known server variable renders its value, confirming evaluation without touching the filesystem

```text
comment field set to a raw echo directive for DOCUMENT_NAME
comment field set to a raw echo directive for SERVER_SOFTWARE
```

### Include reachability

**Expected differential:** including a world-readable non-sensitive virtual path returns its content, proving file read without exfiltrating secrets

```text
note field set to an include directive for the virtual path /robots.txt
note field set to an include directive for a nonexistent SSI probe path
```

### Exec capability check

**Expected differential:** a harmless exec that echoes a fixed string resolves only if Options include Includes without NOEXEC

```text
field set to an exec directive echoing the fixed string ssi-probe
field set to a printenv directive with no command
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
