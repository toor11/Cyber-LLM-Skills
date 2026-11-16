# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`os-command-injection-shell-metacharacter-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `os-command-injection-shell-metacharacter-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Space-substitution survival (IFS)

**Expected differential:** an IFS-based form executes where the space-bearing form is stripped, shown by the marker appearing only for the IFS form

```text
q=echo${IFS}MARKER_METACHAR
q=echo MARKER_METACHAR
```

### Keyword-splitting survival

**Expected differential:** a quote-split keyword runs while the plain keyword is filtered, proving word matching is bypassed

```text
q=who''ami
q=whoami
```

### Brace-expansion survival

**Expected differential:** a brace-expanded form reconstructs the command without spaces, executing where the separated form is blocked

```text
q={echo,MARKER_BRACE}
q=echo MARKER_BRACE
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
