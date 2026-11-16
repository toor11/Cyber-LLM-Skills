# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`os-command-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `os-command-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Command-separator differential (reflected output)

**Expected differential:** the value with a separator adds command output to the response while the benign value does not, and the difference vanishes with an argument vector

```text
ping=127.0.0.1 && id
ping=127.0.0.1
```

### Command substitution probe

**Expected differential:** a substitution form evaluates inside the filename or field while the literal form is passed through unchanged

```text
file=report$(id).pdf
file=report.pdf
```

### Executing-identity confirmation

**Expected differential:** a benign identity command returns the service account in the output, confirming execution context without any destructive action

```text
host=localhost | whoami
host=localhost
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
