# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`os-command-injection-argument-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `os-command-injection-argument-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Output-option smuggling (curl family)

**Expected differential:** a value starting with -o changes where the tool writes, while a positional URL produces normal output

```text
url=-o/tmp/<assessor-writable-file>
url=https://<assessor-controlled-host>/ok
```

### Helper-option smuggling (git family)

**Expected differential:** an --upload-pack style option alters the transport helper, while a positional repository URL clones normally

```text
repo=--upload-pack=echo
repo=https://<assessor-controlled-host>/r.git
```

### End-of-options differential

**Expected differential:** a dash-prefixed value is parsed as an option without a terminator but becomes positional once `--` is inserted

```text
name=--version
name=report.txt
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
