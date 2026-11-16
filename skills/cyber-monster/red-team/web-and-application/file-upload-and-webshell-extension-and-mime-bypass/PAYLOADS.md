# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`file-upload-and-webshell-extension-and-mime-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `file-upload-and-webshell-extension-and-mime-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Which signal drives acceptance

**Expected differential:** acceptance tracks the sniffed content versus the declared type or extension, revealing the trusted signal

```text
submit real PNG bytes with a doubled script-then-image extension
submit script text with image/png declared and a .png name
```

### Runtime execution mapping

**Expected differential:** the accepted file is evaluated when its final extension maps to a handler, versus served as bytes otherwise

```text
GET the stored file whose final extension is an alternate executable suffix
GET a control upload whose final extension is a plain image suffix
```

### Magic-byte prefix carry

**Expected differential:** a valid image header in front of benign marker text is accepted and then evaluated, versus stripped by re-encoding

```text
upload an image header followed by a one-line benign token emitter
re-fetch to compare stored bytes against evaluated output
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
