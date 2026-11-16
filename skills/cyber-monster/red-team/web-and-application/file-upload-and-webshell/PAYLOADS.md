# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`file-upload-and-webshell`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `file-upload-and-webshell`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Inert baseline versus evaluated marker

**Expected differential:** the inert sample is returned byte for byte while the benign marker returns evaluated output when fetched; identical otherwise

```text
upload sample.png as a valid image, then fetch and compare bytes
upload a marker file holding one benign echo of a fixed token, then GET its URL
```

### Storage reachability

**Expected differential:** the stored file is reachable under the web root versus a deployment that serves it from a non-executing path

```text
GET /uploads/<stored-name> to confirm the file is URL-reachable
compare the stored name with the submitted name to see server renaming
```

### Type-decision probe

**Expected differential:** a file whose sniffed content and declared type disagree is accepted or rejected, revealing which the validator trusts

```text
submit PNG-magic bytes with a script extension and image/png declared
submit the same bytes with the real extension to compare acceptance
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
