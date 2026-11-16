# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`file-upload-and-webshell-filename-and-path-abuse`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `file-upload-and-webshell-filename-and-path-abuse`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Filename traversal placement

**Expected differential:** a traversal name lands the file above the upload directory versus a server that stores it under a canonical path

```text
filename=..%2f..%2fmarker-7f3a.txt as a benign marker, read back from the escaped path
filename=marker-7f3a.txt as the baseline, confirm the intended path
```

### Overwrite collision

**Expected differential:** a chosen name replaces a non-owned marker versus an exclusive-create store that refuses the write

```text
upload with the name of a pre-placed benign target file and re-read it
upload the same name twice to see whether the second write is refused
```

### Predictable-path retrieval

**Expected differential:** the stored file is retrievable from a path derived from the name or a counter, versus an unguessable random name

```text
derive the next sequential storage path and request it directly
request the server-generated name to confirm it is non-sequential
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
