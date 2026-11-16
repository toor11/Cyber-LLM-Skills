# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`zip-slip-and-archive-extraction-attacks`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `zip-slip-and-archive-extraction-attacks`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Name-escape entry (absolute or parent-relative)

**Expected differential:** the parent-relative or absolute entry places `<marker>` outside the extraction root, while the same archive with the entry renamed under a benign subfolder keeps it inside; a resolve-and-contain check keeps both contained

```text
entry name: ../<marker>.txt  (parent-relative escape, benign empty file)
entry name: ../../<assessor-controlled-dir>/<marker>.txt
entry name: /tmp/<marker>.txt  (absolute entry; on Windows use a C:\ drive or \\share prefix)
```

### Symlink-escape member plus follow-through write

**Expected differential:** a symlink member pointing to a sibling directory is created, then a later regular entry written through it lands at the link target; an extractor that refuses link members leaves `<marker>` inside the root

```text
entry 1: symlink member `linkdir` -> ../<assessor-controlled-dir>
entry 2: regular file `linkdir/<marker>.txt`  (benign, written through the created link)
```

### Validate-then-canonicalise ordering probe

**Expected differential:** a name that passes a raw-string check but normalises into an escaping path lands `<marker>` outside the root, proving the check ran before canonicalisation; moving the check after resolution contains it

```text
entry name: sub/../../<marker>.txt  (escapes only after normalisation)
entry name: ./well-formed/../../<marker>.txt
entry name: sub/%2e%2e/%2e%2e/<marker>.txt  (encoded dot-segments if a layer decodes before extract)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
