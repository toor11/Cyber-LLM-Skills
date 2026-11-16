# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`file-upload-and-webshell-polyglot-and-archive`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `file-upload-and-webshell-polyglot-and-archive`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Archive member path containment

**Expected differential:** a benign member with a traversal or absolute path lands outside the extraction root, versus a sandbox that confines it

```text
zip containing a member named ../extracted-marker-9c2.txt
zip containing a member with an absolute path to a writable marker location
```

### Symlink extraction

**Expected differential:** a symlink member resolves to a readable marker outside the root, versus an extractor that refuses symlinks

```text
archive with a symlink member pointing at a benign readable marker
plain-file archive baseline to confirm normal extraction placement
```

### Dual-format and active content

**Expected differential:** the second-format or embedded-script view surfaces a benign token where the validator never looked

```text
image valid as PNG that also parses with a benign trailing marker segment
SVG accepted as an image carrying a benign inert marker element
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
