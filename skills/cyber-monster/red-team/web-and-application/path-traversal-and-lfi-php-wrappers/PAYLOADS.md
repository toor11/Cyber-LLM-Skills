# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`path-traversal-and-lfi-php-wrappers`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `path-traversal-and-lfi-php-wrappers`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Filter source disclosure

**Expected differential:** the response is base64 of the named source only behind the filter prefix, and is the raw path behaviour otherwise

```text
doc=php://filter/read=convert.base64-encode/resource=config.php
doc=config.php
```

### Conversion-chain reachability

**Expected differential:** an iconv conversion changes the output bytes, confirming the filter chain composes without materializing a payload

```text
doc=php://filter/convert.iconv.utf-8.utf-16/resource=config.php
```

### Embedded-wrapper presence

**Expected differential:** an inert base64 data body is reflected, proving allow_url_include, while a non-wrapper path is not

```text
doc=data://text/plain;base64,aW5lcnQtbWFya2Vy
```

### Phar and zip detection

**Expected differential:** a file operation on the wrapper path produces a phar unserialize side effect or a zip entry read, routing to the deserialization or archive skill

```text
doc=phar://uploads/archive.phar/test.txt
doc=zip://uploads/test.zip%23entry.txt
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
