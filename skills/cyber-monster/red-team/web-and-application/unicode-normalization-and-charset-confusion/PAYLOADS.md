# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`unicode-normalization-and-charset-confusion`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `unicode-normalization-and-charset-confusion`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Compatibility-fold gap (NFKC/NFKD)

**Expected differential:** the compatibility variant passes validation but canonicalizes to the ASCII form at the sink, while the ASCII form is handled identically by both

```text
action=\uFF54ransfer (fullwidth t then ransfer)
action=\u2044path (fraction slash variant)
```

### Case-folding collision

**Expected differential:** a character that lowercases to an ASCII letter passes a case-sensitive check but collides after folding

```text
user=admin\u212A (trailing Kelvin sign folds to k)
user=\u0131nvoice (dotless i)
```

### Best-fit and charset transcoding

**Expected differential:** a code point best-fit maps to an ASCII metacharacter only after the transcoding step at the sink

```text
name=\uFF07 (fullwidth apostrophe best-fits to a quote)
q=\uFF1C (fullwidth less-than best-fits to a bracket)
```

### Uniqueness collision probe

**Expected differential:** two canonically distinct identifiers resolve to one stored record after normalization

```text
ref=100
ref=\u2460\u2080\u2080 (circled and subscript digits normalizing toward 100)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
