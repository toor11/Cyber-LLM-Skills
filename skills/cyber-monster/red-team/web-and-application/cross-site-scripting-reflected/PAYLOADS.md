# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cross-site-scripting-reflected`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cross-site-scripting-reflected`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Context-locating marker

**Expected differential:** the marker echoes verbatim and its surrounding characters reveal HTML-text, attribute, or script context, versus a benign control that gives the baseline position

```text
q=zz7q1probe (unique non-HTML marker, locate every reflection)
q=zz7q1<u>probe</u> (does an inert tag render as emphasis or as text?)
```

### Attribute-context boundary

**Expected differential:** adding a matching quote closes the attribute and a benign data-attribute appears in the DOM, versus the quoted control that stays inside the value

```text
name=zz7q1" data-probe=zz7q1 x="  (quote-close in a double-quoted attribute)
name=zz7q1' data-probe=zz7q1 x='  (quote-close in a single-quoted attribute)
```

### Script-string boundary

**Expected differential:** a backslash or closing tag changes how the inline script tokenises, versus the plain control that remains a string literal

```text
q=zz7q1</script><u>probe</u> (does the inline script terminate early?)
q=zz7q1\';probe//  (backslash and quote against a JS single-quoted string)
```

### Encoding-survival check

**Expected differential:** the raw bytes show angle brackets and quotes surviving unescaped versus returning as entities once encoding is applied

```text
q=%3Cu%3Ezz7q1%3C/u%3E (url-encoded angle brackets, check decode-then-reflect)
q=zz7q1&probe=&#60;u&#62; (numeric entity, check double-decoding)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
