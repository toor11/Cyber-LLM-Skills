# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cross-site-scripting-stored`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cross-site-scripting-stored`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Stored tracer placement

**Expected differential:** the inert tracer appears on one or more read paths and its surrounding bytes reveal the render context, versus not appearing because the field is not rendered

```text
comment=zz9s2trace (store, then enumerate which pages show it)
display_name=zz9s2trace<u>probe</u> (does an inert tag render bold on any view?)
```

### Read-path attribute boundary

**Expected differential:** a stored quote closes the attribute on the viewing page and a benign data-attribute appears, versus the control staying inside the value

```text
profile_title=zz9s2" data-rp=zz9s2 z="  (quote-break tested on the render path)
filename=zz9s2'oncheck=zz9s2'  (single-quote attribute break on a listing view)
```

### Read-path script boundary

**Expected differential:** a stored closing tag terminates an inline script block on the viewer page versus remaining a string

```text
bio=zz9s2</script><u>rp</u> (inline-script termination on the profile view)
note=zz9s2\';rp//  (backslash-quote against a JS string on the read path)
```

### Persistence-integrity check

**Expected differential:** the stored bytes return identical with delimiters intact, proving storage is not the control and the read path must encode

```text
comment=zz9s2&raw=<b>keepme</b> (confirm storage preserves markup verbatim)
tag=zz9s2%0d%0akeep (confirm CR and LF survive storage for later render)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
