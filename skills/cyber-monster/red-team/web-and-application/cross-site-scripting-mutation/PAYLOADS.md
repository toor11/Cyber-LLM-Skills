# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cross-site-scripting-mutation`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cross-site-scripting-mutation`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Sanitizer fingerprint

**Expected differential:** the client bundle or runtime exposes a sanitizer version; a pre-fix version is in range versus a fixed version out of range

```text
DOMPurify.version  (read in console on the target page)
grep -ro 'VERSION[": ]*[0-9.]*' app.js  (locate the pinned sanitizer version)
```

### Foreign-content re-parse probe

**Expected differential:** after insertion the element serialises to a different tree than submitted, versus a plain-text control that serialises unchanged

```text
<svg><p zzm3x>probe</p></svg>  (namespace-boundary wrap, compare serialisation)
<math><mtext><table zzm3x>probe</table></mtext></math>  (math foreign-content nesting)
```

### Serialisation differential

**Expected differential:** the element innerHTML after insertion differs from the sanitised string, proving the browser rebuilt the tree

```text
el.innerHTML = DOMPurify.sanitize(input); el.innerHTML !== input  (compare blessed vs rebuilt)
new XMLSerializer().serializeToString(el)  (capture the actual post-insert tree)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
