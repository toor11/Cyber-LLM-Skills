# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssti-node-and-client-engines`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssti-node-and-client-engines`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Server-side evaluation (EJS and Pug)

**Expected differential:** the EJS or Pug arithmetic form returns its product in the HTTP response while the literal does not; binding the value as a local removes the difference

```text
title=<%= 7*7 %>
title=#{7*7}
title=<%- 7*7 %>
```

### Handlebars raw-output probe

**Expected differential:** the triple-stache renders unescaped markup while the double-stache escapes it, isolating the raw-output field

```text
title={{{marker_raw}}}
title={{marker_raw}}
```

### Client-side interpolation (Angular and Vue)

**Expected differential:** the expression evaluates in the rendered DOM but is absent from the raw response, marking client-side template injection

```text
q={{7*7}}
q={{$on.constructor}}
q=[[7*7]]
```

### Pug interpolation modes

**Expected differential:** escaped `#{}` versus unescaped `!{}` interpolation diverge on markup handling, confirming which mode the sink uses

```text
name=!{marker_pug}
name=#{marker_pug}
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
