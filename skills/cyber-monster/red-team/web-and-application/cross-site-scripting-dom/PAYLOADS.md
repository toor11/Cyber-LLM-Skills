# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cross-site-scripting-dom`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cross-site-scripting-dom`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Source-to-sink trace marker

**Expected differential:** a benign token set in the DOM source appears in the sink element as data, confirming the flow before any break

```text
#domProbe42 (set via location.hash and observe the sink element)
?view=domProbe42 (set via location.search for a search-sourced sink)
```

### Markup-sink break

**Expected differential:** the value parses as an element only when the sink is innerHTML-style rather than a text sink

```text
#<b id=domProbe42>flow</b> (benign element, inert if the sink is textContent)
```

### postMessage source probe

**Expected differential:** a crafted message is processed by a handler that omits an origin check, reaching the sink from another window

```text
postMessage payload: {"view":"domProbe42"} sent from an unauthorised origin
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
