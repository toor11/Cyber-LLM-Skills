# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`csv-formula-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `csv-formula-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Export differential (control vs trigger)

**Expected differential:** the probe cell's first byte is a trigger in the exported file while the control cell begins with a letter

```text
note=zzcsv_control_text  (benign control: exported cell starts with a letter)
note==1+1  (probe: does the exported cell keep a leading equals?)
```

### Alternate trigger characters

**Expected differential:** non-equals triggers survive at the cell start, proving the neutralisation misses them

```text
note=+zzcsv  (leading plus trigger)
note=@zzcsv  (leading at-sign trigger)
```

### Whitespace-prefixed trigger

**Expected differential:** a leading tab or carriage return before the operator still exports as the first cell bytes

```text
note=%09=zzcsv  (tab then equals, URL-encoded)
note=%0d=zzcsv  (carriage return then equals)
```

### Egress-formula shape (inert, placeholder host)

**Expected differential:** an export cell preserves a HYPERLINK prefix pointed at a placeholder, versus neutralisation stripping the trigger

```text
note==HYPERLINK("https://<assessor-controlled-host>/x","zzcsv")  (link cell; structural shape only)
note="=2+3"  (quoted formula: confirm quoting alone does not neutralise on open)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
