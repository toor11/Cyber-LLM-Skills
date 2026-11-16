# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`xml-attacks-xxe-and-xslt-xslt-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `xml-attacks-xxe-and-xslt-xslt-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Engine fingerprint (benign)

**Expected differential:** a system-property read reflects the processor and version in the output, proving a capability function executed

```text
<xsl:value-of select="system-property('xsl:vendor')" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>
<xsl:value-of select="system-property('xsl:vendor-url')"/>
```

### document() local marker read (benign)

**Expected differential:** document() of a benign local marker file surfaces the marker in the result, proving file-read capability without touching sensitive data

```text
<xsl:value-of select="document('file:///tmp/xsltinj-marker.txt')"/>
```

### Extension-namespace availability

**Expected differential:** declaring an extension namespace and calling a trivial function succeeds or errors, revealing whether extensions are registered

```text
xsltinj declare EXSLT namespace and call a trivial node-set function
xsltinj declare a Java extension prefix and read a constant, observe allowed vs denied
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
