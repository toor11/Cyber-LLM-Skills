# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`xml-attacks-xxe-and-xslt`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `xml-attacks-xxe-and-xslt`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### XPath predicate differential

**Expected differential:** a true predicate returns the normal node set while a false one returns none, with identical request shape, proving input alters structure

```text
name=xmlatk-user' and '1'='1
name=xmlatk-user' and '1'='2
```

### XSLT capability read (benign)

**Expected differential:** a system-property read returns engine metadata in the output, proving the stylesheet reached a capability function

```text
<xsl:value-of select="system-property('xsl:vendor')"/>
<xsl:value-of select="system-property('xsl:version')"/>
```

### Bounded entity-expansion timing

**Expected differential:** a small, bounded nested-entity document raises parse time against the benign baseline without exhausting the host

```text
xmlatk small bounded nested-entity doc: five levels, measure parse time vs baseline
```

### XInclude resolution probe

**Expected differential:** an xi:include pointing at a benign local marker file appears in the tree, proving inclusion is honoured

```text
<xi:include href="file:///tmp/xmlatk-marker.txt" parse="text"/>
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
