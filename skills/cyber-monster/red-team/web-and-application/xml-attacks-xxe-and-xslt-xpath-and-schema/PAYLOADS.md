# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`xml-attacks-xxe-and-xslt-xpath-and-schema`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `xml-attacks-xxe-and-xslt-xpath-and-schema`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Boolean predicate pair

**Expected differential:** the always-true predicate returns the baseline node set while the always-false predicate returns none, request shape unchanged

```text
username=xpsch-acct' or '1'='1
username=xpsch-acct' or '1'='2
```

### Authentication tautology

**Expected differential:** a login XPath returns a user node for the tautology that it does not return for a non-matching value, confirmed with two accounts

```text
username=xpsch-acct' or 1=1 or 'a'='b&password=x
username=xpsch-acct&password=xpsch-wrong
```

### Bounded entity-expansion timing

**Expected differential:** a document with a few bounded nesting levels raises parse time against the benign baseline without exhausting the host

```text
xpsch bounded nested-entity doc at depth 4, measure parse time against a flat document
```

### XInclude resolution probe

**Expected differential:** an xi:include to a benign local marker appears in the parsed tree, proving inclusion is enabled

```text
<xi:include href="file:///tmp/xpsch-marker.txt" parse="text" xmlns:xi="http://www.w3.org/2001/XInclude"/>
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
