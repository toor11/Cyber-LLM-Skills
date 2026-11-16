# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ldap-and-xpath-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ldap-and-xpath-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### LDAP filter boolean differential

**Expected differential:** a benign username matches one entry while a username carrying a breakout sequence widens or short-circuits the filter, proving the input is concatenated as structure

```text
username=jsmith (control)
username=*)(uid=*))(|(uid=*
```

### LDAP metacharacter neutralization probe

**Expected differential:** a username with a literal parenthesis returns a benign no-match when escaped versus a filter error or wildcard when not

```text
username=a)b (literal parenthesis)
username=plain-account (control)
```

### XPath boolean differential

**Expected differential:** a password field with an always-true clause matches a node regardless of the value, versus a benign value that matches only the correct node

```text
password=' or '1'='1 (XPath always-true)
password=correct-value (control)
```

### XPath string-function probe

**Expected differential:** an expression using string-length over the root node name confirms expression context without extracting data

```text
q=' or string-length(name(/*[1]))>0 or '
q=plainsearch (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
