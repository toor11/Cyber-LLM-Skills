# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jndi-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `interactsh-client` | `interactsh-client -v` | Capture outbound LDAP, RMI, or DNS lookups that prove the lookup destination is attacker-controlled | Cross-platform |
| `Burp Collaborator` | `Insert a Collaborator host as the name or provider value, then poll the Collaborator tab` | Observe the server-issued lookup callback inside an intercepting proxy | Cross-platform |
| `Semgrep` | `semgrep --config p/java -e 'new InitialContext(...).lookup(...)' .` | Find JNDI lookups whose name or PROVIDER_URL is tainted by request input | Cross-platform |
| `ripgrep` | `rg -n -e InitialContext -e PROVIDER_URL -e "ctx.lookup" .` | Locate naming-lookup sinks and provider-URL assignments in the codebase | Cross-platform |

## Minimal Script Shape

A scheme classifier that checks a JNDI name against a safe-protocol allowlist and flags ldap, rmi, dns, and iiop as dangerous lookup destinations.

```python
import sys
from urllib.parse import urlsplit

ALLOWED = {"jms", "java", ""}
DANGEROUS = {"ldap", "ldaps", "rmi", "dns", "iiop"}

def classify(name: str) -> str:
    scheme = urlsplit(name).scheme.lower()
    if scheme in DANGEROUS:
        return "DANGEROUS lookup scheme: " + scheme
    if scheme not in ALLOWED:
        return "unexpected scheme: " + scheme
    return "within allowlist"

for name in sys.argv[1:]:
    print(name, "->", classify(name))
```
