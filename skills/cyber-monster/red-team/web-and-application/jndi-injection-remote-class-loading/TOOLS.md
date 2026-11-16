# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jndi-injection-remote-class-loading`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `interactsh-client` | `interactsh-client -v` | Capture the RMI or LDAP callback and any follow-on HTTP fetch for a .class file | Cross-platform |
| `ripgrep` | `rg -n -e trustURLCodebase -e ObjectFactory -e BeanFactory .` | Locate codebase-trust flags and object-factory usage in the application | Cross-platform |
| `java` | `java -XshowSettings:properties -version > java-settings.txt` | Write effective JDK properties, then search java-settings.txt for trustURLCodebase | Windows, Linux, macOS |

## Minimal Script Shape

A decision helper that reports, for a given lookup scheme and trustURLCodebase setting, whether remote class loading is possible or only local factory gadgets remain.

```python
import sys

def assess(scheme: str, trust_codebase: bool) -> str:
    remote = scheme.lower() in {"ldap", "rmi"}
    if remote and trust_codebase:
        return "remote codebase load POSSIBLE"
    if remote:
        return "remote blocked; only local factory gadgets remain"
    return "non-remote provider"

schemes = sys.argv[1:] or ["ldap", "rmi", "jms"]
for scheme in schemes:
    for trust in (True, False):
        print(scheme, "trustURLCodebase=%s" % trust, "->", assess(scheme, trust))
```
