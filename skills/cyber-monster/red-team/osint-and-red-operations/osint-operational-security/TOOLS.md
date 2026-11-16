# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`osint-operational-security`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** an opsec YAML with persona register, egress register, and data-handling rules.
- **Validation Gate:** one source queried through the designated egress with the observed address recorded.
- Confirm the egress address before every collection block; a proxy change silently alters what the source sees.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -x http://egress.example:3128 https://ifconfig.example/` | Confirm the egress address a source will observe | Cross-platform |
| `python` | `python -c "import yaml; print(yaml.safe_load(open('opsec.yaml'))['egress'])"` | Read the egress register before collection | Cross-platform |
| `dig` | `dig +short TXT o-o.myaddr.l.google.com` | Independent check of the resolver-facing address | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import yaml

op = yaml.safe_load(open("opsec.yaml", encoding="utf-8"))
for e in op["egress"]:
    print(e["source"], e["observed_address"], e.get("note", ""))
open_personas = [p for p in op["personas"] if not p.get("retired_at")]
print("personas open", len(open_personas))
```
