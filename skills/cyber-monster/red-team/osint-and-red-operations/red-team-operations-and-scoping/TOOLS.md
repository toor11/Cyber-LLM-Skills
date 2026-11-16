# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`red-team-operations-and-scoping`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a versioned YAML scope document with enumerated ranges, hostnames, exclusions, window, technique allowlist, deconfliction, and stop procedure.
- **Validation Gate:** a machine scope check run before every action, logged with the scope entry that authorised it.
- Keep the signed authorisation and the scope YAML under version control so a later change is visible in the record.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import yaml; print(sorted(yaml.safe_load(open('scope.yaml'))['in_scope']['hostnames']))"` | Read the enumerated in-scope list | Cross-platform |
| `dig` | `dig +short portal.client.example` | Confirm a hostname resolves inside the in-scope ranges | Cross-platform |
| `sqlite3` | `sqlite3 actions.db "SELECT COUNT(*) FROM action WHERE scope_entry IS NULL;"` | Find actions with no authorising scope entry | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import ipaddress
import yaml

scope = yaml.safe_load(open("scope.yaml", encoding="utf-8"))
allowed = [ipaddress.ip_network(r) for r in scope["in_scope"]["ranges"]]
blocked = [ipaddress.ip_network(r) for r in scope.get("excluded", {}).get("ranges", [])]

def permitted(target: str) -> bool:
    net = ipaddress.ip_network(target, strict=False)
    if any(net.subnet_of(b) for b in blocked):
        return False
    return any(net.subnet_of(a) for a in allowed)

print(permitted("198.51.100.5/32"), permitted("198.51.100.10/32"))
```
