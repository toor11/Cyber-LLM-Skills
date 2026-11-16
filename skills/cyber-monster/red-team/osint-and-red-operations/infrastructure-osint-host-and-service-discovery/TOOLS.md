# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`infrastructure-osint-host-and-service-discovery`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** internet-wide scan dataset query API with an explicit `fields` list and a `minify=false` when large fields are needed.
- **Validation Gate:** one current observation confirming a dataset record before the service enters the inventory.
- Dataset APIs changed field behaviour in 2026: large banner fields are omitted by default and removed fields are listed in the record metadata, so read that metadata before assuming a field is absent.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `shodan` | `shodan host 203.0.113.10` | Single-host record with banner and timestamps | Cross-platform |
| `curl` | `curl -sS 'https://api.example/shodan/host/search?key=KEY&query=net:198.51.100.0/24&fields=ip_str,port,product'` | Prefix-scoped search with an explicit field list | Cross-platform |
| `openssl s_client` | `openssl s_client -connect 203.0.113.10:443 -servername target.example </dev/null` | Current confirmation of a service the dataset recorded | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

records = json.load(open("out.json", encoding="utf-8"))["matches"]
fresh = [r for r in records if r.get("timestamp", "") > "2026-08-01"]
print(len(records), "records", len(fresh), "fresh")
for r in fresh[:10]:
    print(r.get("ip_str"), r.get("port"), r.get("product"), r.get("version"), r.get("timestamp"))
```
