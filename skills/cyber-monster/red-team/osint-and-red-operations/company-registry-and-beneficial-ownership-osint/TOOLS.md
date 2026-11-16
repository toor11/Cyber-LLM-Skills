# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`company-registry-and-beneficial-ownership-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** registry JSON or RDAP entity records, GLEIF LEI API (`/api/v1/lei-records`), and securities filing indexes.
- **Validation Gate:** one entity resolved by registration number and confirmed by LEI before any ownership statement.
- Registry APIs vary widely in rate limits and terms; record the interface and date so a later check is reproducible.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=Target'` | LEI resolution and status | Cross-platform |
| `jq` | `jq '.data[].attributes.entity.legalName' lei.json` | Read entity names from a LEI response | Linux, macOS |
| `curl` | `curl -sS https://rdap.example/entity/01234567` | Registry entity record with roles and handles | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

rec = json.load(open("lei.json", encoding="utf-8"))["data"]
for item in rec:
    a = item["attributes"]
    print(json.dumps({"lei": a["lei"], "name": a["entity"]["legalName"],
                      "status": a["registration"]["status"],
                      "next_renewal": a["registration"].get("nextRenewalDate")}))
```
