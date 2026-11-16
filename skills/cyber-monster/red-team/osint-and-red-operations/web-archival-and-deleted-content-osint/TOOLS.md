# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-archival-and-deleted-content-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** CDX and Memento interfaces for archive captures, Common Crawl indexes for independent crawls; record `timestamp` and `digest` per capture.
- **Validation Gate:** a CDX query returning at least one capture with a timestamp and digest before any historical claim.
- Crawl indexes are released per crawl and the collection names change; list the collections before assuming an index name.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://web.archive.org/cdx/search/cdx?url=target.example&output=json'` | Capture list with timestamps, status and digest | Cross-platform |
| `jq` | `jq -r ".[].timestamp" cdx.json` | List capture timestamps for comparison | Linux, macOS |
| `curl` | `curl -sS 'https://index.commoncrawl.org/collinfo.json'` | List available crawl collections before querying | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

rows = json.load(open("cdx.json", encoding="utf-8"))
header, *captures = rows
for cap in captures:
    rec = dict(zip(header, cap))
    print(rec.get("timestamp"), rec.get("statuscode"), rec.get("digest", "")[:12], rec.get("original"))
```
