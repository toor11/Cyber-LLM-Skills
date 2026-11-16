# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`mitmproxy-addon-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** mitmproxy 12.x; contentview API is `prettify(bytes, metadata) -> str` and `reencode(str, metadata) -> bytes`.
- **Validation Gate:** `mitmdump -s addon.py` starts without an import error and produces one log line per flow.
- `mitmproxy.dns.Message` is now `mitmproxy.dns.DNSMessage`; addons written against the old name fail at import.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mitmdump` | `mitmdump -s addon.py -p 8080` | Headless proxy with the addon loaded | Cross-platform |
| `mitmproxy` | `mitmproxy -s addon.py` | Interactive TUI for inspecting individual flows during triage | Cross-platform |
| `mitmweb` | `mitmweb -s addon.py` | Browser UI for reviewing a capture with a team | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib
import json
import logging

from mitmproxy import http

log = logging.getLogger("audit")


def response(flow: http.HTTPFlow) -> None:
    body = flow.response.content or b""
    log.info(json.dumps({"host": flow.request.pretty_host,
                         "status": flow.response.status_code,
                         "sha256": hashlib.sha256(body).hexdigest()}))

addons = []
```
