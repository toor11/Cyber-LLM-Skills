# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http-host-header-attacks`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -D - -o /dev/null 'https://target.example/reset' -H 'X-Forwarded-Host: assessor.invalid'` | Capture whether the forwarded host appears in the response link or Location | Cross-platform |
| `Burp Suite Repeater` | `Resend a reset or verification request editing Host and X-Forwarded-Host` | Observe which header the link builder trusts | Cross-platform |
| `httpx` | `httpx -u https://target.example -H 'X-Forwarded-Host: assessor.invalid' -location -status-code` | Check redirect and header reflection of a forwarded host at scale | Linux, macOS, Windows |

## Minimal Script Shape

A host-reflection harness: it sends a request with an assessor host in Host and X-Forwarded-Host and reports whether that host is echoed into the Location header or body.

```python
import sys, urllib.error, urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://target.example/reset"
PROBE_HOST = "assessor-probe.invalid"

req = urllib.request.Request(TARGET, headers={
    "Host": PROBE_HOST, "X-Forwarded-Host": PROBE_HOST,
    "User-Agent": "authorised-assessment"})
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        location = r.headers.get("Location", "")
        body = r.read().decode("utf-8", "replace")
        status = r.status
except urllib.error.HTTPError as exc:
    location = exc.headers.get("Location", "")
    body = ""
    status = exc.code
print({"status": status, "host_in_location": PROBE_HOST in location,
       "host_in_body": PROBE_HOST in body,
       "host_reflected": PROBE_HOST in location or PROBE_HOST in body})
```
