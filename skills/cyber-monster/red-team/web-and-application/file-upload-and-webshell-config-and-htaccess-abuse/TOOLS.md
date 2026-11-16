# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`file-upload-and-webshell-config-and-htaccess-abuse`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -F 'file=@.htaccess' https://target.example/upload` | Test whether the upload validator accepts a directory-override configuration filename | Cross-platform |
| `apachectl` | `apachectl -t -D DUMP_INCLUDES` | Confirm from the server side which directories honour overrides during a configuration review | Linux, macOS |
| `Burp Suite Repeater` | `Upload the configuration file, then re-request the unchanged content file to capture before and after` | Isolate the single variable that caused evaluation | Cross-platform |

## Minimal Script Shape

An override-effect harness: it fetches a content file in the upload directory and reports whether it is served as static bytes or as a dynamic type, which indicates a planted configuration took effect.

```python
import sys, urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else "https://target.example/uploads/probe.img"
TOKEN = b"CONFIG_OVERRIDE_PROBE"

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(url=req, timeout=10) as r:
        return r.status, r.headers.get("Content-Type", ""), r.read()

status, ctype, body = fetch(URL)
served_verbatim = TOKEN in body
dynamic_type = "html" in ctype.lower() or "php" in ctype.lower()
print({"url": URL, "status": status, "content_type": ctype,
       "verbatim_token_present": served_verbatim,
       "dynamic_content_type": dynamic_type,
       "override_took_effect": dynamic_type and not served_verbatim})
```
