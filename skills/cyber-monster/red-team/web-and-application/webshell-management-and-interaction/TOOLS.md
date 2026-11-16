# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`webshell-management-and-interaction`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS https://target.example/uploads/wshell-probe.php` | Request the uploaded marker and compare computed output against the served-bytes baseline | Cross-platform |
| `nginx -T` | `nginx -T > nginx-effective.conf` | Dump the effective config, then read the uploads location block to see whether it maps an interpreter | Linux |
| `grep` | `grep -R -e AddHandler -e SetHandler -e fastcgi_pass /etc/nginx /etc/apache2` | Find handler mappings that would execute files in an upload directory | Linux, macOS |

## Minimal Script Shape

An execution-context verdict harness: it fetches the served-bytes marker and the interpreter marker, then reports execution only when the computed output appears and the raw source does not.

```python
import urllib.request

BASE = "https://target.example/uploads"
EXPECT = "WSHELL-EXEC-42"      # 6*7 if the interpreter ran
SOURCE = "<?php echo"         # a fragment of the raw source


def body(name):
    req = urllib.request.Request(BASE + "/" + name,
                                headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")


try:
    out = body("wshell-probe.php")
except Exception as exc:  # noqa: BLE001
    out = ""
    print({"error": str(exc)})
executed = EXPECT in out and SOURCE not in out
print({"executed": executed, "inert": SOURCE in out,
       "verdict": "execution context present" if executed else "served inert"})
```
