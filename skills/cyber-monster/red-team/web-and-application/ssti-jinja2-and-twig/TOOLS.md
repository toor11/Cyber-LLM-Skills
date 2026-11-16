# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssti-jinja2-and-twig`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tplmap` | `tplmap -u 'https://target.example/greet?name=*' --level 1` | Mark the injection point with `*` and let the engine-detection heuristics distinguish Jinja2 from Twig without firing exploit stages | Linux, macOS, Windows |
| `curl` | `curl -sS -G 'https://target.example/greet' --data-urlencode 'name={{7*7}}'` | Send the evaluation probe URL-encoded so the delimiters survive to the server and the rendered product is captured | Cross-platform |
| `Burp Suite Repeater` | `Send the greet request to Repeater, toggle name between `{{7*7}}` and `7*7`` | Hold the request constant while flipping only the probe so the rendered-value differential is attributable to one variable | Cross-platform |
| `Semgrep` | `semgrep -e 'render_template_string(...)' --lang python .` | Find source-level concatenation into the template compiler before any runtime probe | Cross-platform |

## Minimal Script Shape

Sends the arithmetic literal and the delimited expression to the same parameter and reports template compilation only when the delimited form renders the product and the literal does not.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/greet"

def render(value):
    url = BASE + "?" + urllib.parse.urlencode({"name": value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8", "replace")

literal = render("7*7")
probe = render("{{7*7}}")
compiled = "49" in probe and "49" not in literal
print({"literal_has_49": "49" in literal,
       "probe_has_49": "49" in probe,
       "template_compiled": compiled})
```
