# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssti-node-and-client-engines`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -G 'https://target.example/card' --data-urlencode 'title=<%= 7*7 %>'` | Send the EJS evaluation probe so the server-side product or its absence is visible in the raw response | Cross-platform |
| `Playwright` | `npx playwright open 'https://target.example/search?q={{7*7}}'` | Render the page in a real browser to see whether an Angular or Vue interpolation evaluates in the DOM versus the raw HTML | Cross-platform |
| `node` | `node -e "console.log(require('ejs').render(process.argv[1],{}))" '<%= 7*7 %>'` | Confirm locally how the suspected engine treats the delimiter before attributing behavior to the target | Linux, macOS, Windows |
| `Semgrep` | `semgrep -e '$E.render(...)' --lang javascript .` | Locate render calls whose template argument is assembled from request data | Cross-platform |

## Minimal Script Shape

Sends the EJS evaluation probe and its literal control to the same parameter and reports server-side compilation only when the probe renders the product and the literal does not.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/card"

def send(value):
    url = BASE + "?" + urllib.parse.urlencode({"title": value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8", "replace")

literal = send("7*7")
probe = send("<%= 7*7 %>")
server_eval = "49" in probe and "49" not in literal
print({"literal_has_49": "49" in literal,
       "probe_has_49": "49" in probe,
       "server_side_evaluation": server_eval})
```
