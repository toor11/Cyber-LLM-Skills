# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`authentication-bypass-default-and-weak-credentials`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Nuclei` | `nuclei -tags default-login -u https://target.example` | Check documented vendor default credentials with a managed, non-destructive template set | Cross-platform |
| `curl` | `curl -si -d 'username=admin&password=admin' https://target.example/login` | Make a single documented-default attempt and capture status and Set-Cookie headers | Cross-platform |
| `EyeWitness` | `eyewitness --web -f urls.txt` | Screenshot panels and flag those likely to carry default-credential logins | Linux |

## Minimal Script Shape

A single-attempt differential: it submits the documented default and a random control pair once each, then reports whether only the default is accepted.

```python
import urllib.error
import urllib.parse
import urllib.request

LOGIN = "https://target.example/login"

def attempt(username, password):
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(LOGIN, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.getheader("Set-Cookie") is not None
    except urllib.error.HTTPError as exc:
        return exc.code, False

default_status, default_cookie = attempt("admin", "admin")
control_status, control_cookie = attempt("admin", "zzNotTheDefault!123")
print({"default_pair": (default_status, default_cookie),
       "control_pair": (control_status, control_cookie),
       "default_accepted": default_cookie and not control_cookie})
```
