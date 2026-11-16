# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`mfa-and-otp-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ffuf` | `ffuf -w codes.txt -X POST -d 'code=FUZZ' -u https://target.example/mfa/verify -mc all -ac` | Measure whether the verification endpoint rate-limits or locks out across a controlled attempt sequence on a tester account | Cross-platform |
| `curl` | `curl -sS -i -X POST 'https://target.example/mfa/verify' -b 'pending=<tester-session>' --data 'code=123456'` | Capture the exact success response and Set-Cookie for the correct-code baseline | Cross-platform |
| `oathtool` | `oathtool --totp -b <tester-seed>` | Generate valid TOTP values for a tester-owned enrolment so reuse and window checks can be tested without guessing real secrets | Linux, macOS |
| `Burp Suite Intruder` | `Mark the code field as the payload position, use a short tester wordlist, and watch the status and lockout columns` | Run the bounded attempt sequence and visualise the missing 429 transition | Cross-platform |

## Minimal Script Shape

An attempt-ceiling harness: it submits a short sequence of wrong codes to a tester-owned pending session and reports whether any rate-limit or lockout response ever appears.

```python
import urllib.parse
import urllib.request

ENDPOINT = "https://target.example/mfa/verify"
PENDING = "pending=<tester-session>"

def submit(code):
    data = urllib.parse.urlencode({"code": code}).encode()
    req = urllib.request.Request(ENDPOINT, data=data, method="POST")
    req.add_header("Cookie", PENDING)
    req.add_header("User-Agent", "authorised-assessment")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

statuses = [submit("%06d" % n) for n in range(1, 11)]
limited = any(s == 429 for s in statuses)
print({"statuses": statuses, "rate_limited": limited,
       "unbounded_attempts_suspected": not limited})
```
