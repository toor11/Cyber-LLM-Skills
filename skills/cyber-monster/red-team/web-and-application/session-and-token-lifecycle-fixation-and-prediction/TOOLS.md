# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`session-and-token-lifecycle-fixation-and-prediction`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i 'https://target.example/login?sid=assessor-fixed-value' -d 'user=a&pass=b'` | Plant an identifier via the URL and read whether it persists after authentication | Cross-platform |
| `Burp Sequencer` | `Capture a token-bearing response and run Sequencer on the session cookie` | Statistically estimate identifier entropy to confirm or refute predictability | Cross-platform |
| `curl loop` | `for i in $(seq 1 20); do curl -sS -D - -o /dev/null https://target.example/start; done` | Collect issued response headers, including Set-Cookie, to inspect identifiers for sequence or timestamp structure | Linux, macOS |
| `ent` | `ent sampled_ids.bin` | Measure byte-level entropy of decoded identifiers as a predictability sanity check | Linux |

## Minimal Script Shape

A fixation harness: it plants an identifier via the URL and cookie, authenticates, and reports whether the planted value survives into the post-login Set-Cookie.

```python
import urllib.request

LOGIN = "https://target.example/login"


def login_with(planted):
    data = b"user=test&pass=test"
    req = urllib.request.Request(LOGIN + "?sid=" + planted, data=data,
                                 headers={"Cookie": "session=" + planted})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.headers.get("Set-Cookie", "")


if __name__ == "__main__":
    planted = "assessor-fixed-value"
    issued = login_with(planted)
    fixated = planted in issued or issued == ""
    print({"planted": planted, "post_login_set_cookie": issued,
           "fixation_suspected": fixated})
```
