# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`email-header-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS https://target.example/contact --data-urlencode 'reply_to=zzmail@example.org%0d%0aX-Probe: zzmail'` | Submit the newline probe through the form endpoint | Cross-platform |
| `swaks` | `swaks --to team@example.com --header 'Reply-To: a%0d%0aX-Probe: b'` | Exercise the SMTP path directly to see which terminators the MTA honours | Linux, macOS, Windows |
| `Controlled mailbox viewer` | `Open the received message source (View Source)` | Reads whether the injected header actually arrived in the composed message | Cross-platform |
| `Python email parser` | `python -c "import email,sys;print(email.message_from_file(open(sys.argv[1])).items())" msg.eml` | Parse the received message and list headers to detect injected fields | Cross-platform |

## Minimal Script Shape

A composition checker: it builds a header block from a probe value, detects embedded CR/LF, and reports whether an extra header would be injected, without sending any mail.

```python
import re

def build_headers(reply_to, name):
    injected = bool(re.search(r"[\r\n]", reply_to) or re.search(r"[\r\n]", name))
    block = (
        "From: site@example.com\r\n"
        "Reply-To: " + reply_to + "\r\n"
        "Subject: Contact from " + name + "\r\n"
    )
    header_lines = [l for l in block.split("\r\n") if l]
    return injected, header_lines

probe = "zzmail@example.org\r\nX-Probe: zzmail"
injected, lines = build_headers(probe, "zzmail")
extra = [l for l in lines if l.lower().startswith("x-probe")]
print({"crlf_in_field": injected, "extra_headers": extra,
       "verdict": "INJECTABLE" if extra else "clean"})
```
