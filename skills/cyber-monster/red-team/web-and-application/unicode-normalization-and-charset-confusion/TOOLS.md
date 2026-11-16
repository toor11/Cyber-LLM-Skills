# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`unicode-normalization-and-charset-confusion`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import unicodedata,sys; s=sys.argv[1]; print(repr(s), repr(unicodedata.normalize('NFKC', s)))" "$ACTION"` | Show the raw versus NFKC-normalized form to confirm a folding gap | Linux, macOS, Windows |
| `curl` | `curl -sS -G 'https://target.example/action' --data-urlencode 'action=<compatibility-variant>'` | Submit the compatibility variant and observe whether validation accepts it | Cross-platform |
| `Burp Suite Repeater` | `Insert the code point via the Unicode payload and compare accepted-versus-executed value` | Hold the request constant while swapping ASCII for a compatibility variant | Cross-platform |
| `Semgrep` | `semgrep -e 'unicodedata.normalize(...)' --lang python .` | Find normalization calls and check whether validation precedes or follows them | Cross-platform |

## Minimal Script Shape

Models a permissive raw-form validator and an NFKC sink and reports a normalization gap when the probe passes validation yet folds to a sensitive canonical value at the sink.

```python
import re
import unicodedata

SENSITIVE = {"transfer", "admin"}
VALIDATOR = re.compile(r"^[\w.-]+$", re.UNICODE)

def accepted(value):
    # Permissive validator: Unicode word characters allowed, denylist on raw form
    return bool(VALIDATOR.match(value)) and value not in SENSITIVE

def canonical(value):
    return unicodedata.normalize("NFKC", value)

probe = "tr\uFF41nsfer"  # 'tr' + fullwidth a + 'nsfer' folds to transfer
raw_pass = accepted(probe)
sink = canonical(probe)
print({"raw_accepted": raw_pass, "sink_value": sink,
       "normalization_gap": raw_pass and sink != probe and sink in SENSITIVE})
```
