# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`os-command-injection-shell-metacharacter-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python filter_probe.py` | Report which known bypass tokens survive a candidate blocklist unchanged | Cross-platform |
| `Burp Suite Intruder` | `Load an IFS, quoting, glob, and brace wordlist into the injected parameter` | Sweep survivable constructs to find which the filter fails to neutralise | Cross-platform |
| `Semgrep` | `semgrep -e 'subprocess.run($CMD, shell=True)' --lang python .` | Find shell sinks guarded only by character replacement rather than an argument vector | Cross-platform |

## Minimal Script Shape

A blocklist survival checker: it applies a candidate character blocklist to a set of known bypass tokens and reports which tokens pass through unchanged and would still be tokenised by a shell.

```python
BLOCKED = [";", "|", "&", " ", "`"]
BYPASS_TOKENS = ["${IFS}", "$IFS$9", "{a,b}", "''"]

def filtered(value):
    for ch in BLOCKED:
        value = value.replace(ch, "")
    return value

def survives(token):
    cleaned = filtered(token)
    return token, cleaned, cleaned == token

for tok in BYPASS_TOKENS:
    original, cleaned, intact = survives(tok)
    print({"token": original, "after_filter": cleaned, "survives_blocklist": intact})
```
