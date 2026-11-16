# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`os-command-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' "https://target.example/diag?ping=127.0.0.1"` | Capture the status, size, and timing triple that forms the baseline for the separator differential | Cross-platform |
| `Semgrep` | `semgrep --config p/command-injection --severity ERROR .` | Find shell-built command sinks and subprocess calls using shell=True before runtime testing | Cross-platform |
| `Burp Suite Repeater` | `Send the request to Repeater and alternate the benign and separator values on one connection` | Keep the paired baseline stable so output or timing changes are attributable | Cross-platform |

## Minimal Script Shape

A separator differential harness: it runs a wrapped command with a benign value and with a value carrying a shell separator and marker, and reports when only a shell interpretation explains the divergence.

```python
import subprocess
import sys

# Compares a benign argument against one carrying a shell separator and a unique marker,
# flagging divergence that only a shell would produce.
BENIGN = "127.0.0.1"
PROBE = "127.0.0.1; echo MARKER_$$"

def run(value):
    proc = subprocess.run(["./ping_wrapper.sh", value], capture_output=True, text=True, timeout=10)
    return proc.stdout

base = run(BENIGN)
probe = run(PROBE)
print({"baseline_len": len(base), "probe_len": len(probe),
       "marker_present": "MARKER_" in probe,
       "shell_interpreted": "MARKER_" in probe and base != probe})
```
