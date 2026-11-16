# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`side-channel-and-fault-injection`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `chipwhisperer` | `cw.capture_trace()` in a lab flowgraph | Power trace capture for separation analysis | ChipWhisperer |
| `picoscope` | vendor capture software | Oscilloscope capture through a shunt resistor | PicoScope |
| `rg` | `rg -n -e 'memcmp' -e 'check_pin'` | The single-branch checks, which are the fault targets | any |
| `objdump` | `objdump -d firmware.elf` | The compiled branch, which is what a glitch skips | binutils |

## Minimal script shape

```python
# Structural classifier: which checks are single-branch and which keys leave the core.
import pathlib
import re

SINGLE_BRANCH = re.compile(r"if\s*\(\s*(memcmp|strcmp)\(")
REDUNDANT = re.compile(r"ct_compare.*\n.*ct_compare_alt", re.S)
KEY_IN_CORE = re.compile(r"\b(aes_key|key)\s*\[")
KEY_IN_SE = re.compile(r"se_\w+\(|psa_\w+\(")

def classify(root: str) -> dict:
    out = {"single_branch": [], "redundant": [], "key_in_core": [], "key_in_se": []}
    for p in pathlib.Path(root).rglob("*.c"):
        t = p.read_text(errors="ignore")
        for name, pat in (("single_branch", SINGLE_BRANCH), ("redundant", REDUNDANT),
                          ("key_in_core", KEY_IN_CORE), ("key_in_se", KEY_IN_SE)):
            if pat.search(t):
                out[name].append(str(p))
    return out

if __name__ == "__main__":
    print(classify("firmware-src"))
```

`single_branch` with no `redundant` in the same file is the fault finding; `key_in_core` with no `key_in_se` is the side-channel finding.
