# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`os-command-injection-argument-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Semgrep` | `semgrep -e 'subprocess.run([..., $X, ...])' --lang python .` | Locate argument vectors built from request values without an end-of-options terminator | Cross-platform |
| `strace` | `strace -f -e trace=execve -s 200 -p <worker-pid>` | Capture the exact argv the child process receives to see whether user input lands in an option slot | Linux |
| `python` | `python argopt_check.py -o/tmp/x https://host/ok` | Flag which candidate values are option-shaped and whether a terminator is present | Cross-platform |

## Minimal Script Shape

An option-shape analyser: for each candidate value it reports whether the value would be parsed as a CLI option and whether the constructed argv includes an end-of-options terminator.

```python
import sys

def is_option_like(value):
    return value.startswith("-") or value.startswith("--")

def guarded(argv):
    # A '--' terminator means later values are positional even if they start with '-'
    return "--" in argv

for value in sys.argv[1:]:
    argv = ["curl", "-s", value]
    print({"value": value, "option_like": is_option_like(value),
           "terminator_present": guarded(argv),
           "argument_injection_possible": is_option_like(value) and not guarded(argv)})
```
