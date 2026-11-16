# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`move-aptos-and-sui-smart-contract-audit`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Move bytecode verifier with the chain's CLI (`aptos move test`, `sui move test`), abilities as declared on each struct.
- **Validation Gate:** one test asserting an external module cannot construct the capability, and one asserting the token cannot be copied.
- Module publishing is immutable by default on Aptos; an upgrade policy that allows code change is a trust assumption to record.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `aptos` | `aptos move test` | Run Move unit tests including abort expectations | Linux, macOS |
| `sui` | `sui move test` | Run Sui Move tests | Linux, macOS |
| `aptos` | `aptos move publish --dry-run` | Check publishing and upgrade policy without deploying | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess

for cmd in (["aptos", "move", "test"], ["sui", "move", "test"]):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(cmd[0], "exit", res.returncode, res.stdout.splitlines()[-1:] or "")
    except (OSError, subprocess.SubprocessError) as exc:
        print(cmd[0], "unavailable", type(exc).__name__)
```
