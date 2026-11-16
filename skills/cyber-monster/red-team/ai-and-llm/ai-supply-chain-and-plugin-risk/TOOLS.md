# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ai-supply-chain-and-plugin-risk`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** per-user delegated credentials, pinned manifest hashes, and an egress allowlist for plugin endpoints.
- **Validation Gate:** one plugin call showing the credential's scopes and one manifest hash comparison.
- Review plugin updates as new components; an approval of a previous manifest does not cover a changed description.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import yaml; print(yaml.safe_load(open('plugins.yaml'))['plugins'])"` | Read the plugin inventory and credentials | Cross-platform |
| `curl` | `curl -sS -o manifest.json https://plugins.example/crm/manifest.json` | Save the manifest served now, then hash that file with sha256sum | Cross-platform |
| `jq` | `jq '.scopes' user-scopes.json` | Read the requesting user's scopes for comparison | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib
import subprocess
import yaml

p = yaml.safe_load(open("plugins.yaml", encoding="utf-8"))["plugins"][0]
served = subprocess.run(["curl", "-sS", p["endpoint"] + "/manifest.json"],
                        capture_output=True).stdout
actual = hashlib.sha256(served).hexdigest()
print("pinned", p.get("manifest_sha256"))
print("served", actual)
print("match" if actual == p.get("manifest_sha256") else "CHANGED")
```
