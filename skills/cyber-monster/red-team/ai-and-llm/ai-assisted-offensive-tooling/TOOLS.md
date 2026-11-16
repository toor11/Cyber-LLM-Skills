# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ai-assisted-offensive-tooling`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a prompt template that supplies the collected data explicitly, and an assist log recording prompt hash, output, verification, and reviewer.
- **Validation Gate:** every CVE or URL in the output checked against the primary source before it enters a deliverable.
- Do not paste client data into a model service that is not approved for that data classification.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import json; e=json.load(open('assist-log.json'))['entries']; print(len(e))"` | Count assist entries for the engagement record | Cross-platform |
| `jq` | `jq ".entries[].verified" assist-log.json` | Review which drafts were verified | Linux, macOS |
| `curl` | `curl -sS -o advisory.txt $ADVISORY_URL` | Save the advisory, then search advisory.txt for the affected-versions line the claim depends on | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

entries = json.load(open("assist-log.json", encoding="utf-8"))["entries"]
unverified = [e["task"] for e in entries if not e.get("verified")]
print("entries", len(entries), "unverified", unverified)
```
