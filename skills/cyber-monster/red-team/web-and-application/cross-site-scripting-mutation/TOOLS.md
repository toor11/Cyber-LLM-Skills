# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cross-site-scripting-mutation`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `DOMPurify demo` | `DOMPurify.sanitize(input) then diff against el.innerHTML after insertion` | Shows the blessed string versus the rebuilt tree so mutation is visible | Cross-platform |
| `Browser DevTools console` | `DOMPurify.version; compare submitted string to node.outerHTML` | Reads the sanitizer version and captures the post-insertion serialisation | Cross-platform |
| `Playwright` | `npx playwright open https://target.example/profile` | Drives insertion in real Chromium and captures outerHTML for the differential | Cross-platform |
| `ripgrep` | `rg -o 'dompurify[^"']*[0-9.]+' dist/` | Fingerprints the bundled sanitizer version offline from the built assets | Windows, Linux, macOS |

## Minimal Script Shape

A Python harness that shells out to Node to run the sanitizer, re-parse its output through innerHTML, and report whether the blessed string and the rebuilt tree diverge.

```python
import json
import subprocess

INPUT_HTML = "<svg><p zzm3x>probe</p></svg>"

NODE = r"""
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const win = new JSDOM('').window;
const purify = DOMPurify(win);
const clean = purify.sanitize(process.argv[1]);
const el = win.document.createElement('div');
el.innerHTML = clean;                 // re-parse the blessed string
console.log(JSON.stringify({version: purify.version, clean,
                            rebuilt: el.innerHTML, mutated: clean !== el.innerHTML}));
"""

def main():
    out = subprocess.run(["node", "-e", NODE, INPUT_HTML],
                         capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        print({"error": out.stderr.strip()[:120]})
        return
    res = json.loads(out.stdout)
    print({"mutated": res["mutated"], "version": res["version"]})

main()
```
