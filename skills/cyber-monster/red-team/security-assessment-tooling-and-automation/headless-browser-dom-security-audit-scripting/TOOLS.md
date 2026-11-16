# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`headless-browser-dom-security-audit-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Playwright 1.4x+ (`chromium.launch`, `new_context`, `add_init_script`, `page.on`), Chromium bundled engine.
- **Validation Gate:** `python -m playwright install --with-deps chromium` then one navigation with the violation listener attached.
- `add_init_script` runs before page scripts, which is the only reliable point to register the violation listener.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `playwright` | `python -m playwright install chromium` | Installs the engine build the script drives | Cross-platform |
| `playwright codegen` | `python -m playwright codegen https://target.example/` | Record a stable interaction sequence before scripted probing | Cross-platform |
| `chromium headless` | `chromium --headless=new --dump-dom https://target.example/` | One-shot rendered DOM without a script, useful as a control | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    page = browser.new_context().new_page()
    events = []
    page.expose_function("report", lambda e: events.append(e))
    page.add_init_script("document.addEventListener('securitypolicyviolation', e => report({d: e.violatedDirective, u: e.blockedURI}));")
    page.goto("https://target.example/", wait_until="domcontentloaded")
    print(len(events), events[:2])
    browser.close()
```
