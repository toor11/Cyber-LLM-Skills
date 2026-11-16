# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`prototype-pollution-client-side-gadgets`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ppmap` | `ppmap -u 'https://target.example/app#__proto__[cg_canary]=polluted'` | Scan the page for client-side pollution sources and candidate gadgets | Cross-platform |
| `Burp DOM Invader` | `Enable DOM Invader prototype-pollution scan in the embedded browser` | Discover gadget chains from a polluted property to a DOM sink | Cross-platform |
| `Playwright` | `npx playwright open 'https://target.example/app#__proto__[cg_canary]=polluted'` | Load the page with the pollution fragment in a real browser to confirm the gadget | Cross-platform |

## Minimal Script Shape

A browser canary harness using Playwright: it loads the page with a pollution fragment and evaluates whether a fresh object inherits the canary, reporting client-side prototype pollution without executing a payload.

```python
from playwright.sync_api import sync_playwright

TARGET = "https://target.example/app"
POLLUTE = "#__proto__[cg_canary]=polluted"

def check():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(TARGET + POLLUTE)
        leaked = page.evaluate("() => ({}).cg_canary === 'polluted'")
        browser.close()
        return leaked

if __name__ == "__main__":
    polluted = check()
    print({"client_prototype_polluted": polluted,
           "verdict": "gadget-reachable" if polluted else "no-pollution"})
```
