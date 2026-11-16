# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`async-http-and-dns-audit-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** httpx `AsyncClient` with explicit `Limits` and `timeout`; dnspython `dns.asyncresolver` with `configure=False`.
- **Validation Gate:** `python -c "import httpx, dns.resolver"` plus a dry run against a single in-scope host before the full set.
- Set `follow_redirects=False` by default: an off-scope redirect followed silently breaks the scope guarantee.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `httpx` | `python -c "import httpx; print(httpx.__version__)"` | Pin the client version whose Limits semantics you rely on | Cross-platform |
| `dnspython` | `python -c "import dns.version; print(dns.version.version)"` | Confirm resolver API before writing async code | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' -I https://target.example/` | One-off control request for a baseline pair | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import asyncio, json, httpx

async def one(url, client, sem):
    async with sem:
        r = await client.get(url, follow_redirects=False)
        print(json.dumps({"url": url, "status": r.status_code, "len": len(r.content)}))

async def main():
    scope = [l.strip() for l in open("scope.txt") if l.strip()]
    sem = asyncio.Semaphore(4)
    async with httpx.AsyncClient(timeout=10.0) as client:
        await asyncio.gather(*(one(u, client, sem) for u in scope))

asyncio.run(main())
```
