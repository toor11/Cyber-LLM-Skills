---
name: async-http-and-dns-audit-scripting
description: "Engineers bounded asynchronous Python HTTP and DNS audit scripts with `httpx.AsyncClient` and `dnspython`: mandatory scope-allowlist enforcement, `asyncio.Semaphore` concurrency caps, exponential backoff, TLS verification controls, and streaming JSONL output. Use when writing safe custom web/DNS posture scanners."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["httpx async scanner", "python http audit script", "asyncio semaphore http", "dnspython script"]
cwe: [CWE-400]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Async Http and DNS Audit Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Concurrent, scope-bounded HTTP and DNS collection scripts. The engineering problem is not sending requests but bounding them: a global semaphore and per-host rate limiter keep concurrency inside what the rules of engagement allow, an explicit scope file decides which hostnames are legal, and structured JSONL output keeps every response attributable to the request that produced it.

- **Scope is enforced before DNS.** Resolve only names that appear in the scope file, and re-check after resolution so a wildcard CNAME cannot drag the script outside the authorised range.
- **Concurrency is a budget, not a speed knob.** One semaphore for in-flight requests and one token bucket per host, both recorded in the output metadata so the run is reproducible.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target set exceeds a few thousand names **THEN** stream names from disk and cap the in-flight window instead of materialising every task.
2. **IF** a host returns 429 or resets **THEN** back off that host only; dropping the global semaphore is what turns an authorised scan into an outage.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a scope file, a concurrency budget, and a per-host rate limit agreed in the engagement — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11+ with httpx (`AsyncClient(limits=..., timeout=...)`), dnspython (`dns.asyncresolver`), and a JSONL writer
- **Mandatory Self-Validation Command:** `python -c "import httpx, dns.resolver; print(httpx.__version__, dns.__version__)"`

1. Confirm the target surface: load the scope file, normalise names, drop duplicates, and record the count before any request leaves the host.
2. Choose the branch: HTTP probe (one GET/HEAD per URL), DNS probe (A/AAAA/CNAME/TXT per name), or TLS probe (handshake plus certificate), each with its own concurrency ceiling.
3. Define the differential: probe the same URL twice with identical headers and compare status, body length, and a stable hash; a difference between baseline and probe only counts when the second run is byte-stable in the baseline.
4. Name the stop condition: a total request budget and a per-host error ceiling; abort the host on repeated connection failures rather than retrying indefinitely.
5. Prove it: every output row carries the request URL, the resolved address, the timestamp, and a hash of the body, so a finding can be re-run from the log alone.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `httpx.AsyncClient(limits=Limits(max_connections=..., max_keepalive_connections=...))` | Caps in-flight sockets process-wide, which is the only reliable way to stay inside an agreed concurrency budget. |
| `asyncio.Semaphore per host` | Serialises requests to one origin without throttling unrelated hosts; per-host is where the engagement limit is usually written. |
| `dns.asyncresolver.Resolver(configure=False)` | Prevents the analyst machine's resolver from silently redirecting lookups to a search domain or hijacked resolver. |
| `JSONL row with url, addr, status, sha256` | Makes each observation attributable and replayable; console output is not evidence. |

## Worked Contrast

**Unbounded Fan-Out Over a Wordlist:**

```python
import asyncio, httpx

async def probe(url, client):
    r = await client.get(url)
    print(url, r.status_code)

async def main(urls):
    async with httpx.AsyncClient() as c:
        await asyncio.gather(*(probe(u, c) for u in urls))  # BUG: unbounded, no scope check, no retry discipline

asyncio.run(main([f"https://{h}" for h in open("hosts.txt").read().split()]))
```

**Scope-First Probe With a Fixed Window:**

```python
import asyncio, json, hashlib, httpx

LIMIT = 8

async def probe(url, client, sem, out):
    async with sem:
        try:
            r = await client.get(url, follow_redirects=False)
        except httpx.HTTPError as exc:
            out.write(json.dumps({"url": url, "error": type(exc).__name__}) + "\n")
            return
        out.write(json.dumps({"url": url, "status": r.status_code,
                              "len": len(r.content),
                              "sha256": hashlib.sha256(r.content).hexdigest()}) + "\n")

async def main(scope_path):
    scope = {l.strip().lower() for l in open(scope_path) if l.strip()}
    sem = asyncio.Semaphore(LIMIT)
    with open("audit.jsonl", "w", encoding="utf-8") as out:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await asyncio.gather(*(probe(f"https://{h}", client, sem, out) for h in sorted(scope)))

asyncio.run(main("scope.txt"))
```

**Why this matters:** The semaphore is the engagement limit expressed in code, and the JSONL row is the evidence. Unbounded `gather` over a wordlist is how an authorised audit becomes a load test against a shared origin, and a printed status code cannot be re-examined later.

## When It Is NOT This Issue

- **Client-side timeout read as an outage.** A 10-second timeout on a slow origin is your configuration, not a finding; re-probe with a longer timeout and a single connection.
- **Wildcard DNS read as host sprawl.** A wildcard A record makes every random label resolve; compare against a deliberately random label before reporting thousands of hosts.
- **CDN edge difference read as content change.** Different edges serve different bodies; hold the connection target constant before claiming a differential.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `httpx.AsyncClient` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `async-http-and-dns-audit-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: async-http-and-dns-audit-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `httpx.AsyncClient`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile async_http_and_dns.py; python async_http_and_dns.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `async-http-and-dns-audit-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-400`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
