---
name: pdf-and-headless-renderer-injection
description: Audits server-side HTML-to-PDF and headless screenshot renderers (wkhtmltopdf, Puppeteer, Playwright, WeasyPrint, PrinceXML) for local file read (`file://`), cloud IMDS SSRF, `<link rel=attachment>`, and iframe timing side channels. Use when user HTML/Markdown is rendered into PDFs or images.
family: web-and-application
tier: core
triggers: ["html to pdf ssrf", "wkhtmltopdf lfi", "weasyprint attachment", "headless pdf injection"]
cwe: [CWE-918, CWE-200]
owasp: [A10:2021]
attack: []
capec: []
related: [sql-injection, cross-site-scripting, csrf, ssrf]
corpus_sparse: true
---

# Pdf and Headless Renderer Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Server-side HTML-to-PDF and headless screenshot pipelines render attacker-influenced HTML, CSS, or Markdown in an engine such as wkhtmltopdf, Puppeteer or Chromium, Playwright, WeasyPrint, or PrinceXML that runs with the server's filesystem and network position. The engine resolves resource references placed in the document: img, link rel=attachment, at-import, iframe, CSS url(), and file:// or http://169.254.169.254 targets. The security decision is whether the renderer disables local-file access and confines outbound fetches before loading those references. When it does not, the attacker reads local files embedded into the output, reaches cloud metadata and instance credentials, or opens a blind SSRF and timing side channel through the renderer's egress position.

- **Precondition chain:** user-influenced HTML or a user-supplied URL reaches a server-side renderer, the engine is allowed to fetch external or local resources with no disable-local-file-access flag and no fetch allowlist, the rendered artefact or a timing or size side effect is retrievable by the requester, and the engine has network reach to internal or metadata endpoints.
- **Readable differential:** render a document that references only an assessor-controlled external URL versus one that references file:/// or the metadata IP; a finding exists when the internal reference changes the output or produces a server-originated callback and vanishes once local-file access is disabled and an egress allowlist is enforced.
- **Empirical grounding:** CWE-918 and CWE-200 fold into OWASP Top 10:2025 A01; Stirling-PDF URL-to-PDF SSRF-to-file-read (GHSA-998c-x8hx-737r, fixed 0.45.0) and the Browsershot setUrl SSRF and LFI fixes (5.0.3 and 5.0.5, bypassing CVE-2024-21549 and CVE-2024-21544) anchor the renderer class, while Typebot CVE-2025-64709 shows the IMDSv2 custom-header bypass variant.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the document can reference file:/// and the output is returned to the requester **THEN** use an inert local file such as /etc/hostname and check whether its bytes embed into the rendered PDF
2. **IF** the goal is cloud instance metadata or role credentials **THEN** switch to [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) (1 hop) and confirm whether the engine can carry the IMDSv2 token header
3. **IF** the engine honors link rel=attachment to embed a referenced file **THEN** test the attachment vector separately, since it embeds a file even when img loading is restricted
4. **IF** no output is returned and only timing or size is observable **THEN** switch to [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) (1 hop) and use an iframe load-time oracle
5. **IF** the input is a fully attacker-controlled fetch URL rather than a rendered document **THEN** switch to [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) (1 hop) for the resolver-versus-connector gap
6. **IF** the engine is wkhtmltopdf versus WeasyPrint versus headless Chromium **THEN** record the engine first because local-file and redirect handling differ per engine
7. **IF** user Markdown or SVG is converted to HTML before rendering **THEN** test SVG foreignObject and at-import, which fetch resources even when script is stripped
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the renderer has local-file access disabled and runs network-isolated with no metadata route **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The reference reaches link-local or cloud metadata | [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) | Impact is instance-role credential exposure, a different invariant than local read |
| Only a blind callback or render timing is observable | [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) | The oracle is switched to out-of-band or timing, not output inspection |
| Input is a whole fetch URL, not a rendered document | [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) | The defect is validator-versus-resolver disagreement, not document reference resolution |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Identify the engine and whether the input is an HTML body, a Markdown or SVG document, or a URL the server fetches, and record the pipeline that reaches the renderer.
2. Confirm outbound fetch with an assessor-controlled external reference, capturing the engine's User-Agent so server-origin is established before any internal probe.
3. Classify engine capability by reading the invocation: is local-file access disabled, are redirects followed, is an egress allowlist present.
4. Choose the branch from evidence: a callback from the renderer's egress proves server-side fetch; embedded local file bytes in the PDF prove file read; a render-time delta proves a blind timing oracle.
5. Define the baseline-versus-probe differential: the external reference versus a file:/// or metadata reference, holding the rest of the document constant.
6. **Stop condition.** Stop when (a) a local file's bytes embed in the output or a metadata response returns or a server-originated callback arrives, demonstrated against the external baseline, (b) every internal reference is refused identically, or (c) advancing would read a real credential or internal secret; (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a fetch that originates from the renderer rather than a browser, carrying the engine User-Agent and landing on an inert internal target: an embedded /etc/hostname line in the PDF, a metadata endpoint banner, or an egress callback, all of which disappear once local-file access and an egress allowlist are enforced.
8. Close with the structural fix: disable local-file access, pin a resolve-once egress allowlist that rejects loopback, link-local, and private addresses, strip file and gopher schemes, and run the renderer in a network-isolated sandbox with no metadata route, then replay the file:/// and metadata probes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Outbound request carrying a wkhtmltopdf, HeadlessChrome, or WeasyPrint User-Agent | Proves the fetch is server-side from the renderer, not the victim's browser, on any HTML-to-PDF stack |
| file:/// content appearing inside the generated PDF | Proves local file read on wkhtmltopdf or WeasyPrint when local-file access is not disabled |
| link rel=attachment with a file:// href embedding a file | Proves the attachment vector reads a local file even when image loading is restricted |
| A request from the renderer host to 169.254.169.254 | Proves metadata reachability on AWS, GCP, or Azure, with impact gated by whether the token header can be sent |
| An iframe whose load time varies with the referenced host | Proves a blind timing oracle usable when no output is returned |
| Renderer invoked without a disable-local-file-access flag or url_fetcher allowlist | Proves missing confinement in the engine configuration itself, independent of any single reference |

## Worked Contrast

**Vulnerable pattern:**

```python
from weasyprint import HTML

def render_pdf(user_html: str) -> bytes:
    # Default url_fetcher resolves file://, http://169.254.169.254, any <img> or <link>.
    return HTML(string=user_html).write_pdf()
```

**Hardened pattern:**

```python
import ipaddress
import socket
import urllib.parse
from weasyprint import HTML, default_url_fetcher

ALLOWED_SCHEMES = {"https"}

def safe_fetcher(url, *args, **kwargs):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise ValueError("scheme blocked")
    addr = ipaddress.ip_address(socket.gethostbyname(parts.hostname))
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        raise ValueError("internal destination blocked")
    return default_url_fetcher(url, *args, **kwargs)

def render_pdf(user_html: str) -> bytes:
    return HTML(string=user_html, url_fetcher=safe_fetcher).write_pdf()
```

**Why this matters:** The defect hands user HTML to a renderer whose default fetcher honours file:// and internal IPs, turning a document into local-file read and metadata SSRF. The fix supplies a url_fetcher that restricts schemes to https and rejects every private, loopback, link-local, or reserved address before the engine connects, closing both the file-read and metadata branches.

## When It Is NOT This Issue

- **Local-file access disabled:** an engine started with disable-local-file-access cannot embed file:// content even when the document references it.
- **Network-isolated renderer:** a sandbox with no route to metadata or internal ranges blocks the SSRF branch regardless of the reference.
- **Output never returned and no blind oracle:** if the PDF is not retrievable and timing is not observable, a file reference yields no evidence path.
- **External public fetch only:** a reference that reaches another public site is a fetch gap, not internal access, until an inward destination is shown.
- **IMDSv2 token flow unreachable:** when the engine cannot issue the PUT and custom header, the metadata endpoint returns no credential.
- **Static template with no user references:** a renderer fed a fixed template with no attacker-controlled resource URLs has no injection surface.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `pdf-and-headless-renderer-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `pdf-and-headless-renderer-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: pdf-and-headless-renderer-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-918, CWE-200 | Mapping: A10:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `pdf-and-headless-renderer-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-918, CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
