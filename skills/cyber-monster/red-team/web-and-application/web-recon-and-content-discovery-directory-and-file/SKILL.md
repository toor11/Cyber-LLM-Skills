---
name: web-recon-and-content-discovery-directory-and-file
description: Directory and file brute forcing. Covers wordlist selection, recursion, extension fuzzing, and rate control to find backups, configs, admin panels and debug endpoints. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["directory brute force", "file discovery", "ffuf", "gobuster", "dirsearch"]
cwe: [CWE-20]
owasp: [A01:2021]
attack: []
capec: [CAPEC-116]
related: [web-recon-and-content-discovery, web-recon-and-content-discovery-javascript-analysis, web-recon-and-content-discovery-archive-and-osint-recon, sql-injection]
parent: web-recon-and-content-discovery
---

# Web Recon and Content Discovery Directory and File - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Directory and file discovery works because a web server answers differently for a path that exists and one that does not, so an attacker can replay a wordlist and read the server's own disclosure in the response. The decision point is the routing and static-file layer: an unmapped request should return a path-independent 404, but backups, VCS metadata, config files, and debug endpoints left inside the document root give a 200, a redirect, a distinct length, or a directory listing instead. The gain is not code execution but reachable surface, a backup archive, a .git tree, or an admin panel that the application never meant to link. Confirmation is always a differential: the response for a candidate path diverges from the bulk-404 baseline in status, body length, or timing, and that divergence is reproducible.

- **Precondition chain:** Sensitive artefacts sit inside the served document root, the server returns a distinguishable response for an existing path versus a missing one, and no uniform error handler or authentication gate hides that difference from an unauthenticated client.
- **Readable differential:** A candidate path is requested and compared against a known-missing control path; a finding exists when status, body length, or timing diverge from the bulk-404 baseline, and it collapses once the server returns a uniform 404 for both.
- **Empirical grounding:** SOURCES.md carries no advisory specific to directory and file brute forcing, so this stays at taxonomy: CWE-20 improper input validation and the OWASP WSTG content-discovery methodology referenced in SOURCES.md, with the exposed artefacts falling under OWASP Top 10:2025 A01 Broken Access Control.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as path brute forcing **THEN** start at the parent class [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) (1 hop) for general triage
2. **IF** the target routes are really endpoints embedded in shipped JavaScript **THEN** switch to [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) (1 hop)
3. **IF** the content exists only in historical snapshots or VCS history **THEN** switch to [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) (1 hop)
4. **IF** a discovered path is an unauthenticated admin or object endpoint **THEN** pivot to [`authorization-and-idor`](../authorization-and-idor/SKILL.md) because existence is now an access-control question
5. **IF** the server returns an identical status and length for every path **THEN** treat response distinguishability, not the wordlist, as the control and record the exact oracle
6. **IF** a WAF rate-limits or tarpits the scan **THEN** lower the request rate and key the differential on body length rather than status code
7. **IF** the host multiplexes virtual hosts by the Host header **THEN** fuzz the Host header for virtual hosts instead of fuzzing paths
8. **IF** an extension such as .bak, .old, .zip, or .git is the real target **THEN** fuzz the extension list against known base names rather than running a flat wordlist
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
10. **IF** no path yields a response distinguishable from the bulk-404 baseline **THEN** STOP and record a verified non-finding rather than reporting raw wordlist hits

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A discovered path is an authenticated admin panel | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Existence is proven; whether access control gates it is a different invariant |
| Secrets sit inside a discovered JavaScript bundle | [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) | Routes to in-bundle secret analysis rather than path enumeration |
| Only archived or deleted content holds the target | [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) | Historical snapshots are a different source than live brute forcing |
| Need parent class methodology | [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the routing and static-file layer and classify it.** Determine whether paths are served by a framework router, a static handler, or a reverse proxy, because each produces its own missing-path response and its own disclosure shape.
2. **Capture the bulk-404 baseline first.** Request several guaranteed-missing paths and record status, body length, redirect target, and timing; this noise floor is what every candidate is compared against.
3. **Choose the oracle from the baseline.** If missing paths return 404 with a fixed length, status is the oracle; if everything returns 200 with a soft error page, body length or a marker string is the oracle; if responses are padded, fall back to timing.
4. **Run a scoped, rate-controlled wordlist.** Match the wordlist and extension set to the detected stack, keep concurrency low enough to stay inside authorised load, and filter results by the chosen oracle, not by raw hit count.
5. **Separate reachability from exposure.** For each divergent path, confirm it actually returns content an unauthenticated client should not have, rather than a login redirect or a generic placeholder.
6. **Stop condition.** Halt when a path either (a) returns content that diverges from the bulk-404 baseline and is served without authentication, (b) shows no divergence across the whole list, or (c) would require downloading or altering real data to confirm. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single candidate path whose response diverges reproducibly from the bulk-404 baseline in status, length, or timing, plus the retrieved artefact's identity (a backup name, a .git/config, a debug route), not merely a 200 that could be a catch-all handler.
8. **Close with the structural fix.** Move backups, VCS metadata, and config files out of the document root, disable directory autoindexing, and return a uniform 404 for unknown paths so existence cannot be inferred. Verify by replaying the confirmed path and seeing it match the baseline.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A 200 with a distinct body length for `/config.php.bak` or `/backup.zip` | Proves a backup artefact is reachable inside the document root on any static or framework stack, the core content-discovery finding |
| A served `/.git/HEAD` or `/.git/config` response | Proves version-control metadata leaked into the web root, which can reconstruct source on Apache or Nginx deployments |
| A directory listing page returned for a folder with no index | Proves autoindexing is enabled, exposing every file name without a wordlist on the serving tier |
| A 401 or 302-to-login for a path that a wordlist surfaced | Proves the path exists but is gated, which reclassifies the finding as an access-control question rather than disclosure |
| Identical status and body length for every unmapped path | Proves a catch-all soft-404 handler, meaning status alone is not a usable oracle and length or timing must be used |
| A `/debug`, `/actuator`, or `/server-status` route answering unauthenticated | Proves a diagnostic endpoint shipped to production, a high-value content-discovery hit on common frameworks |
| A response length that tracks a Host-header value rather than the path | Proves virtual-host multiplexing, so the discovery surface is the Host namespace rather than the path namespace |

## Worked Contrast

**Vulnerable pattern:**

```nginx
# Backups, configs, and VCS metadata live under the web root, and the
# server both serves them and lists the directory that holds them.
server {
    listen 80;
    root /var/www/app;              # also contains config.php.bak, db.sql, .git/
    location / {
        autoindex on;              # directory listing exposes every file name
        try_files $uri $uri/ =404;
    }
}
```

**Hardened pattern:**

```nginx
# Only built public assets are reachable; sensitive artefacts live elsewhere,
# listing is off, and dotfiles are denied so existence cannot be inferred.
server {
    listen 80;
    root /var/www/app/public;       # no backups, no db dumps, no VCS metadata
    location / {
        autoindex off;             # unknown paths get a uniform 404
        try_files $uri /index.php?$query_string;
    }
    location ~ /\.(?!well-known) {  # block .git, .env, and other dotfiles
        deny all;
        return 404;
    }
}
```

**Why this matters:** The defect is that secrets sit inside the served root and the server advertises them through listings and distinct responses. The structural control relocates sensitive artefacts out of the document root, disables autoindexing, and returns a uniform 404 for dotfiles, so a wordlist can no longer distinguish an existing path from a missing one.

## When It Is NOT This Issue

- **Soft-404 catch-all mistaken for hits:** an app that returns 200 with a friendly error page for every path will light up a wordlist. Only a response that diverges from that soft-404 baseline in length or content is a hit.
- **Login redirect counted as exposure:** a path that 302s to the authentication flow exists but is gated. That is an access-control question, not an unauthenticated-disclosure finding.
- **Static placeholder files:** default framework assets such as `favicon.ico`, `robots.txt`, or a stock `index.html` are expected content, not leaked artefacts.
- **Rate-limit page echoed as content:** a WAF challenge or throttle page returned mid-scan is the control working, and its distinct length is not evidence of a hidden file.
- **Developer copy on a non-production host:** a `.bak` on an explicitly labelled staging box inside the test scope is an environment artefact, not a production exposure.
- **Reachable but empty directory:** an autoindex of a folder that contains nothing sensitive is noise, not a disclosure, until a sensitive file is actually enumerated inside it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-recon-and-content-discovery-directory-and-file` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-recon-and-content-discovery-directory-and-file` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-recon-and-content-discovery-directory-and-file
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: A01:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) - Web and Application (core)
- [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) - Web and Application (leaf)
- [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-recon-and-content-discovery-directory-and-file` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 35 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (19), OffsecCyber (8), CYBER_CPT/L5/ctf_search (7), SecEval/attck (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
