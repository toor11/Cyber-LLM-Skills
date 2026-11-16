---
name: web-recon-and-content-discovery
description: "Maps a web application's surface: directory and file brute forcing, virtual host discovery, parameter mining, JavaScript endpoint extraction, source-map and backup hunting, and wayback and archive mining. Use at the start of web testing or when looking for unlinked functionality."
family: web-and-application
tier: core
triggers: ["web recon", "content discovery", "directory brute force", "ffuf", "gobuster", "endpoint discovery", "content discovery"]
cwe: [CWE-20]
owasp: [A01:2021]
attack: []
capec: [CAPEC-116]
related: [web-recon-and-content-discovery-directory-and-file, web-recon-and-content-discovery-javascript-analysis, web-recon-and-content-discovery-archive-and-osint-recon, sql-injection]
---

# Web Recon and Content Discovery - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Content discovery infers the parts of a web application that are reachable but not linked: directories and files found by brute forcing a wordlist, virtual hosts resolved from the same IP, parameters mined by observing response changes, endpoints extracted from JavaScript bundles and source maps, and historical URLs pulled from archives. Each discovery is proven the same way, by a response differential: a path that exists returns something measurably different (status, length, redirect, timing) from a path that does not. The security-relevant control on the target is whether unlinked, backup, source-map, and administrative resources are actually protected rather than merely unlinked; discovery finds the ones reachable by anyone who asks. The value gained is an expanded, accurate map of the attack surface that routes the rest of the assessment. Proof is the existence differential for each discovered resource, calibrated against a known-absent baseline so soft-404s do not masquerade as hits.

- **Precondition chain:** The server responds differently to existing and non-existing resources, unlinked or forgotten resources are reachable without extra authorisation, and the discovery is calibrated against a known-absent baseline so generic catch-all responses are not counted as hits.
- **Readable differential:** A request for a known-absent path versus a request for a candidate path; a discovery exists when the candidate diverges from the absent baseline in status, length, or redirect, and a candidate that matches the baseline is treated as not present.
- **Empirical grounding:** CWE-20 and OWASP A01 frame the class, and OWASP WSTG content-discovery methodology anchors the proof standard that a discovered path is confirmed by a differential response, not by a wordlist hit alone. SOURCES.md has no discovery-specific advisory, so this skill stays at the taxonomy and WSTG methodology level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the task is brute forcing directories and files **THEN** switch to [`web-recon-and-content-discovery-directory-and-file`](../web-recon-and-content-discovery-directory-and-file/SKILL.md) (1 hop)
2. **IF** the task is extracting endpoints and secrets from JavaScript **THEN** switch to [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) (1 hop)
3. **IF** the task is mining archives and OSINT for historical URLs **THEN** switch to [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) (1 hop)
4. **IF** candidate parameters rather than paths must be discovered **THEN** read [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md)
5. **IF** the discovery needs repeating at scale with calibrated diffing **THEN** use [`web-app-fuzzing-and-automation`](../web-app-fuzzing-and-automation/SKILL.md)
6. **IF** a discovered host is an unclaimed subdomain pointing at a dangling service **THEN** pivot to [`subdomain-takeover`](../subdomain-takeover/SKILL.md)
7. **IF** a discovered file is an exposed API schema or spec **THEN** pivot to [`openapi-and-swagger-exposure`](../openapi-and-swagger-exposure/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every candidate matches the known-absent baseline and no reachable resource diverges **THEN** STOP and record a verified non-finding rather than reporting soft-404 noise

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Candidates are parameters, not paths | [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md) | Different invariant: hidden parameters versus hidden paths |
| A discovered subdomain points at a dangling service | [`subdomain-takeover`](../subdomain-takeover/SKILL.md) | Routes to the takeover invariant for the discovered host |
| A discovered file is an API schema | [`openapi-and-swagger-exposure`](../openapi-and-swagger-exposure/SKILL.md) | Routes to schema-exposure impact rather than path discovery |
| Target matches `web-recon-and-content-discovery-directory-and-file` | [`web-recon-and-content-discovery-directory-and-file`](../web-recon-and-content-discovery-directory-and-file/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `web-recon-and-content-discovery-javascript-analysis` | [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `web-recon-and-content-discovery-archive-and-osint-recon` | [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish the known-absent baseline first.** Request several paths that certainly do not exist and record the status, length, and redirect behaviour; this is the signature of 'not here' that every candidate is measured against.
2. **Choose discovery channels for the surface.** Directory and file brute forcing, virtual-host enumeration, parameter mining, JavaScript and source-map extraction, and archive mining each reveal a different slice; pick the ones the target exposes.
3. **Select wordlists and mutations to the stack.** Use lists weighted to the identified technology (extensions, backup suffixes, framework paths) so hits are relevant rather than generic.
4. **Run calibrated against the baseline.** Diff each candidate response against the absent baseline on status, length, and redirect, and auto-filter responses that match the catch-all so soft-404s are not counted.
5. **Confirm each hit resolves to real, reachable content.** Re-request a flagged path by hand and verify it returns distinct content and does not merely redirect into the generic baseline.
6. **Stop condition.** Halt a channel when it either (a) yields paths that diverge from the absent baseline and serve real content, (b) returns only baseline-matching responses across the list, or (c) begins returning rate-limit or WAF pages that break the differential. Outcome (a) is a discovery, (b) is a non-finding, (c) means re-pace rather than conclude.
7. **State what counts as proof.** Proof of a discovered resource is a hand-reproduced existence differential: the candidate path returns a status, length, or redirect distinct from the calibrated absent baseline, and it serves content the application did not link. A single wordlist hit without this differential is not confirmed.
8. **Close with the structural fix and verify it.** The target-side fix is to remove or authenticate the exposed resources (delete backups and source maps, require authorisation on admin paths, return a uniform 404 for absent and forbidden alike), then re-run the calibrated sweep to confirm the differential that revealed them is gone.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A candidate path whose status or length differs from the known-absent baseline | Proves the resource exists and is reachable, the core discovery differential |
| A `.js.map` source map served alongside a bundle | Proves original source and route structure are exposed on the build |
| A backup or editor-suffix file (`.bak`, `~`, `.old`) returning 200 | Proves a forgotten artefact is reachable without authorisation |
| A virtual host on the same IP returning different content for a different `Host` | Proves an unlinked application surface reachable by host header |
| A `robots.txt` or `sitemap.xml` listing paths absent from the linked navigation | Proves disclosure of unlinked routes by the site itself |
| A soft-404 catch-all returning 200 for any path | Proves the baseline must be calibrated or every hit is a false positive |
| An endpoint referenced in a JavaScript bundle but absent from the rendered site | Proves client-side disclosure of a reachable but unlinked API route |

## Worked Contrast

**Vulnerable pattern:**

```nginx
server {
    root /var/www/app;
    # Source maps and backups are served like any static file
    location / {
        try_files $uri $uri/ =404;
    }
    # Admin UI is merely unlinked, not protected
    location /admin-internal/ { }
}
```

**Hardened pattern:**

```nginx
server {
    root /var/www/app;
    location / {
        try_files $uri $uri/ =404;
    }
    # Do not serve source maps, backups, or editor artefacts
    location ~* \.(map|bak|old|swp)$ { return 404; }
    # Unlinked is not a control: require authentication
    location /admin-internal/ {
        auth_request /auth;
        try_files $uri $uri/ =404;
    }
}
```

**Why this matters:** The defect is that forgotten source maps and backup files were served as ordinary static content and the admin path relied on being unlinked, so a wordlist sweep that diverges from the 404 baseline exposed all of it. The fix refuses to serve map and backup suffixes and puts the administrative surface behind authentication, so discovery no longer finds reachable content there.

## When It Is NOT This Issue

- **Soft-404 false positive:** a 200 that is actually the generic catch-all page is not a discovered resource; calibrate against the absent baseline.
- **Linked content:** a path already present in the site navigation or sitemap is not an unlinked discovery.
- **Archive-only URL:** a path that exists only in a historical snapshot and now 404s is not current surface.
- **Redirect into the baseline:** a candidate that redirects to the same generic page as absent paths is not distinct content.
- **Authenticated-equivalent 404:** a path that returns 404 to the unauthenticated tester but exists for authenticated users is a different question than open exposure.
- **WAF or rate-limit page:** a 403 challenge counted as a hit conflates a control with a resource.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-recon-and-content-discovery` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-recon-and-content-discovery` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-recon-and-content-discovery
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: A01:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`web-recon-and-content-discovery-directory-and-file`](../web-recon-and-content-discovery-directory-and-file/SKILL.md) - Web and Application (leaf)
- [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) - Web and Application (leaf)
- [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-recon-and-content-discovery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 50 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/oxdf (16), bugbounty-hunter-v1 (11), OffsecCyber (10), CYBER_CPT/L5/ctf_search (10) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 2 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
