---
name: web-recon-and-content-discovery-archive-and-osint-recon
description: Archive and OSINT web recon. Covers wayback and Common Crawl mining, GitHub and paste searches, and historical endpoint discovery for forgotten functionality. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["wayback recon", "archive recon", "gau", "common crawl", "historical endpoint"]
cwe: [CWE-20]
owasp: [A01:2021]
attack: []
capec: [CAPEC-116]
related: [web-recon-and-content-discovery, web-recon-and-content-discovery-directory-and-file, web-recon-and-content-discovery-javascript-analysis, sql-injection]
parent: web-recon-and-content-discovery
---

# Web Recon and Content Discovery Archive and OSINT Recon - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Archive and OSINT recon recovers surface and secrets from sources outside the live application: Wayback Machine and Common Crawl snapshots, search-engine and GitHub or paste indexes, and historical copies of JavaScript bundles. It works because the internet remembers endpoints, parameters, hostnames, and credentials that a site has since removed or rotated but that still appear in a cached snapshot or a committed file. The assessor pulls historical URLs, deduplicates and filters them, and looks for resources the current site no longer links or serves, or for secrets that were committed and may still be valid. The security-relevant control is whether removed functionality was actually decommissioned and whether leaked secrets were rotated, not merely unlinked or deleted from the live tree. The value is a view of forgotten surface and exposed secrets the live site hides. Proof is a historical artefact, a snapshot URL or a committed secret, shown to contain something the current site does not serve, and ideally still reachable or still valid.

- **Precondition chain:** The target or its code appears in an archive, search index, or public repository, that historical artefact contains an endpoint, parameter, or secret the live site no longer exposes, and the recovered item is either still reachable or still valid rather than fully decommissioned.
- **Readable differential:** A resource or secret present in a historical snapshot or commit versus its state on the current live site; a finding exists when the archived artefact reveals something the live site does not serve and the item remains reachable or valid, and it closes when the endpoint is decommissioned and the secret is rotated.
- **Empirical grounding:** CWE-20 and OWASP A01 frame the class; the scale is anchored by the GitGuardian State of Secrets Sprawl 2025 report (23,770,171 new secrets in public GitHub commits in 2024, 70% of 2022-leaked secrets still valid), GitHub's figure of over 39 million secrets leaked in 2024, and the Intruder JavaScript-bundle scan that found over 42,000 tokens across 334 secret types.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the task is not confirmed to be archive or OSINT recon **THEN** start at parent class [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) (1 hop) first
2. **IF** the discovery is live directory and file brute forcing **THEN** switch to [`web-recon-and-content-discovery-directory-and-file`](../web-recon-and-content-discovery-directory-and-file/SKILL.md) (1 hop)
3. **IF** the task is parsing current JavaScript bundles for endpoints **THEN** switch to [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) (1 hop)
4. **IF** a recovered secret is an API key or token that may still be valid **THEN** pivot to [`api-key-and-secret-exposure`](../api-key-and-secret-exposure/SKILL.md)
5. **IF** a recovered hostname is an unclaimed subdomain pointing at a dangling service **THEN** pivot to [`subdomain-takeover`](../subdomain-takeover/SKILL.md)
6. **IF** a historical endpoint is still live and needs technique testing **THEN** route back through [`web-app-fuzzing-and-automation`](../web-app-fuzzing-and-automation/SKILL.md) within scope
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** every archived artefact is fully decommissioned and every recovered secret is rotated **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Recovered artefact is a credential or token | [`api-key-and-secret-exposure`](../api-key-and-secret-exposure/SKILL.md) | Different invariant: secret validity rather than surface recovery |
| Recovered hostname is a dangling subdomain | [`subdomain-takeover`](../subdomain-takeover/SKILL.md) | Routes to the takeover invariant for the historical host |
| A historical endpoint is still live | [`web-recon-and-content-discovery-directory-and-file`](../web-recon-and-content-discovery-directory-and-file/SKILL.md) | Routes to live confirmation of the recovered path |
| Need parent class methodology | [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Pull historical URLs before touching the live target.** Query Wayback and Common Crawl indexes and search engines for the domain; this is passive and expands coverage without sending a single request to the application.
2. **Deduplicate and filter the index.** Collapse duplicate captures, filter by extension and status, and group by path so the signal, distinct historical endpoints, is separable from thousands of repeat captures.
3. **Diff the historical set against the live site.** For each archived endpoint, check whether the current site still links or serves it; the interesting items are those the live site no longer exposes.
4. **Search code and paste indexes for the domain and its secrets.** Look in public GitHub, gists, and paste sites for the hostname, internal paths, and credential patterns tied to the target.
5. **Validate reachability or validity, not just presence.** Confirm whether a recovered endpoint still responds and whether a recovered secret is still accepted, because a decommissioned endpoint or rotated key is only historical.
6. **Stop condition.** Halt when a recovered artefact is either (a) something the live site no longer serves yet is still reachable or still valid, (b) fully decommissioned or rotated so it has no current effect, or (c) only confirmable by actually using a live credential to access data. Outcome (a) is a finding, (b) is a non-finding, (c) must be reported as a credential exposure without exercising it against real data.
7. **State what counts as proof.** Proof is the historical artefact, a dated snapshot URL or a public commit, shown to contain an endpoint or secret the current site does not serve, together with evidence it is still reachable or still valid. A snapshot of content identical to the live site is not a finding.
8. **Close with the structural fix and verify it.** The target-side fix is to decommission the recovered endpoint at the origin, not merely unlink it, and to rotate and revoke any exposed secret, then re-check the archive-derived item to confirm it no longer responds and the credential is rejected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A Wayback or Common Crawl capture of an endpoint absent from the current site | Proves historical surface the live application no longer links, the core archive differential |
| A secret pattern (API key, token) in a public GitHub commit tied to the domain | Proves credential exposure, high impact if the key is still valid |
| An archived JavaScript bundle referencing routes removed from the current build | Proves client-side disclosure of decommissioned-looking but possibly live endpoints |
| A historical subdomain in certificate transparency or an archive now resolving to a dangling target | Proves a takeover candidate recovered from history |
| A recovered endpoint that still returns live content when requested in scope | Proves the removal was cosmetic, not a decommission |
| A leaked credential still accepted by the service | Proves the secret was never rotated, matching the high still-valid rate reported for leaked secrets |
| Internal hostnames or paths appearing in paste-site indexes | Proves information disclosure outside the application's own surface |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Build injects the ENTIRE environment into the client bundle
const webpack = require('webpack');
module.exports = {
  plugins: [
    new webpack.DefinePlugin({
      'process.env': JSON.stringify(process.env),   // leaks every secret
    }),
  ],
};
```

**Hardened pattern:**

```javascript
// Only an explicit allowlist of non-secret values reaches the client bundle
const webpack = require('webpack');
const PUBLIC_KEYS = ['API_BASE_URL', 'SENTRY_DSN'];
const exposed = Object.fromEntries(
  PUBLIC_KEYS.map((k) => [`process.env.${k}`, JSON.stringify(process.env[k])])
);
module.exports = {
  plugins: [new webpack.DefinePlugin(exposed)],
};
```

**Why this matters:** The defect is a build that embedded the whole process environment into the shipped bundle, so every server secret became recoverable from an archived or live JavaScript file. The fix defines only an explicit allowlist of non-secret values, so historical and current bundles cannot leak credentials, and any already-leaked secret must additionally be rotated.

## When It Is NOT This Issue

- **Decommissioned endpoint:** an archived path that now returns a hard 404 or connection refused at the origin is historical only, not current surface.
- **Rotated secret:** a credential found in a commit that the service now rejects is an exposure to document, not a live access path.
- **Identical snapshot:** an archive copy that matches the live site reveals nothing the site does not already serve.
- **Third-party domain:** archived content for a vendor or CDN domain outside the agreed scope is not the target's surface.
- **Placeholder or example secret:** a committed string that is an obvious example or test fixture is not a live credential.
- **Already-public data:** information intended to be public that happens to appear in archives is not a disclosure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-recon-and-content-discovery-archive-and-osint-recon` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-recon-and-content-discovery-archive-and-osint-recon` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-recon-and-content-discovery-archive-and-osint-recon
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: A01:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) - Web and Application (core)
- [`web-recon-and-content-discovery-directory-and-file`](../web-recon-and-content-discovery-directory-and-file/SKILL.md) - Web and Application (leaf)
- [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-recon-and-content-discovery-archive-and-osint-recon` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 31 |
| Distinct dataset sources | 4 |
| Top sources | osint-tool-database (16), bugbounty-hunter-v1 (12), CYBER_CPT/github_security_md (2), hackerone_disclosed_reports (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
