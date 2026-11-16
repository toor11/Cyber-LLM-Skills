---
name: web-recon-and-content-discovery-javascript-analysis
description: JavaScript analysis for endpoints and secrets. Covers extracting API routes, hidden parameters and hardcoded secrets from bundled JavaScript, source maps and webpack chunks. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["javascript recon", "js endpoint extraction", "source map", "hardcoded secret js"]
cwe: [CWE-20]
owasp: [A01:2021]
attack: []
capec: [CAPEC-116]
related: [web-recon-and-content-discovery, web-recon-and-content-discovery-directory-and-file, web-recon-and-content-discovery-archive-and-osint-recon, sql-injection]
parent: web-recon-and-content-discovery
---

# Web Recon and Content Discovery Javascript Analysis - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Bundled JavaScript ships to every visitor, so whatever the build pipeline bakes into a chunk is readable by anyone who fetches it. The security decision lives in the build step, not at runtime: a webpack or Vite config that emits source maps, or that injects the whole process environment through DefinePlugin, writes server routes, hidden parameters, and API tokens straight into a public asset. An assessor extracts endpoints and secrets from the minified bundle, its `.js.map`, or a webpack chunk, and the gain is a map of the attack surface plus any live credential that was compiled in. Proof is differential: an endpoint or secret is present in the fetched bundle yet absent from the authenticated application's own responses, so it was disclosed by the build rather than by legitimate navigation.

- **Precondition chain:** The build publishes client JavaScript that embeds routes, parameters, or secrets, that bundle is fetchable without authentication, and no publish allowlist or source-map suppression removes the server-only material before shipping.
- **Readable differential:** An endpoint or token recovered from the public bundle is compared against the authenticated application's own surface; a finding exists when the bundle reveals something the app never serves, and it disappears once the build strips maps and applies a publish allowlist.
- **Empirical grounding:** SOURCES.md has no advisory specific to JavaScript recon, so this stays at taxonomy: CWE-20 and the OWASP WSTG review of client-side code, with the leakage root cause matching the SOURCES.md note that build scripts used `process.env` wholesale instead of a `.env` allowlist, placing live tokens in shipped bundles.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as bundle analysis **THEN** start at the parent class [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) (1 hop) for general triage
2. **IF** the surface is really server paths rather than shipped code **THEN** switch to [`web-recon-and-content-discovery-directory-and-file`](../web-recon-and-content-discovery-directory-and-file/SKILL.md) (1 hop)
3. **IF** the target only exists in historical bundles or VCS history **THEN** switch to [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) (1 hop)
4. **IF** a `.js.map` is served alongside the production bundle **THEN** reconstruct the original sources from the source map and flag the path and comment disclosure
5. **IF** a bundle references an API route absent from the authenticated app **THEN** treat the endpoint as the finding and route to [`authorization-and-idor`](../authorization-and-idor/SKILL.md)
6. **IF** a string in the bundle matches a known secret format **THEN** confirm the token is live out-of-band before reporting and route to [`api-key-and-secret-exposure`](../api-key-and-secret-exposure/SKILL.md)
7. **IF** the leaked values come from the whole environment at build time **THEN** record the DefinePlugin or env-injection config as the structural root cause
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** no endpoint or secret appears that is absent from the authenticated app **THEN** STOP and record a verified non-finding rather than reporting ordinary client code

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A bundle embeds a hardcoded token | [`api-key-and-secret-exposure`](../api-key-and-secret-exposure/SKILL.md) | Routes to live-secret validation, a different invariant than endpoint mapping |
| A discovered endpoint lacks server-side authorization | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | The bundle only reveals the route; access control is tested separately |
| Server-side path brute forcing is the better fit | [`web-recon-and-content-discovery-directory-and-file`](../web-recon-and-content-discovery-directory-and-file/SKILL.md) | Enumerating the server tree is distinct from parsing the client bundle |
| Need parent class methodology | [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the shipped assets and classify each.** List every `.js` chunk, its `.js.map` if present, and any webpack runtime manifest, distinguishing vendor chunks from application chunks since only the latter hold custom routes and keys.
2. **Pull an authenticated baseline of the real surface.** Record the routes and parameters the application actually exercises so that anything found only in the bundle is provably build-disclosed rather than normal traffic.
3. **Extract candidate endpoints and secrets.** Run an endpoint extractor and a secret scanner across the chunks and any recovered source map, collecting absolute and relative paths, query parameters, and token-shaped strings.
4. **Choose the proof channel per candidate.** An endpoint is proven by its absence from the authenticated baseline; a secret is proven by a non-destructive liveness check against its own service, never by using it to act.
5. **Reconstruct from the source map when present.** If a `.js.map` is served, rebuild the original file tree and comments, because directory structure and developer notes are themselves disclosure.
6. **Stop condition.** Halt when a candidate either (a) is an endpoint or live secret absent from the authenticated baseline, (b) turns out to be present in normal app responses too, or (c) can only be confirmed by actually using the credential. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an endpoint or token recovered from the public bundle together with evidence it is absent from the authenticated application surface, plus for a secret a read-only liveness signal; a string that merely looks like a key without that check is not proof.
8. **Close with the structural fix.** Disable source-map emission for production, replace wholesale environment injection with an explicit publish allowlist of client-safe variables, and rotate any exposed secret. Verify by rebuilding and confirming the map is gone and the token no longer appears in the bundle.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `.js.map` returned with 200 next to the production bundle | Proves source maps shipped to production, disclosing original file paths and comments on any webpack or Vite build |
| A fetch or axios call in a chunk referencing `/api/internal/...` not seen in normal use | Proves a server route was compiled into the client and is absent from the authenticated baseline |
| A string matching an AWS, Stripe, or Google key format inside a chunk | Proves a token-shaped secret was bundled, pending a read-only liveness check on its service |
| `process.env` serialised wholesale via DefinePlugin in the runtime chunk | Proves the build injected the entire environment, the structural root cause of bundled secrets |
| A webpack manifest mapping chunk ids to lazy-loaded route modules | Proves the full client route table is enumerable from the manifest without crawling the app |
| A hidden form parameter or feature flag present only in the bundle | Proves a parameter the UI never renders, expanding the request surface on the application tier |
| A commented-out staging or debug URL inside the source map | Proves environment and infrastructure disclosure recovered from the reconstructed sources |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Production build ships source maps and bakes the whole environment
// into the public bundle, so every CI secret is readable by any visitor.
const webpack = require("webpack");
module.exports = {
  mode: "production",
  devtool: "source-map",                 // emits .js.map next to each chunk
  plugins: [
    new webpack.DefinePlugin({
      "process.env": JSON.stringify(process.env), // leaks everything in CI
    }),
  ],
};
```

**Hardened pattern:**

```javascript
// Only an explicit allowlist of client-safe values is injected, and no
// source map is published, so server secrets never reach the bundle.
const webpack = require("webpack");
const PUBLIC = ["API_BASE_URL", "SENTRY_DSN"];
const exposed = Object.fromEntries(
  PUBLIC.map((k) => [`process.env.${k}`, JSON.stringify(process.env[k])])
);
module.exports = {
  mode: "production",
  devtool: false,                        // no source maps in the public bundle
  plugins: [new webpack.DefinePlugin(exposed)],
};
```

**Why this matters:** The defect injects the entire environment and ships source maps, so secrets and original paths travel to every client. The structural control is an explicit publish allowlist of client-safe variables plus suppressed source maps, so the build can no longer leak server-only material.

## When It Is NOT This Issue

- **Public configuration mistaken for a secret:** values such as a public API base URL, a Sentry DSN, or a publishable Stripe key are meant to be client-side and are not a leak.
- **Endpoint already in the authenticated surface:** a route found in the bundle that the app also calls during normal use is expected, not build-disclosed.
- **Expired or revoked token:** a key recovered from an old cached bundle that fails a read-only liveness check is historical noise, not a live exposure.
- **Vendor library string:** a token-shaped constant inside a third-party dependency chunk is usually a fixture or hash, not an application secret.
- **Source map behind authentication:** a `.js.map` that only loads for authenticated internal users on a non-production host is a dev convenience, not public disclosure.
- **Minified identifier that resembles a key:** a long base62 webpack module hash is not a credential and should not be reported as one.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-recon-and-content-discovery-javascript-analysis` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-recon-and-content-discovery-javascript-analysis` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-recon-and-content-discovery-javascript-analysis
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
- [`web-recon-and-content-discovery-archive-and-osint-recon`](../web-recon-and-content-discovery-archive-and-osint-recon/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-recon-and-content-discovery-javascript-analysis` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 6 |
| Top sources | SecEval/owasp_wstg (1), CYBER_CPT/hacktricks_cloud (1), CYBER_CPT/go_exploitdb (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
