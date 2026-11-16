---
name: api-key-and-secret-exposure
description: Finds and validates exposed API keys and secrets in JavaScript bundles, mobile apps, public repositories, error pages and misconfigured storage, then proves impact by exercising the credential. Use when hunting for credential material reachable from the application surface.
family: web-and-application
tier: core
triggers: ["api key exposure", "leaked secret", "hardcoded key", "secret in javascript", "exposed credentials"]
cwe: [CWE-798]
owasp: [A07:2021]
attack: [T1552]
capec: [CAPEC-70]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# API Key and Secret Exposure - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A provisioned credential such as an AWS access key, a Stripe `sk_live_` secret, a Google `AIza` key, or a GitHub `ghp_` token is emitted onto a surface the attacker can already read: a minified JavaScript bundle, a published source map, a mobile package, a verbose error page, a committed git object, or a misconfigured storage listing. The security decision that failed is a build-time or deployment-time one about which material is public, not a runtime input check, so no escaping or parameterisation is relevant. Once the string is reachable the attacker holds the same authority the server intended only for itself, and impact is bounded only by the scope the key carries. Confirmation is a two-part question: is the secret actually present on the client-reachable surface, and is it still live rather than rotated, each answerable without touching any protected resource.

- **Precondition chain:** a real credential is embedded in or rendered onto a surface the attacker can fetch, the build or deployment never stripped or server-sided it, and the credential is still valid and carries usable scope at the provider.
- **Readable differential:** the shipped client asset or published history contains a secret pattern that the server-only build does not, and the exposure disappears once the key is moved behind the server and rotated, proving the leak was a bundling or history-retention failure rather than an expected public key.
- **Empirical grounding:** CWE-798 Use of Hard-coded Credentials, with exposure classes CWE-200 and CWE-312; GitGuardian's State of Secrets Sprawl 2025 reported 23,770,171 new secrets in public GitHub commits during 2024 and that 70 percent of secrets leaked in 2022 were still valid, and an Intruder JavaScript-bundle scan found over 42,000 tokens where a build script used `process.env` wholesale instead of a `.env` allowlist.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the secret only surfaces after mining minified bundles, chunks, and source maps **THEN** treat build-time bundling as the surface and enumerate `.js`, `.js.map`, and `_next/static` artefacts before claiming exposure
2. **IF** the found value is an AWS `AKIA` key, a Stripe `sk_live_`, a Google `AIza`, or a GitHub `ghp_` **THEN** classify the provider and its scope first, because impact is defined by the credential type not the leak location
3. **IF** the credential is an OAuth client secret or refresh token rather than a provisioned API key **THEN** switch to [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) (1 hop) because the invariant is grant and scope validation
4. **IF** the exposed key is the HMAC used to sign the application's own JWTs **THEN** switch to [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) (1 hop); recovery of the signing key turns the leak into token forgery
5. **IF** the secret was deleted from HEAD but may remain in git history **THEN** record that deletion does not remediate; only rotation closes the exposure
6. **IF** the value looks like a secret but is a publishable client identifier (publishable key, public config) **THEN** confirm the provider's public-vs-secret prefix before reporting
7. **IF** the leak is reachable only through a reconstructed source map of a single-page app **THEN** verify a `.js.map` is actually served and reference [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) for the extraction
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** no secret pattern is present on any client-reachable surface and no provider confirms the key is live **THEN** STOP and record a verified non-finding rather than reporting a format-matching string

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Leaked value is the app's own JWT signing secret | [`jwt-attacks-secret-cracking`](../jwt-attacks-secret-cracking/SKILL.md) | Invariant becomes token forgery once the signing key is recovered, not credential storage |
| Leaked value is an OAuth client secret or refresh token | [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) | Invariant is grant and scope validation at the authorization server |
| Secret recovered from a published source map of a bundle | [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) | Invariant is build-time bundling hygiene, a discovery problem before validation |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate every surface that ships to the client and classify what sits on it.** Enumerate JavaScript bundles, chunk files, published source maps, mobile package contents, HTML comments, error pages, and reachable storage listings. The sink here is a publication boundary, so list the artefacts before pattern-matching them.
2. **Choose the confirmation channel before fetching a key.** Presence on a client asset, reconstruction from a source map, discovery in git history, and a live-versus-revoked provider signal are distinct oracles. Prefer the one that proves exposure while touching the fewest protected resources, starting with static presence.
3. **Record a baseline from a server-only source.** Note which secret patterns appear in the server environment or private configuration but must never appear in the client build. That baseline is what a shipped bundle is compared against.
4. **Sweep the client surface for provider-specific prefixes.** Match `AKIA`, `sk_live_`, `AIza`, and `ghp_` against each artefact, then attempt a source-map reconstruction where a `.map` is served. A hit here is candidate exposure, not yet confirmed impact.
5. **Separate a true secret from a publishable identifier.** Check the provider's public-versus-secret convention: a publishable or anon key is expected on the client, while a secret-scoped key is the finding. Misreading this is the dominant false positive.
6. **Stop condition.** Halt when the key is either (a) present on a client-reachable surface and confirmed live by a read-only provider identity call, (b) absent from every client surface or proven already rotated, or (c) usable only by performing a scoped action against real customer data. Case (a) is confirmation, (b) is a non-finding, (c) is beyond non-destructive scope.
7. **State what counts as proof.** Proof is the exact artefact and offset where the secret ships, the provider classification showing it is a secret-scoped credential, and a read-only validity signal such as an identity echo that returns the key's owner, all tied together without reading or mutating a protected resource. A format match alone is not proof.
8. **Close with the structural fix.** Move the credential server-side, replace wholesale `process.env` injection with an explicit public-prefixed allowlist in the bundler, strip source maps from production, and rotate the exposed key because deletion from history does not revoke it. Verify by rebuilding and re-sweeping the client surface for the prefix.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An `AKIA`-prefixed string inside a shipped JavaScript bundle or mobile package | Proves an AWS access key id reached the client build on a webpack, Vite, or React Native pipeline, so the secret is world-readable |
| An `sk_live_` token echoed in an HTTP response or error page | Proves a live Stripe secret key is reachable from the application surface, carrying charge and refund scope until rotated |
| A reachable `.js.map` source map served alongside a minified bundle | Proves original source with inlined constants can be reconstructed on any single-page-app deployment that published maps |
| `process.env` serialised wholesale into client config by a bundler define step | Proves a build-time allowlist failure where every environment variable, including server secrets, ships to the browser |
| A secret still present in an earlier commit after deletion from HEAD | Proves history retention on the git host, so rotation rather than deletion is the only remediation |
| A `ghp_` or `AIza` token returned by a debug or status endpoint | Proves a GitHub token or Google API key leaks through an application-controlled response on the running stack |
| A read-only provider identity call returning the owner of the found key | Proves the credential is live rather than revoked, confirming impact without touching protected resources |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// vite.config.js: serialises the entire server environment into the client bundle
import { defineConfig } from "vite";

export default defineConfig({
  define: {
    // Ships STRIPE_SECRET_KEY, AWS keys and every other variable to the browser
    "process.env": JSON.stringify(process.env),
  },
});
```

**Hardened pattern:**

```javascript
// Only variables with a public prefix are exposed; secrets stay server-side
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const client = Object.fromEntries(
    Object.entries(env).filter(([key]) => key.startsWith("VITE_")),
  );
  // Server-scoped secrets are read at runtime on the server, never in define()
  return { define: { "import.meta.env.PUBLIC": JSON.stringify(client) } };
});
```

**Why this matters:** The defect serialises the whole process environment into client-reachable JavaScript, so every provisioned secret ships to every browser. The control exposes only an explicit public-prefixed allowlist and keeps secret-scoped material on the server, so a leaked variable can no longer be a live credential.

## When It Is NOT This Issue

- **Publishable key mistaken for a secret:** a Stripe publishable key, a Google Maps browser key with referrer restrictions, or a Supabase anon key is meant to live in the client; only secret-scoped prefixes are the finding.
- **Format match with no live credential:** a string matching `AKIA` or `sk_live_` that the provider reports as revoked or never valid is a hygiene note, not an exploitable exposure.
- **Server-only path, not client-reachable:** a secret present in a server log or private build artefact that no unauthenticated request can fetch has not crossed the publication boundary.
- **Referrer- or IP-restricted key:** a key that only functions from the app's own origin or network carries a compensating control that neutralises external reuse.
- **Example or placeholder value:** a `AKIAIOSFODNN7EXAMPLE`-style documentation token or an obvious dummy is not a provisioned credential.
- **Rotated before report:** a key found in old git history that has already been rotated proves the history-retention lesson but is not a current exposure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `api-key-and-secret-exposure` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `api-key-and-secret-exposure` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: api-key-and-secret-exposure
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-798 | Mapping: T1552]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `api-key-and-secret-exposure` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-798, T1552`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 34 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (26), hackerone_disclosed_reports (2), CYBER_CPT/expku (2), CYBER_CPT/go_exploitdb (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
