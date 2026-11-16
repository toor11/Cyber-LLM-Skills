# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`oauth-oidc-misconfiguration-flow-and-state-flaws`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: fast-jwt: Cache Confusion via cacheKeyBuilder Collisions Can Return Claims From a Different Token (I

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-601`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # fast-jwt: Cache Confusion via cacheKeyBuilder Collisions Can Return Claims From a Different Token (Identity/Authorization Mixup) fast-jwt: Cache Confusion via cacheKeyBuilder Collisions Can Return Claims From a Different Token (Identity/Authorization Mixup) - **OSV ID**: GHSA-r
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: CISA mixup of IOC domains

- **Provenance:** Source: `CYBER_CPT/netresec` | CWE: `CWE-601`
- **Context / Surface:** Source: netresec (en)
- **Root Cause / Analysis:** ## CISA mixup of IOC domains Google's Threat Intelligence Group (GTIG) and Mandiant's recent [Disrupting the GRIDTIDE Global Cyber Espionage Campaign] (https://cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign/) report is great and it h
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Litestar's FileStore key canonicalization collisions allow response cache mixup/poisoning (ASCII ord

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-601`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Litestar's FileStore key canonicalization collisions allow response cache mixup/poisoning (ASCII ord + Unicode NFKD) Litestar's FileStore key canonicalization collisions allow response cache mixup/poisoning (ASCII ord + Unicode NFKD) - **OSV ID**: GHSA-vxqx-rh46-q2pg - **CVE**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: OpenClaw: Gemini OAuth exposed the PKCE verifier through the OAuth state parameter

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-601`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # OpenClaw: Gemini OAuth exposed the PKCE verifier through the OAuth state parameter - **OSV ID**: GHSA-9jpj-g8vv-j5mf - **CVE**: CVE-2026-34511 - **Published**: 2026-04-04T06:26:55Z - **Modified**: 2026-04-07T14:35:45.361838Z - **Affected Packages**: openclaw - **Ecosystem**: np
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: OpenClaw: Gemini OAuth exposed the PKCE verifier through the OAuth state parameter

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-601`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary Before OpenClaw 2026.4.2, the Gemini OAuth flow reused the PKCE verifier as the OAuth 'state' value. Because the provider reflected 'state' back in the redirect URL, the verifier could be exposed alongside the authorization code. ## Impact Anyone who could capture the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Litestar's FileStore key canonicalization collisions allow response cache mixup/poisoning (ASCII ord

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-601`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary FileStore maps cache keys to filenames using Unicode NFKD normalization and ord() substitution without separators, creating key collisions. When FileStore is used as response-cache backend, an unauthenticated remote attacker can trigger cache key collisions via crafte
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
