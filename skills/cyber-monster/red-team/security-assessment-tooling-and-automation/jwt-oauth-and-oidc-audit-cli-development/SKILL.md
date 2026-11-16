---
name: jwt-oauth-and-oidc-audit-cli-development
description: "Writes non-destructive JWT, OAuth 2.0, and OIDC configuration auditors: `.well-known/openid-configuration` validator, JWKS key-rotation/algorithm inspector, PKCE/state requirement checker, and RFC-compliant claim verifier. Use when scripting identity and token configuration checks."
family: security-assessment-tooling-and-automation
tier: leaf
triggers: ["oidc audit script", "jwks validator", "jwt linter", "oauth config checker"]
cwe: [CWE-347]
owasp: [A07:2021]
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# JWT Oauth and OIDC Audit CLI Development - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Auditing an OpenID Connect deployment by reading its published metadata and then testing the token pipeline: fetch `/.well-known/openid-configuration`, confirm `issuer` matches the issuer in issued tokens, inspect `jwks_uri` key types and rotation, check `id_token_signing_alg_values_supported`, and verify that `code_challenge_methods_supported` includes `S256` for public clients. The CLI exists to make each of those checks a recorded observation rather than a recollection.

- **Issuer equality is the first check.** A token whose `iss` differs from the discovery document's `issuer` must be rejected; a validator that ignores `iss` accepts tokens from a sibling deployment.
- **Algorithm agreement, not algorithm preference.** The verifier must pin the accepted `alg` set explicitly; taking the algorithm from the token header is the classic confusion bug.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the client is public (SPA, mobile, CLI) **THEN** require `code_challenge_methods_supported` to include `S256` and confirm PKCE is enforced server-side.
2. **IF** `jwks_uri` returns keys of a type the verifier does not pin **THEN** record the accepted key types before testing any token.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a discovery document, a sample token, and the verifier configuration (accepted algs, expected issuer, audience) — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python with `PyJWT[crypto]` (`jwt.decode(..., algorithms=[...], issuer=..., audience=...)`) and `httpx` for metadata fetches
- **Mandatory Self-Validation Command:** `python -c "import jwt, httpx; print(jwt.__version__)"`

1. Confirm the target surface: fetch the discovery document, record `issuer`, `jwks_uri`, `id_token_signing_alg_values_supported`, and `code_challenge_methods_supported`.
2. Choose the branch: metadata audit (what the deployment advertises), token audit (claims and signature against the published keys), or flow audit (PKCE, state, nonce, redirect_uri handling).
3. Define the differential: decode a token with the correct issuer and audience (baseline, must pass) and with one claim altered (probe, must fail). A verifier that accepts both is the finding.
4. Name the stop condition: a fixed claim set per run and a single key fetch, so key rotation during the test does not masquerade as a failure.
5. Prove it: record the metadata document hash, the key ids used, and the decode error text for each probe, so the finding names the check that failed rather than the library.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `httpx.get(base + "/.well-known/openid-configuration")` | The authoritative metadata; every later check compares against it rather than against documentation. |
| `jwt.decode(token, key, algorithms=["RS256"], issuer=..., audience=...)` | Passing an explicit algorithm list removes header-driven algorithm selection. |
| `jwt.get_unverified_header(token)` | Reads `kid` and `alg` for routing to the right key, never for deciding what to trust. |
| `jwks["keys"] filtered on kid and kty` | Key selection by id and type prevents an RSA token being verified with an EC key path. |

## Worked Contrast

**Validation That Trusts the Token Header:**

```python
import jwt

header = jwt.get_unverified_header(token)
claims = jwt.decode(token, key, algorithms=[header["alg"]])  # BUG: algorithm chosen by the attacker
print(claims["sub"])  # BUG: no issuer or audience check
```

**Pinned Algorithm, Issuer and Audience:**

```python
import jwt
from jwt import InvalidTokenError

header = jwt.get_unverified_header(token)
if header.get("alg") not in {"RS256"}:
    raise SystemExit("unexpected alg")

try:
    claims = jwt.decode(
        token, key, algorithms=["RS256"],
        issuer=METADATA["issuer"], audience=CLIENT_ID,
        options={"require": ["iss", "aud", "exp", "sub"]},
    )
except InvalidTokenError as exc:
    raise SystemExit(f"rejected: {type(exc).__name__}")
print(claims["sub"], claims["aud"])
```

**Why this matters:** Taking `alg` from the token lets the token choose how it is verified, and skipping `iss` and `aud` accepts tokens minted for another client or another deployment. Pinning the algorithm list and requiring the registered claims makes the verifier's decision independent of anything the token says about itself.

## When It Is NOT This Issue

- **`alg: none` reported from a decoder that already rejects it.** Many libraries reject `none` by default; the finding requires an accepting path.
- **Audience mismatch on an ID token vs an access token.** They carry different audiences; compare against the right one.
- **Metadata behind a CDN serving a stale copy.** A stale discovery document explains a key mismatch that is not a vulnerability.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `.well-known/openid-configuration` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `jwt-oauth-and-oidc-audit-cli-development` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: jwt-oauth-and-oidc-audit-cli-development
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `.well-known/openid-configuration`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile jwt_oauth_and_oidc.py; python jwt_oauth_and_oidc.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `jwt-oauth-and-oidc-audit-cli-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
