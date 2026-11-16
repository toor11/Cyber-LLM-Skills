---
name: signature-and-mac-attacks
description: "Attacks signature and MAC verification: algorithm confusion, missing verification, malleability, and encoding of signed data. Use when integrity depends on a MAC or digital signature."
family: cryptography-attacks
tier: core
triggers: ["signature bypass", "mac bypass", "hmac attack", "verification bypass"]
cwe: [CWE-347]
owasp: []
attack: []
capec: [CAPEC-463]
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
---

# Signature and Mac Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Signature and MAC review is about what the verifier commits to. A MAC over the message authenticates the message; if the receiver parses the message into fields and uses a field the MAC does not cover, the MAC is decorative. That is the structural failure behind most real findings: a JWT that signs the header but a consumer that reads `alg` from the unsigned header, a webhook that MACs the body but a handler that reads a query parameter to decide the tenant, a signature over a document but a renderer that honours an embedded path. The second failure class is algorithm confusion: HMAC and RSA both consume byte strings, so a verifier that selects the algorithm from the token can be handed one that treats the RSA public key as an HMAC secret. The third is malleability, where a signature is valid for a value that differs from what the signer intended — ECDSA's `(r, n-s)` variant, or a scheme that signs a hash without domain separation so a signature over one context is valid in another. The precondition is always the gap between the bytes covered and the bytes used, and the review is a two-column comparison of those sets.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a field used by the handler is not covered by the MAC or signature **THEN** that gap is the finding; list the covered fields against the used fields before anything else.
2. **IF** the algorithm is selected from the token, header, or message **THEN** the branch is algorithm confusion; the fix is a fixed algorithm per key.
3. **IF** the scheme has no domain separation or context binding **THEN** the branch is cross-context reuse: a signature valid in one place accepted in another.
4. **IF** the scheme is HMAC over the full canonical message with a constant-time compare **THEN** the disposition is a control; record the canonicalisation.
5. **IF** the signature is ECDSA and the verifier rejects high-`s` values **THEN** malleability is closed; without that check, the same authorisation can take two forms.
6. **IF** the target is a JWT specifically **THEN** work through [`tls-and-pki-attacks`](../tls-and-pki-attacks/SKILL.md) for the key and trust side, and keep this skill for the MAC coverage question.
7. **IF** the digest is a raw hash of a concatenation **THEN** switch to [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md); that is a construction break, not a coverage gap.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Draw the two sets.** On one side, every byte the MAC or signature covers. On the other, every field the handler reads to make a decision. The difference is the attack surface, and drawing it takes a read of both the signer and the consumer.
2. **Check the algorithm selection.** Where does the verifier learn which algorithm to use? A constant per key is safe; a value from the message is a confusion candidate.
3. **Choose the branch.** Coverage gap, algorithm confusion, malleability, or cross-context reuse. Each has a proof that does not require forging anything.
4. **Define the baseline-vs-probe differential.** Baseline: a token whose covered and used fields agree. Probe: the same token with an uncovered field changed. Acceptance with the changed field is the finding; rejection means the field is covered somewhere you did not see.
5. **Name the stop condition.** Stop at the first uncovered field that changes a decision. Do not attempt to forge a MAC or recover a key.
6. **State the proof.** Report the covered set, the used set, the specific uncovered field, and the decision it changes. If every used field is inside the covered set and the algorithm is fixed, record `Verified Safe` with the canonicalisation named.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `jwt.decode(token, key, algorithms=[h["alg"]])` | Algorithm taken from the token, which is the confusion precondition | PyJWT misconfiguration, jsonwebtoken |
| MAC over the body but the handler reads `request.args["tenant"]` | Coverage gap: an unsigned field drives the decision | Webhook handlers, callback endpoints |
| `hmac.compare_digest(mac, expected)` over a canonical serialisation | Correct: full coverage plus constant-time compare | Python and Go webhook verifiers |
| ECDSA verification without a low-`s` check | Malleability: two distinct encodings for one authorisation, which breaks replay caches keyed by signature | Custom API signing |
| A signature over `sha256(payload)` with no context prefix | Cross-context reuse: the same signature is valid wherever that payload appears | Multi-endpoint API signing |
| A canonicalisation that sorts keys and drops duplicates | Closes the parser-differential gap between signer and consumer | JWS, AWS SigV4-style schemes |

## Worked Contrast

**Vulnerable: MAC covers the body, the handler trusts an unsigned parameter**

```python
# The HMAC is over the raw body, but the tenant comes from a query parameter. The
# signature is valid and irrelevant: the attacker picks the tenant.
import hmac, hashlib

def handle(request) -> dict:
    expected = hmac.new(SECRET, request.body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers["X-Sig"]):
        raise HTTPError(401, "bad signature")
    tenant = request.args["tenant"]          # unsigned field drives the decision
    return process(tenant, request.body)
```

**Hardened: signature over a canonical structure that includes every decision field**

```python
# The signed payload is a canonical JSON object that carries the tenant, so a
# changed tenant changes the MAC. The algorithm is fixed, not negotiated.
import hashlib, hmac, json

def handle(request) -> dict:
    doc = json.loads(request.body)
    tenant = request.headers.get("X-Tenant", "")
    if doc.get("tenant") != tenant:
        raise HTTPError(400, "tenant mismatch")
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(SECRET, b"v1|webhook|" + canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers["X-Sig"]):
        raise HTTPError(401, "bad signature")
    return process(doc["tenant"], doc)
```

**Why this matters:** The left handler verifies a signature over bytes it then ignores for the tenant decision, so the signature proves nothing about who the request is for. The right handler binds the tenant into the signed canonical form and uses a context prefix, so changing the tenant invalidates the MAC and the same signature cannot be replayed against another endpoint.

## When It Is NOT This Issue

- **A field that is derived from a signed field.** A tenant id computed from a signed subject is covered transitively; trace the derivation before filing.
- **An algorithm selected from server-side configuration keyed by the key id.** The header may name a `kid`, but the algorithm comes from config, which closes confusion.
- **A MAC over the raw body plus a separately signed header.** Two signatures over disjoint fields is a valid pattern if both are verified; check both.
- **A signature that is intentionally not bound to a context, in a single-endpoint service.** Cross-context reuse needs a second context to be meaningful.
- **ECDSA malleability with no replay cache keyed by signature.** High-`s` variants matter when something deduplicates on the signature; without that, it is a note.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `signature-and-mac-attacks` based solely on surface keywords (`HMAC`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `signature-and-mac-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: signature-and-mac-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-347`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)
- [`password-hashing-and-kdf-attacks`](../password-hashing-and-kdf-attacks/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `signature-and-mac-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 24 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (11), cyber-security/security-code (3), hackerone_disclosed_reports (3), CYBER_CPT/oxdf (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
