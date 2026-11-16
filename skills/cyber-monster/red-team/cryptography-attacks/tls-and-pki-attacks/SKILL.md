---
name: tls-and-pki-attacks
description: "Attacks TLS and PKI in practice: weak protocol versions and ciphers, certificate validation gaps, pinning weaknesses, and trust store abuse. Use when assessing transport security or an interception scenario."
family: cryptography-attacks
tier: core
triggers: ["tls attack", "ssl misconfiguration", "pki attack", "certificate validation", "cipher suite"]
cwe: [CWE-326]
owasp: []
attack: []
capec: [CAPEC-94]
related: [tls-and-pki-attacks-configuration-weaknesses, tls-and-pki-attacks-certificate-validation-gaps, classical-and-covert-encoding, symmetric-cipher-attacks]
---

# TLS and PKI Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

TLS review splits into the negotiation, the trust decision, and the certificate lifecycle. Negotiation failures are configuration: a protocol floor below TLS 1.2, a cipher suite list that still offers static RSA or RC4, a curve allowlist that overrides the library default, or a renegotiation setting. Trust failures are code: a client that accepts any certificate, a pinning implementation that compares the wrong field, a hostname check that only validates the leaf's CN, or a trust store that includes a private CA for everything. Lifecycle is operational and increasingly the dominant risk: the CA/Browser Forum's SC-081v3 ballot reduces the maximum validity of publicly trusted TLS certificates to 200 days from 15 March 2026, then 100 days from 2027 and 47 days from 2029, and reduces domain-validation reuse to 10 days by 2029, which means an estate that renews manually cannot stay compliant and an outage becomes a security-pressure event where exceptions get granted. Post-quantum group support belongs in the same review because the terminator that cannot negotiate a hybrid is the one that will also resist the next change.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a client disables verification, or accepts any chain **THEN** switch to [`tls-and-pki-attacks-certificate-validation-gaps`](../tls-and-pki-attacks-certificate-validation-gaps/SKILL.md); that is the trust branch.
2. **IF** the server offers a legacy protocol, cipher, or curve **THEN** switch to [`tls-and-pki-attacks-configuration-weaknesses`](../tls-and-pki-attacks-configuration-weaknesses/SKILL.md).
3. **IF** the question is certificate lifetime, renewal automation, or domain-validation reuse **THEN** stay here; the SC-081v3 schedule is the deciding fact.
4. **IF** the endpoint must support post-quantum key exchange **THEN** check the negotiated group against `X25519MLKEM768` and record the blocking terminator.
5. **IF** the review is about a code-level TLS client in an application **THEN** the trust branch is the entry point; negotiation is secondary.
6. **IF** the estate includes a private CA **THEN** scope it explicitly; a private CA trusted everywhere turns one compromise into universal interception.
7. **IF** the target is an mTLS service mesh **THEN** record both directions; client-certificate verification is a separate trust decision from server verification.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `tls-and-pki-attacks-configuration-weaknesses` | [`tls-and-pki-attacks-configuration-weaknesses`](../tls-and-pki-attacks-configuration-weaknesses/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `tls-and-pki-attacks-certificate-validation-gaps` | [`tls-and-pki-attacks-certificate-validation-gaps`](../tls-and-pki-attacks-certificate-validation-gaps/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Capture the negotiation.** Protocol version, cipher suite, key-exchange group, and certificate chain from the actual endpoint. Configuration files lie; a handshake does not.
2. **Enumerate the trust decisions.** Every place a certificate is verified: browsers (out of scope), application clients, service mesh sidecars, and machine-to-machine callers. Each has its own store and its own failure mode.
3. **Choose the branch.** Negotiation, trust, or lifecycle. For lifecycle, compute the renewal cadence the estate can sustain against the SC-081v3 schedule.
4. **Define the baseline-vs-probe differential.** Baseline: a handshake against a known-good endpoint records protocol, suite, group, and chain length. Probe: the same handshake with a legacy client profile or a hybrid group offered, which shows what the server falls back to.
5. **Name the stop condition.** Stop at the first negotiated value that violates the floor, or the first verification path that accepts a chain it should reject. Do not perform interception testing against production users.
6. **State the proof.** Report the negotiated tuple, the chain, the verification code path, and the deadline that makes it urgent. If everything meets the floor and renewals are automated, record `Verified Safe` with the evidence.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `ssl_protocols TLSv1 TLSv1.1 TLSv1.2` | Protocol floor below current guidance, so downgrade is available | nginx, HAProxy, Apache configs |
| A certificate with 398 days of validity issued after March 2026 | Not compliant with the SC-081v3 200-day maximum, so the renewal process is unmanaged | Public TLS endpoints |
| `verify=False` or `CERT_NONE` in a client | Verification disabled, which is the trust branch | Python `requests`, `ssl` contexts |
| `X25519MLKEM768` negotiated on a TLS 1.3 handshake | Key exchange is post-quantum ready at that hop | BoringSSL, OpenSSL 3.5+, Cloudflare origins |
| A trust store containing an internal CA | Every certificate that CA issues is trusted by this client, which is a broad grant | Application bundles, sidecar stores |
| `ssl_ecdh_curve` set explicitly to a classical list | A manual allowlist overriding the library default, which blocks hybrid negotiation | Terminator configs |

## Worked Contrast

**Vulnerable: client that disables verification, server with a legacy floor**

```python
# The client accepts any certificate, so the server's configuration is irrelevant:
# interception needs no certificate forgery at all.
import requests

def call_api(url: str) -> dict:
    return requests.get(url, verify=False, timeout=10).json()   # no trust decision
```

```nginx
# Server still offers TLS 1.0 and 1.1 and a static-RSA suite.
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers AES128-SHA:RC4-SHA:HIGH:!aNULL;
```

**Hardened: verification against the system store with a pinned CA, and a modern floor**

```python
# Verification on, with an explicit CA bundle for the private PKI and hostname
# checking left enabled; no global disable switch in the code path.
import requests

def call_api(url: str) -> dict:
    return requests.get(url, verify="/etc/ssl/private-ca.pem", timeout=10).json()
```

```nginx
# TLS 1.2 floor, AEAD-only suites, and no explicit curve allowlist so the library
# default (which includes the hybrid group) applies.
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
```

**Why this matters:** The left client performs no trust decision, so every other control on the connection is decorative, and the left server offers protocols and suites that a network attacker can steer toward. The right pair restores the trust decision with an explicit CA scope and moves the server to a floor where the negotiated suite is an AEAD with forward secrecy.

## When It Is NOT This Issue

- **TLS 1.0 on a device with no upgrade path, isolated behind a terminator that enforces TLS 1.2+.** The internal hop is a documented exception with its own compensating control.
- **A short-lived internal certificate with a private CA.** Validity rules for public trust do not apply; the finding would be about the CA's scope.
- **A certificate with 397 days of validity issued before 15 March 2026.** The SC-081v3 limits apply to certificates issued on or after each date; existing certificates keep their validity.
- **Pinning implemented in a mobile app that also ships a backup pin.** That is correct practice, not a fragility finding.
- **A self-signed certificate on a loopback-only development service.** Not reachable and not trusted elsewhere.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `tls-and-pki-attacks` based solely on surface keywords (`TLS version`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `tls-and-pki-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: tls-and-pki-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-326`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`tls-and-pki-attacks-configuration-weaknesses`](../tls-and-pki-attacks-configuration-weaknesses/SKILL.md) - Cryptography Attacks (leaf)
- [`tls-and-pki-attacks-certificate-validation-gaps`](../tls-and-pki-attacks-certificate-validation-gaps/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `tls-and-pki-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-326`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 28 |
| Distinct dataset sources | 13 |
| Top sources | OffsecCyber (15), CYBER_CPT/blackhills (2), cyber-security/security-code (1), SecEval/attck (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
