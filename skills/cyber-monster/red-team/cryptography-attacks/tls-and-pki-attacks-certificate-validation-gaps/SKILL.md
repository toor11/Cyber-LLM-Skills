---
name: tls-and-pki-attacks-certificate-validation-gaps
description: Certificate validation gaps. Covers missing chain validation, hostname check gaps, pinning bypass prerequisites and custom trust stores. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["certificate validation bypass", "pinning gap", "chain validation"]
cwe: [CWE-326]
owasp: []
attack: []
capec: [CAPEC-94]
related: [tls-and-pki-attacks, tls-and-pki-attacks-configuration-weaknesses, classical-and-covert-encoding, symmetric-cipher-attacks]
parent: tls-and-pki-attacks
---

# TLS and PKI Attacks Certificate Validation Gaps - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Validation gaps are code defects in the trust decision, and they are more common than protocol weaknesses because every HTTP client, every SDK, and every internal RPC call makes one. The direct gap is a disabled verification flag: `verify=False`, `InsecureSkipVerify: true`, an empty `X509TrustManager`, or a `HostnameVerifier` that returns true. The subtler gaps are partial checks: a client that validates the chain but not the hostname, so any certificate from a trusted CA works for any host; a hostname check that only compares the CN and ignores subject alternative names; a pinning implementation that compares a subject string instead of the SPKI hash, so a reissued certificate with the same subject passes; and a custom `TrustManager` that delegates to the default for some chains but accepts others. Time is another axis: a client that does not check validity dates, or one that checks them against a local clock the attacker can influence. The precondition is an attacker able to present a certificate, which on a hostile network is anyone, and the proof is a client that completes a handshake to a certificate it should reject.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** verification is disabled by a flag or an overridden trust manager **THEN** that is the finding; the only remaining question is reachability from a hostile network position.
2. **IF** the chain is validated but the hostname is not **THEN** the finding is hostname binding, and the proof is a valid certificate for a different name being accepted.
3. **IF** pinning compares a subject, an issuer, or a serial rather than the SPKI **THEN** the pin is ineffective against reissue; state which field is compared.
4. **IF** a custom trust store adds a CA **THEN** scope it: every certificate that CA issues is now trusted by this client.
5. **IF** validity dates are not checked, or are checked against a caller-supplied clock **THEN** the branch is time validation.
6. **IF** the client uses a platform default context with no overrides **THEN** the disposition is a control; confirm there is no global monkey-patch elsewhere.
7. **IF** the review is about server-side protocol or suite configuration **THEN** switch to [`tls-and-pki-attacks-configuration-weaknesses`](../tls-and-pki-attacks-configuration-weaknesses/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`tls-and-pki-attacks`](../tls-and-pki-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find every trust decision.** Grep for context construction, verification flags, trust managers, hostname verifiers, and pin checks. A trust decision is any place the code decides whether to accept a peer certificate.
2. **Classify what is checked.** Chain to a root, hostname against SANs, validity window, revocation, key usage, and pin. Each is a separate check and each can be independently missing.
3. **Choose the branch.** Disabled verification, missing hostname binding, ineffective pin, over-broad trust store, or time.
4. **Define the baseline-vs-probe differential.** Baseline: the client connects to the legitimate endpoint and succeeds. Probe: the client connects to a test endpoint presenting a certificate it should reject (wrong name, expired, untrusted root). Success on the probe is the finding.
5. **Name the stop condition.** Stop at the first probe certificate accepted that should have been rejected. Do not attempt interception of real user traffic.
6. **State the proof.** Report the code path, the check that is missing or ineffective, the probe certificate's property (name mismatch, expiry, unknown root), and the fix. If every probe is rejected, record `Verified Safe` with the checks that fired.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `verify=False` in an HTTP client call | Verification disabled entirely, so any certificate is accepted | Python `requests`, `httpx` |
| `InsecureSkipVerify: true` in a TLS config | The same defect in Go, and it is often set to make a test pass | Go `crypto/tls`, Kubernetes clients |
| `HostnameVerifier { _, _ -> true }` | Chain checked, name not, so any CA-issued certificate works for any host | Android, Java `HttpsURLConnection` |
| `checkServerTrusted` overridden to return without validating | Empty trust manager, the classic Android defect | Custom `X509TrustManager` |
| A pin compared with `cert.subjectDN` or a serial number | The pin survives reissue, so it does not pin the key | Mobile pinning implementations |
| `ssl.create_default_context()` with no overrides | Platform defaults: chain, hostname, and dates are checked — a control | CPython `ssl`, most SDKs |

## Worked Contrast

**Vulnerable: chain validated but hostname check disabled, and a subject-based pin**

```java
// The trust manager validates the chain, so the code looks careful, but the
// hostname verifier accepts anything and the pin compares the subject string —
// which a reissued certificate for another host can satisfy.
HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
conn.setHostnameVerifier((host, session) -> true);              // no name binding
X509Certificate leaf = (X509Certificate) session.getPeerCertificates()[0];
if (!leaf.getSubjectDN().getName().contains("CN=api.example.com")) {  // subject pin
    throw new IOException("pin mismatch");
}
```

**Hardened: default hostname verification and a pin over the public key**

```java
// The default verifier checks SANs against the host, and the pin is a SHA-256 of
// the SPKI so a reissued certificate with a different key fails.
HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
conn.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());

X509Certificate leaf = (X509Certificate) conn.getPeerCertificates()[0];
byte[] spki = MessageDigest.getInstance("SHA-256").digest(leaf.getPublicKey().getEncoded());
if (!MessageDigest.isEqual(spki, EXPECTED_SPKI_SHA256)) {
    throw new IOException("spki pin mismatch");
}
```

**Why this matters:** The left code checks that *some* trusted chain exists and that a subject string appears somewhere, so an attacker with any CA-issued certificate for a name they control passes both checks. The right code binds the certificate to the hostname through SAN comparison and pins the actual public key, so a different key cannot be substituted even with a valid chain.

## When It Is NOT This Issue

- **`verify=False` in a test helper that is never used in production code paths.** Confirm the import graph before filing.
- **A custom trust store that adds exactly one internal CA and is used only for internal hostnames.** The grant is scoped; the finding would need it applied to external calls.
- **Pinning with a documented backup pin and a rotation plan.** Multiple pins are correct practice.
- **A client that skips revocation checking but enforces short-lived certificates.** The lifetime is a compensating control; state both.
- **A hostname check that compares SANs and falls back to CN for legacy certificates.** The modern path is enforced; the fallback is a compatibility note.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `tls-and-pki-attacks-certificate-validation-gaps` based solely on surface keywords (`hostname check`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `tls-and-pki-attacks-certificate-validation-gaps` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: tls-and-pki-attacks-certificate-validation-gaps
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-326`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`tls-and-pki-attacks`](../tls-and-pki-attacks/SKILL.md) - Cryptography Attacks (core)
- [`tls-and-pki-attacks-configuration-weaknesses`](../tls-and-pki-attacks-configuration-weaknesses/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `tls-and-pki-attacks-certificate-validation-gaps` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-326`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/github_security_md (5), CYBER_CPT/expku (1), CYBER_CPT/osv (1), CYBER_CPT/oxdf (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
