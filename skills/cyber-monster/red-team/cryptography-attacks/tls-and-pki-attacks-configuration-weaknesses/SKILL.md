---
name: tls-and-pki-attacks-configuration-weaknesses
description: TLS configuration weaknesses. Covers deprecated protocol versions, weak cipher suites, missing forward secrecy and misconfigured renegotiation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["tls misconfiguration", "weak cipher", "no forward secrecy", "ssl scan"]
cwe: [CWE-326]
owasp: []
attack: []
capec: [CAPEC-94]
related: [tls-and-pki-attacks, tls-and-pki-attacks-certificate-validation-gaps, classical-and-covert-encoding, symmetric-cipher-attacks]
parent: tls-and-pki-attacks
---

# TLS and PKI Attacks Configuration Weaknesses - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Configuration weaknesses are the negotiated surface: which protocols, suites, curves, and extensions a server will accept from a client that offers the worst. The failures are specific and enumerable. A protocol floor below TLS 1.2 admits downgrade and legacy padding behaviour. A suite list containing CBC-mode suites exposes the MAC-then-encrypt constructions that Lucky Thirteen targets, and one containing static RSA key exchange exposes the Bleichenbacher surface. A curve allowlist that names only classical groups blocks the post-quantum hybrid and, in the other direction, an allowlist containing weak or non-standard groups widens the attack surface. Renegotiation left enabled allows a prefix-injection class of attacks against older stacks. Compression left enabled exposes CRIME-style length leaks. Session resumption without ticket rotation concentrates key material. Each of these is visible in a handshake and in the config file, and the review output is a list of negotiated values against a floor rather than a general judgment.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the server completes a TLS 1.0 or 1.1 handshake **THEN** the protocol floor is the finding; report the negotiated version and the client profile that reached it.
2. **IF** any CBC-mode suite is offered **THEN** note the Lucky Thirteen exposure and check whether the stack has the constant-time record-processing fixes.
3. **IF** a static-RSA suite is offered **THEN** add the Bleichenbacher exposure; the RSA operation is decryption, not signing, in that suite.
4. **IF** `ssl_ecdh_curve` or an equivalent allowlist is set **THEN** it overrides the library default and is the most common reason a modern library still negotiates classical groups.
5. **IF** compression or renegotiation is enabled **THEN** those are separate findings with their own proofs.
6. **IF** the client side is the question **THEN** switch to [`tls-and-pki-attacks-certificate-validation-gaps`](../tls-and-pki-attacks-certificate-validation-gaps/SKILL.md).
7. **IF** the endpoint is a load balancer fronting a legacy backend **THEN** record both hops; the front may meet the floor while the back does not.

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

1. **Capture what the server actually accepts.** Enumerate protocols, suites, curves, and extensions with a scanner, not from the config file. Config drift is common and a terminated endpoint may differ from the file.
2. **Compare against a written floor.** Protocol minimum, AEAD-only suites, forward-secret key exchange, no compression, no renegotiation. A floor you cannot quote is not a floor.
3. **Choose the branches that apply.** Protocol, suite, curve, extension. Each gets its own line in the report, because the fixes differ.
4. **Define the baseline-vs-probe differential.** Baseline: a modern client negotiates the strongest available tuple. Probe: a legacy client profile negotiates a weaker one. The weakest tuple the server will accept is the finding, and the modern tuple is the control.
5. **Name the stop condition.** Stop once the weakest accepted protocol and suite are recorded. Do not attempt traffic interception or protocol exploitation.
6. **State the proof.** Report the weakest tuple, the config line or the library default responsible, and the target configuration. If the weakest accepted tuple meets the floor, record `Verified Safe` with the tuple.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `ssl_protocols TLSv1 TLSv1.1` in config | Protocol floor below the current minimum, so legacy handshakes succeed | nginx, Apache, HAProxy |
| A CBC suite in the accepted list | MAC-then-encrypt construction, exposed to Lucky Thirteen if record processing is not constant-time | OpenSSL-backed terminators |
| `AES128-SHA` or any `RSA_WITH` suite | Static RSA key exchange, so the Bleichenbacher surface is reachable | Legacy load balancers, embedded TLS |
| `ssl_ecdh_curve secp256r1` set explicitly | A manual allowlist that blocks the hybrid group regardless of library support | nginx, Envoy, Java `jdk.tls.namedGroups` |
| `ssl_session_tickets on` with a static ticket key | Resumption keys never rotate, so one key compromise decrypts recorded sessions | nginx, custom terminators |
| `TLS_AES_256_GCM_SHA384` with `X25519MLKEM768` negotiated | Meets the modern floor including post-quantum key exchange — the control tuple | TLS 1.3 terminators |

## Worked Contrast

**Vulnerable: legacy protocol floor, CBC and static-RSA suites, static ticket key**

```nginx
# Legacy protocols, CBC and static-RSA suites, and a fixed ticket key: the weakest
# tuple a client can reach is far below any current floor.
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers AES128-SHA:DES-CBC3-SHA:RC4-SHA:HIGH;
ssl_session_tickets on;
ssl_session_ticket_key /etc/nginx/static_ticket.key;
```

**Hardened: TLS 1.2 floor with AEAD-only suites, forward secrecy, rotating tickets**

```nginx
# TLS 1.2 floor, ECDHE with AEAD only, and no static ticket key so tickets rotate
# with the worker lifecycle. No explicit curve allowlist, so the library default
# (including the hybrid group) applies.
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_tickets off;
```

**Why this matters:** The left configuration lets a network attacker steer a client down to a CBC or static-RSA suite where the record layer and the RSA operation have their own known weaknesses, and the fixed ticket key means recorded sessions stay decryptable after a key leak. The right configuration restricts the negotiable surface to forward-secret AEAD suites on a TLS 1.2 floor and removes the long-lived resumption key.

## When It Is NOT This Issue

- **TLS 1.0 on an isolated device hop behind a terminator that enforces the floor.** Document the hop and its compensating control rather than filing it as an endpoint finding.
- **A CBC suite retained for a specific legacy client with a documented deadline.** The exposure is real but bounded; report the client and the date.
- **Session tickets enabled with a per-worker random key.** Rotation happens on restart, which is a defensible trade-off.
- **A curve allowlist that excludes the hybrid because the terminator's library predates it.** That is a migration item with a version dependency, not a misconfiguration.
- **A test endpoint with a deliberately weak configuration.** Confirm it is excluded from the production inventory.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `tls-and-pki-attacks-configuration-weaknesses` based solely on surface keywords (`TLS 1.0`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `tls-and-pki-attacks-configuration-weaknesses` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: tls-and-pki-attacks-configuration-weaknesses
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
- [`tls-and-pki-attacks-certificate-validation-gaps`](../tls-and-pki-attacks-certificate-validation-gaps/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `tls-and-pki-attacks-configuration-weaknesses` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-326`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/expku (3), CYBER_CPT/oxdf (1), CYBER_CPT/github_security_md (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
