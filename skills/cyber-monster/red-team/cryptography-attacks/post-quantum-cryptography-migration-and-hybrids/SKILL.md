---
name: post-quantum-cryptography-migration-and-hybrids
description: "Assesses Post-Quantum Cryptography (PQC) and hybrid KEM/signature deployments (ML-KEM / Kyber, ML-DSA / Dilithium, X25519MLKEM768): harvest-now-decrypt-later inventory, hybrid combiner transcript binding, ciphertext/signature size MTU fragmentation issues, and implementation side channels. Use when auditing PQC readiness or hybrid TLS/VPN designs."
family: cryptography-attacks
tier: core
triggers: ["post quantum cryptography", "ml-kem kyber", "ml-dsa dilithium", "hybrid kem tls", "pqc migration"]
cwe: [CWE-327]
owasp: []
attack: []
capec: []
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
corpus_sparse: true
---

# Post Quantum Cryptography Migration and Hybrids - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Post-quantum migration review has two halves that are often conflated. The first is inventory and timeline: which algorithms in the estate are quantum-vulnerable (RSA, ECDSA, ECDH, DHE, and any Diffie-Hellman over a finite field), where they appear (TLS, code signing, firmware, at-rest envelope keys, document signing), and what deadline binds the organisation. NIST's transition guidance deprecates quantum-vulnerable public-key algorithms after 2030 and disallows them after 2035, with earlier deadlines for high-impact federal systems; CNSA 2.0 imposes a stricter schedule on national-security systems. The second half is the construction: a hybrid key exchange combines a classical share and a post-quantum share so the session is secure if *either* survives, and the combiner must bind both shares and both public keys into the transcript — a hybrid that concatenates shared secrets without binding the public keys is vulnerable to a contribute-then-reveal or a re-encapsulation attack depending on the combiner. TLS 1.3's `X25519MLKEM768` is the deployed instance, negotiated by Chrome by default since Chrome 131 and preferred by Cloudflare for origins that support it, which means the review question for most estates is not "should we" but "which terminator in the path still forces a classical group".

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the task is inventory **THEN** enumerate algorithm usage per terminator and per stored artefact, and map each to a deadline; do not start with a code change.
2. **IF** the task is a hybrid combiner review **THEN** verify that both shared secrets and both public keys are bound into the transcript and into the KDF label, or the hybrid is weaker than its parts.
3. **IF** a TLS terminator advertises only classical groups **THEN** that device is the blocking item; check the documented curve allowlist first, because a manual allowlist overrides a library default.
4. **IF** the estate signs firmware or documents **THEN** the signature migration is separate from the key-exchange migration and usually later; do not merge the two plans.
5. **IF** a "harvest now, decrypt later" exposure exists for long-lived data **THEN** prioritise key establishment over signatures, because confidentiality is the property already at risk.
6. **IF** an embedded or middlebox device cannot be upgraded **THEN** the finding is an architecture item (tunnel, terminate-early, or replace), not a configuration tweak.
7. **IF** the algorithm is a post-quantum signature (ML-DSA, SLH-DSA) **THEN** check signature and key sizes against the protocol's frame limits before recommending it; some legacy protocols cannot carry them.
8. **IF** the hybrid negotiation itself is the question **THEN** work through [`tls-and-pki-attacks`](../tls-and-pki-attacks/SKILL.md) for the handshake and [`ecc-and-diffie-hellman-attacks`](../ecc-and-diffie-hellman-attacks/SKILL.md) for the classical leg's validation.
9. **IF** the post-quantum primitive is a lattice KEM and you need the implementation-level side-channel view **THEN** switch to [`constant-time-and-crypto-side-channel-code-audit`](../constant-time-and-crypto-side-channel-code-audit/SKILL.md) before accepting a validation claim.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Build the inventory with evidence.** For each TLS terminator, capture the negotiated group from a real handshake. For each stored artefact, read the algorithm identifier from the certificate or key metadata. For each signature, read the OID. Inventory without evidence becomes a guess within a week.
2. **Map each item to its binding deadline.** Record which regime applies — general NIST guidance, a federal high-impact system, or CNSA 2.0 — and the corresponding dates. An item with no regime is prioritised by data lifetime instead.
3. **Choose the branch.** Key establishment, signature, or at-rest key wrap. Key establishment is the hybrid-combiner review; signature is a size-and-compatibility review; key wrap is a KMS capability question.
4. **Define the baseline-vs-probe differential.** Baseline: a handshake that negotiates the classical group. Probe: the same client with the hybrid group offered. The differential is the negotiated group name and whether a HelloRetryRequest was required, which tells you if the peer merely tolerates it or actually prefers it.
5. **Name the stop condition.** Stop when every terminator's negotiated group is recorded and every artefact's algorithm is read. Do not attempt to benchmark post-quantum performance against production traffic.
6. **State the proof.** Report the negotiated group per endpoint, the blocking device in each path, the deadline that applies, and the combiner property for any in-house hybrid. If a path already negotiates a hybrid group end to end, record it as migrated with the evidence.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `bssl client -connect host:443 -curves X25519MLKEM768` returns that group | The terminator supports and prefers the hybrid, so this hop is migrated | BoringSSL, Cloudflare-fronted origins |
| ClientHello offering the hybrid but the server selecting `x25519` | The server is classical-only: the blocking item, not the client | Any TLS 1.3 stack |
| An explicit `--curves` or `ssl_ecdh_curve` allowlist in config | A manual allowlist overrides library defaults, which is the most common reason a modern library still negotiates classical | nginx, HAProxy, Envoy, Java `jdk.tls.namedGroups` |
| A certificate with an RSA-2048 or P-256 key | Signature migration is still pending for that endpoint, independent of key exchange | Certificate inventory |
| `hybrid = concat(classical_ss, pq_ss)` with no public keys in the label | A combiner that does not bind both public keys, so the hybrid's security is not the max of its parts | In-house hybrid implementations |
| `ML-KEM-768` in a KEM API call | The primitive is the standardised one (FIPS 203), not a pre-standard Kyber variant, which matters for validation claims | OpenSSL 3.5+, BoringSSL, `liboqs` |

## Worked Contrast

**Vulnerable: hybrid combiner that concatenates secrets without binding the public keys**

```python
# Concatenating the two shared secrets and hashing them looks like a hybrid, but
# nothing binds the two public keys, so a peer can contribute a classical share it
# controls while replaying a recorded PQ share.
def hybrid_secret(classical_ss: bytes, pq_ss: bytes) -> bytes:
    return hashlib.sha256(classical_ss + pq_ss).digest()     # no transcript binding
```

**Hardened: both public keys and both shares inside a labelled transcript hash**

```python
# The KDF input is a transcript that names the protocol, both groups, both public
# keys, and both shared secrets, so neither share can be substituted or replayed.
import hashlib

def hybrid_secret(proto: str, classical_pub: bytes, pq_pub: bytes,
                  classical_ss: bytes, pq_ss: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"hybrid-v1|" + proto.encode() + b"|")
    h.update(len(classical_pub).to_bytes(2, "big") + classical_pub)
    h.update(len(pq_pub).to_bytes(2, "big") + pq_pub)
    h.update(len(classical_ss).to_bytes(2, "big") + classical_ss)
    h.update(len(pq_ss).to_bytes(2, "big") + pq_ss)
    return h.digest()
```

**Why this matters:** The left combiner derives a key from two secrets but never commits to which public keys produced them, so an attacker who controls one leg can force the output while replaying the other, and the "hybrid" degrades to its weakest component. The right combiner commits to the full transcript with explicit lengths, so any substitution changes the derived key and the handshake fails.

## When It Is NOT This Issue

- **A pre-standard Kyber identifier in an old build.** It is a migration item, not a vulnerability, unless the specific variant has a documented break. State which identifier you found.
- **A device that only supports classical groups but sits behind a terminator that does the hybrid.** The hop that matters is migrated; record the internal hop as an inventory item with its own deadline.
- **Large post-quantum signatures failing a legacy frame limit.** That is a compatibility constraint on the migration plan, not a defect in the algorithm.
- **A hybrid used only for signatures.** The combiner argument in this skill is about key establishment; signature hybrids have a different construction and a different proof.
- **No hybrid support at all in a system with a 2031+ decommission date.** The correct output is a dated plan, not a finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `post-quantum-cryptography-migration-and-hybrids` based solely on surface keywords (`ML-KEM-768`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `post-quantum-cryptography-migration-and-hybrids` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: post-quantum-cryptography-migration-and-hybrids
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-327`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `post-quantum-cryptography-migration-and-hybrids` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-327`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
