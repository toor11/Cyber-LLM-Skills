---
name: saml-assertion-attacks-signature-wrapping
description: SAML XML signature wrapping. Covers XSW variants that relocate the signed assertion while injecting a forged one, including namespace and comment tricks per parser. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["saml xsw", "signature wrapping", "xsw attack", "xml signature wrapping"]
cwe: [CWE-347]
owasp: [A07:2021]
attack: [T1606]
capec: [CAPEC-196]
related: [saml-assertion-attacks, saml-assertion-attacks-assertion-forgery, sql-injection, cross-site-scripting]
parent: saml-assertion-attacks
---

# SAML Assertion Attacks Signature Wrapping - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Signature wrapping keeps a genuinely valid signature in the document but changes which element the service provider's claim extractor selects. By injecting a forged Assertion and relocating the original signed one into a wrapper position such as ds:Object, samlp:Extensions, or a nested Assertion, the signature library still resolves a valid Reference while the business logic returns the forged element by document position or by a getElementById that matches a duplicated ID. The decision point is the mismatch between the node the ds:Reference resolved and the node handed to the application. Because the signature over the relocated original still verifies byte for byte, the attacker authenticates as a forged Subject without ever forging a signature.

- **Precondition chain:** the service provider validates a signature that is present and valid somewhere in the document, claim extraction selects an element by position or by an ID that can be duplicated, and no check binds the consumed element's identity to the node the signature Reference resolved.
- **Readable differential:** a response with the signed Assertion in its canonical position versus one where a forged Assertion is injected and the signed one is relocated; the wrapped variant authenticating as the forged Subject proves selection and verification disagree, and it reverts once extraction is pinned to the verified node.
- **Empirical grounding:** CVE-2025-25291 and CVE-2025-25292 (ruby-saml) are namespace and DOCTYPE parser-differential wrapping bugs where the verified element differed from the parsed one; CWE-347 falls under OWASP Top 10:2025 A07:2025.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as signature wrapping **THEN** start at parent class [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) first
2. **IF** claim extraction selects the Assertion by document position **THEN** inject a forged Assertion before the signed one and compare which Subject the service provider consumes
3. **IF** extraction resolves an element by getElementById or an ID attribute **THEN** duplicate the signed element's ID on the forged node, as in the CVE-2025-25291 class, and observe which node wins
4. **IF** the signature library and the claim reader handle namespaces differently **THEN** target the namespace parser differential of CVE-2025-25292 specifically
5. **IF** the signed assertion is encrypted **THEN** confirm whether the decrypted element, not the ciphertext, is the node the Reference binds to
6. **IF** only unsigned acceptance or replay is in play rather than relocation **THEN** switch to [`saml-assertion-attacks-assertion-forgery`](../saml-assertion-attacks-assertion-forgery/SKILL.md) (1 hop)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
8. **IF** extraction is pinned to the node the signature Reference resolved **THEN** STOP and classify as a verified non-finding for CWE-347

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The signature is absent rather than relocated | [`saml-assertion-attacks-assertion-forgery`](../saml-assertion-attacks-assertion-forgery/SKILL.md) | With no valid signature to wrap, the invariant is acceptance of unsigned input, not element selection |
| The service provider parser expands a DOCTYPE while resolving the wrapped structure | [`xxe`](../xxe/SKILL.md) | Entity expansion is a separate XML parsing weakness from signature wrapping |
| A downstream role is taken from a wrapped AttributeStatement | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Even a wrapping-resistant service provider can over-grant if attributes are not re-scoped |
| Need parent class methodology | [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the Reference resolver and the claim selector.** In the service provider code, find how the ds:Reference URI maps to a node during verification and, separately, how the application picks the Assertion it trusts, by first match, XPath, or getElementById.
2. **Classify the selection mechanism.** Position-based, XPath-based, and ID-based selectors each wrap differently, so record which one the service provider uses because it dictates the wrapping layout.
3. **Baseline the canonical response.** Capture the untouched signed response, the signed Assertion's ID, and the authenticated Subject for a low-privilege account.
4. **Build the differential by relocation, not by resigning.** Inject a forged Assertion and move the original signed element to a wrapper position while keeping its signature byte for byte valid, then compare which Subject the service provider consumes.
5. **Iterate variants against the observed selector.** If selection is position-based, try ordering variants; if ID-based, duplicate the signed ID onto the forged node; stop at the first layout that flips the consumed Subject.
6. **Stop condition.** Stop when (a) a relocated-signature response authenticates as the forged Subject while the signature still validates, (b) every wrapping variant is rejected or ignored, or (c) advancing needs a real identity-provider key. Case (a) confirms wrapping, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a session for the forged Subject together with evidence that the signature over the relocated original still verified, plus the selector line that returns a different node than the Reference resolved. A forged element that is accepted but ignored is not proof.
8. **Close with the structural fix.** Make verification return the exact signed node and have the application consume claims only from that returned node, reject documents with more than one Assertion or duplicate IDs, and schema-validate element position; verify by replaying each wrapping variant against the patched service provider.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A forged Assertion present alongside a validly signed one that has been relocated | Proves classic XML signature wrapping, where the signature verifies while a different element is consumed on any wrapping-vulnerable service provider |
| Two elements sharing the same ID attribute value with only one signed | Proves ID-based selection can be hijacked, the CVE-2025-25291 class, on getElementById-style service provider resolvers |
| Namespace prefixes rebound between the signed element and the consumed element | Proves the CVE-2025-25292 namespace parser differential on libraries that canonicalise and parse differently |
| The original Signature wrapping the forged Assertion inside its ds:Object or Extensions | Proves a wrapper position the validator ignores but the reader honours; document-order selectors |
| Claim extraction using getElementsByTagName index zero or a non-anchored XPath | Proves position-based selection that ordering can flip; service providers without Reference pinning |
| The verification result not tied to the node handed to business logic | Proves the time-of-check to time-of-use gap at the core of wrapping; any service provider that verifies then re-queries |

## Worked Contrast

**Vulnerable pattern:**

```python
def extract_subject(doc):
    # The signature validates somewhere in the document; the reader then takes
    # the first assertion by position, which a wrapped or injected one can occupy.
    if not signature_valid(doc):
        raise ValueError("signature invalid")
    first = doc.findall(".//{*}Assertion")[0]
    return first.find(".//{*}NameID").text
```

**Hardened pattern:**

```python
def extract_subject(doc):
    signed_node = verify_and_return_signed_node(doc)   # the node the Reference covered
    if signed_node is None or signed_node.tag.split("}")[-1] != "Assertion":
        raise ValueError("no signed assertion")
    if len(doc.findall(".//{*}Assertion")) != 1:
        raise ValueError("multiple assertions rejected")
    if duplicate_ids(doc):
        raise ValueError("duplicate ID attributes rejected")
    return signed_node.find(".//{*}NameID").text
```

**Why this matters:** The fix consumes the NameID from the node the signature Reference actually covered and refuses documents with more than one Assertion or duplicate IDs, so relocating or injecting an element cannot change the selected Subject. Selection and verification are bound to the same node, closing the wrapping gap.

## When It Is NOT This Issue

- **Forged element accepted but never read:** many service providers tolerate extra XML without consuming it, so a wrapped assertion that does not change the session Subject is not a finding.
- **Single-assertion response rejected on tampering:** if editing the signed element invalidates the signature and the service provider rejects it, verification is working.
- **Unsigned-response acceptance:** that is assertion forgery, a different invariant; wrapping requires a genuinely valid signature to relocate.
- **ID duplication rejected by schema:** a service provider that refuses duplicate ID attributes defeats ID-based wrapping; record it as the compensating control.
- **Lab service provider trusting any certificate:** a staging trust-all configuration is not a wrapping vulnerability.
- **Attribute over-grant on a correctly selected assertion:** the right Subject with the wrong role is authorization scoping, not wrapping.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `saml-assertion-attacks-signature-wrapping` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `saml-assertion-attacks-signature-wrapping` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: saml-assertion-attacks-signature-wrapping
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-347 | Mapping: T1606]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) - Web and Application (core)
- [`saml-assertion-attacks-assertion-forgery`](../saml-assertion-attacks-assertion-forgery/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `saml-assertion-attacks-signature-wrapping` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, T1606`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/go_exploitdb (2), CYBER_CPT/osv (2), OffsecCyber (1), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
