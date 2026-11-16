---
name: saml-assertion-attacks
description: "Exploits SAML SSO: XML signature wrapping, assertion replay, comment and namespace confusion, weak or absent signature validation, and XSW variants against service providers. Use when an application consumes SAML assertions from an identity provider."
family: web-and-application
tier: core
triggers: ["saml", "saml attack", "signature wrapping", "xsw", "assertion replay", "sso bypass", "xml signature"]
cwe: [CWE-347]
owasp: [A07:2021]
attack: [T1606]
capec: [CAPEC-196]
related: [saml-assertion-attacks-signature-wrapping, saml-assertion-attacks-assertion-forgery, sql-injection, cross-site-scripting]
---

# SAML Assertion Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

A SAML service provider consumes a SAMLResponse that carries a signed Assertion, and the invariant is that the bytes the signature verifies must be the exact bytes whose Subject, Conditions, and AttributeStatement the application then consumes. The break is a parser differential: the XML signature is validated by one parser or canonicalisation while the claims are read by another, so a valid signature over an unprivileged element can be reused while a smuggled Assertion supplies a different NameID. Related failures are accepting a response with no signature at all, resolving the signature Reference to an element other than the consumed one, and trusting attributes before the signature result is enforced. The decision point is the Reference resolution and the identity of the element handed downstream, and a successful attacker authenticates as an arbitrary Subject.

- **Precondition chain:** the service provider accepts an externally supplied SAMLResponse, signature verification and claim extraction traverse the document independently through two parsers or an unpinned Reference, and the extracted Subject is mapped to a session without rechecking which element was actually signed.
- **Readable differential:** a response where the signed element and the consumed element are identical versus one where a second Assertion is injected so a different Subject is read; acceptance of the second proves the verified bytes and the consumed claims diverge, and it reverts once a single canonical parser reads claims only from the signed element.
- **Empirical grounding:** CVE-2025-25291 and CVE-2025-25292 (ruby-saml) are parser-differential signature-wrapping flaws where a signature verified through one parser covered claims read through another, enabling account takeover; CWE-347 maps to OWASP Top 10:2025 A07:2025.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves relocating or wrapping the signed element **THEN** switch to [`saml-assertion-attacks-signature-wrapping`](../saml-assertion-attacks-signature-wrapping/SKILL.md) (1 hop)
2. **IF** the target specifically involves unsigned acceptance, comment truncation, or replay **THEN** switch to [`saml-assertion-attacks-assertion-forgery`](../saml-assertion-attacks-assertion-forgery/SKILL.md) (1 hop)
3. **IF** signature verification and claim extraction use two different XML parsers or libraries **THEN** treat the parser differential as the primary finding, as in CVE-2025-25291 and CVE-2025-25292, before testing wrapping layouts
4. **IF** the SAMLResponse contains an EncryptedAssertion **THEN** confirm decryption happens before verification and that the decrypted element is the one the signature covers
5. **IF** the service provider parser resolves a DOCTYPE or external entities **THEN** also read [`xxe`](../xxe/SKILL.md) because the assertion endpoint is an XML parsing sink in its own right
6. **IF** the session after single sign-on is a self-contained bearer token **THEN** that is a token-format question; see [`jwt-attacks`](../jwt-attacks/SKILL.md) (1 hop)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
8. **IF** the service provider verifies one canonical parse and reads claims only from the signed element **THEN** STOP and classify as a verified non-finding for CWE-347

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The service provider parser processes a DOCTYPE or external entity | [`xxe`](../xxe/SKILL.md) | The assertion endpoint becomes an XML parsing sink, a confidentiality invariant distinct from signature verification |
| The session after single sign-on is a self-contained signed token | [`jwt-attacks`](../jwt-attacks/SKILL.md) | Verification shifts to JWS algorithm and key handling rather than XML canonicalisation |
| Downstream authorization trusts an attribute without rechecking identity | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Even a correctly signed assertion can over-grant if attributes are not scoped |
| Target matches `saml-assertion-attacks-signature-wrapping` | [`saml-assertion-attacks-signature-wrapping`](../saml-assertion-attacks-signature-wrapping/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `saml-assertion-attacks-assertion-forgery` | [`saml-assertion-attacks-assertion-forgery`](../saml-assertion-attacks-assertion-forgery/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the verification path and the consumption path separately.** Find the library call that validates the XML signature and, independently, the code that reads NameID, Conditions, and AttributeStatement, and note whether both operate on one shared parsed document.
2. **Classify the verification model from the code.** Determine whether a signature is required at all, whether the ds:Reference URI is pinned to the verified element, and whether the same parser and canonicalisation feed both verification and extraction.
3. **Capture a legitimate baseline response.** Record the accepted SAMLResponse, the signed element's ID, the NameID consumed, and the resulting session subject for a low-privilege test account.
4. **Define the baseline-versus-probe differential.** Produce a response where the consumed Subject differs from the signed element, a second Assertion, a relocated signature, or an unsigned twin, and compare the resulting session subject against the baseline.
5. **Decide the branch from observed parser behaviour.** If removing the signature still authenticates, the forgery branch is live; if only a wrapped or injected element changes the Subject, the parser-differential branch is live; let the response select the branch.
6. **Stop condition.** Stop when (a) a response whose signed bytes and consumed claims diverge yields a session for a Subject the signature never covered, (b) every such response is rejected identically, or (c) proceeding would require a real identity-provider key or another user's live assertion. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a session established for a Subject whose claims were not inside the signed, verified element, shown by the server mapping the smuggled NameID, plus the code location where verification and extraction read different nodes. An XML validation warning alone is not proof.
8. **Close with the structural fix.** Use one hardened XML library for both steps, resolve the signature Reference to a single node, read claims only from that verified element, forbid DOCTYPE and multiple Assertions, and enforce Conditions and one-time use; verify by replaying each probe against the patched service provider.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A signature verified by one XML library while claims are read by another | Proves a parser differential of the CVE-2025-25291 and CVE-2025-25292 class, so the signed bytes and the consumed NameID can diverge on any multi-parser service provider |
| A ds:Reference URI resolving to an element other than the consumed Assertion | Proves the signature does not cover the element whose Subject is used; XML-DSig service providers |
| A service provider accepting a SAMLResponse with no ds:Signature element present | Proves signature verification is optional, so any crafted assertion authenticates; misconfigured SAML service providers |
| Two Assertion elements in one response with only one signed | Proves assertion injection where the unsigned twin supplies the Subject; the classic signature-wrapping surface |
| A DOCTYPE or external entity accepted by the service provider's XML parser | Proves the endpoint is also an XXE sink independent of signatures; libxml-backed SAML stacks |
| A NameID consumed without a NotOnOrAfter or Recipient check | Proves replay and audience gaps even when the signature is valid; service providers lacking SubjectConfirmation enforcement |
| An AttributeStatement read before the signature result is enforced | Proves a time-of-check ordering flaw that lets unsigned attributes flow downstream; service providers that parse then verify |

## Worked Contrast

**Vulnerable pattern:**

```python
def authenticate(saml_response_xml):
    doc = etree.fromstring(saml_response_xml)
    # The signature is checked for validity, but the Subject is read from the
    # whole document, so an injected unsigned Assertion can supply a NameID.
    if not signature_is_valid(doc):
        raise ValueError("bad signature")
    name_id = doc.find(".//{*}Subject/{*}NameID").text
    return create_session(name_id)
```

**Hardened pattern:**

```python
def authenticate(saml_response_xml):
    if b"<!DOCTYPE" in saml_response_xml:
        raise ValueError("DOCTYPE not allowed")
    doc = etree.fromstring(saml_response_xml, parser=hardened_parser())
    assertions = doc.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    if len(assertions) != 1:
        raise ValueError("exactly one assertion required")
    signed = verify_signature_return_node(doc)   # the element actually covered
    if signed is not assertions[0]:
        raise ValueError("signed element is not the consumed assertion")
    name_id = signed.find(".//{*}Subject/{*}NameID").text
    enforce_conditions(signed)                   # NotOnOrAfter, Audience, one-time
    return create_session(name_id)
```

**Why this matters:** The hardened version parses once with a DOCTYPE-free hardened parser, requires exactly one Assertion, and reads the NameID only from the element the signature actually covered, so the verified bytes and the consumed claims are identical. That closes the parser-differential and assertion-injection paths a validity-only check leaves open.

## When It Is NOT This Issue

- **Signature invalid and response rejected:** a service provider returning an error for a tampered signature is doing its job, and a 500 on malformed XML is not an authentication bypass.
- **Self-signed test identity provider in staging:** a lab service provider configured to trust any certificate is a configuration artefact, not a production signature-verification flaw.
- **Replay inside the NotOnOrAfter window by the legitimate user:** reusing your own fresh assertion once is normal, while impact requires a different Subject or a past-window reuse.
- **Encrypted assertion that fails to decrypt:** a decryption error is not a signature bypass; confirm the decrypted element is the one verified before claiming a finding.
- **Attribute over-grant with a correct signature:** if the identity is right but a role attribute is too broad, that is an authorization-scoping issue, not assertion forgery.
- **Metadata endpoint exposure:** reading the service provider's published SAML metadata is expected and is not an attack on assertion verification.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `saml-assertion-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `saml-assertion-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: saml-assertion-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-347 | Mapping: T1606]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`saml-assertion-attacks-signature-wrapping`](../saml-assertion-attacks-signature-wrapping/SKILL.md) - Web and Application (leaf)
- [`saml-assertion-attacks-assertion-forgery`](../saml-assertion-attacks-assertion-forgery/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `saml-assertion-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, T1606`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/nuclei_templates (3), OffsecCyber (2), CYBER_CPT/gh_security_lab (2), CYBER_CPT/awesome_web_security (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
