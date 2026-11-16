---
name: saml-assertion-attacks-assertion-forgery
description: SAML assertion forgery and replay. Covers unsigned assertion acceptance, comment-based signature bypass, recipient and audience gaps, and replay of captured assertions. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["saml forgery", "assertion replay", "unsigned saml", "saml bypass"]
cwe: [CWE-347]
owasp: [A07:2021]
attack: [T1606]
capec: [CAPEC-196]
related: [saml-assertion-attacks, saml-assertion-attacks-signature-wrapping, sql-injection, cross-site-scripting]
parent: saml-assertion-attacks
---

# SAML Assertion Attacks Assertion Forgery - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Assertion forgery exploits service providers that extract and trust claims without a binding signature over them. In the simplest case the service provider accepts a response with no ds:Signature at all, so a hand-built assertion authenticates. A subtler case is a canonicalisation-versus-read text split, where a comment or null inserted into NameID means the canonicaliser signs one string while the reader returns a truncated one, turning admin followed by a comment into admin. A third case is replay, where missing NotOnOrAfter, Recipient, Audience, or InResponseTo checks let a captured assertion be reused. The decision point is whether every consumed claim is covered by a verified signature and whether SubjectConfirmation is enforced, and the attacker authenticates as an arbitrary or replayed Subject without a valid signature over the forged element.

- **Precondition chain:** the service provider consumes a NameID or attributes not all covered by a verified signature, or it canonicalises text differently from how it reads it, or it omits NotOnOrAfter, Recipient, Audience, and InResponseTo checks, and it maps the resulting Subject to a session.
- **Readable differential:** a genuinely signed assertion versus a response with the signature removed or a comment inserted into NameID; acceptance of the stripped or comment-split identity proves claims are trusted without signature coverage, and it reverts once a signature over the exact consumed text and the Conditions are enforced.
- **Empirical grounding:** CWE-347 and OWASP Top 10:2025 A07:2025 anchor unsigned-acceptance and replay; the ruby-saml advisories CVE-2025-25291 and CVE-2025-25292 are the signed cousin where verified bytes and consumed text diverged.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as forgery or replay **THEN** start at parent class [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) first
2. **IF** the response carries no ds:Signature element **THEN** test unsigned acceptance directly, since a resulting session is immediate confirmation
3. **IF** the NameID may contain a comment or null byte **THEN** probe comment-based text truncation where the canonicaliser and the reader disagree
4. **IF** Conditions lack NotOnOrAfter, Recipient, or Audience enforcement **THEN** test replay of a captured assertion and cross-service-provider recipient reuse separately
5. **IF** a valid signature is present but covers a different element **THEN** switch to [`saml-assertion-attacks-signature-wrapping`](../saml-assertion-attacks-signature-wrapping/SKILL.md) (1 hop)
6. **IF** single sign-on issues a bearer token afterwards **THEN** token replay becomes a lifecycle question; see [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) (1 hop)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
8. **IF** every consumed claim is signature-covered and Conditions are enforced one-time **THEN** STOP and classify as a verified non-finding for CWE-347

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A valid signature exists but is relocated | [`saml-assertion-attacks-signature-wrapping`](../saml-assertion-attacks-signature-wrapping/SKILL.md) | With a valid signature to move, the invariant becomes element selection rather than signature absence |
| A replayed assertion rides a post-single-sign-on session token | [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) | Reuse after logout or rotation is a revocation invariant, not assertion coverage |
| A forged attribute grants extra roles | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Trusting unsigned attributes for authorization is an access-control scoping failure |
| Need parent class methodology | [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate where claims are read and where, if anywhere, a signature is required.** Find the code that extracts NameID, Conditions, and attributes, and confirm whether a ds:Signature is mandatory and whose bytes it must cover.
2. **Classify the forgery surface.** Decide whether the opportunity is unsigned acceptance, a canonicalisation-versus-read text split, or a missing SubjectConfirmation or Conditions check, because each is tested differently.
3. **Baseline a signed login.** Record the accepted signed response, the NameID consumed, the NotOnOrAfter value, and the Recipient and Audience the service provider expects.
4. **Define the baseline-versus-probe differential.** Remove the signature, inject a comment into NameID, or resubmit past the window, changing one variable at a time, and compare the authenticated Subject or the accept and reject outcome against the baseline.
5. **Separate text truncation from pure unsigned acceptance.** A comment-split NameID that logs in as a truncated identity is a different control failure than a wholly unsigned response, so name which one fired.
6. **Stop condition.** Stop when (a) a response with no valid signature over the consumed claims, or a replayed one, yields a session, (b) every such response is rejected, or (c) advancing requires a legitimate signing key or a live victim assertion. Case (a) confirms forgery or replay, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a session for a Subject whose claims were not signature-covered, or a successful replay past NotOnOrAfter, with the exact missing check named. A tolerated but ignored unsigned element is not proof.
8. **Close with the structural fix.** Require a signature over the consumed Assertion, canonicalise and read the same text so a comment cannot truncate it, and enforce NotOnOrAfter, Recipient, Audience, and one-time InResponseTo; verify by replaying each probe against the patched service provider.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A service provider establishing a session from a SAMLResponse containing no ds:Signature | Proves signature verification is optional, so a hand-built assertion authenticates; permissive SAML service providers |
| A comment or null inside NameID changing the identity the reader returns | Proves a canonicalisation-versus-read text split of the ruby-saml comment class on libraries that strip comments before signing but not before reading |
| Missing NotOnOrAfter enforcement on the Assertion or SubjectConfirmationData | Proves captured assertions replay indefinitely; service providers that skip Conditions |
| A Recipient or Audience not matched to this service provider | Proves an assertion minted for another service provider is accepted here; federations without audience restriction |
| An InResponseTo not matched to a pending AuthnRequest | Proves unsolicited-response acceptance that enables replay; service-provider-initiated flows missing request binding |
| A signature present but covering an element other than the consumed one | Proves claims are trusted without coverage even when a signature exists, the boundary toward wrapping |

## Worked Contrast

**Vulnerable pattern:**

```python
def login(saml_response):
    doc = etree.fromstring(saml_response)
    # No signature requirement: if a NameID is present, the user is logged in.
    name_id = doc.find(".//{*}Subject/{*}NameID").text
    return create_session(name_id)
```

**Hardened pattern:**

```python
def login(saml_response):
    doc = etree.fromstring(saml_response, parser=hardened_parser())
    signed = verify_signature_return_node(doc)
    if signed is None:
        raise ValueError("a signature over the assertion is required")
    name_id_el = signed.find(".//{*}Subject/{*}NameID")
    name_id = "".join(name_id_el.itertext())   # read the exact text the signature covers
    conditions = signed.find(".//{*}Conditions")
    if not conditions_valid(conditions, audience="https://sp.example/acs"):
        raise ValueError("conditions failed: window, recipient, or audience")
    if not consume_in_response_to(doc):
        raise ValueError("unsolicited or replayed response")
    return create_session(name_id)
```

**Why this matters:** The fix refuses any response whose consumed Assertion is not covered by a verified signature, reads the full NameID text so a comment cannot truncate it, and enforces the validity window, audience, and one-time InResponseTo. Unsigned acceptance, comment splitting, and replay all close because coverage and Conditions become mandatory.

## When It Is NOT This Issue

- **Unsigned element present but ignored:** a service provider that parses but never trusts an unsigned block is not forgeable, so confirm the Subject actually comes from it.
- **Replay inside the window by the same user:** a single in-window reuse is normal single-sign-on behaviour, not a replay finding.
- **Comment in NameID rejected or read whole:** if the service provider reads the complete text including the comment-delimited portion, the truncation split does not occur.
- **Audience correctly restricted:** an assertion minted for another service provider being rejected here is the control working.
- **Staging identity provider with signing disabled:** a lab configuration that omits signatures is an artefact, not a production bypass.
- **Correctly signed assertion with a stale clock:** a NotOnOrAfter failure caused by server clock skew is an operational issue, not attacker-controlled forgery.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `saml-assertion-attacks-assertion-forgery` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `saml-assertion-attacks-assertion-forgery` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: saml-assertion-attacks-assertion-forgery
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-347 | Mapping: T1606]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) - Web and Application (core)
- [`saml-assertion-attacks-signature-wrapping`](../saml-assertion-attacks-signature-wrapping/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `saml-assertion-attacks-assertion-forgery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-347, T1606`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/osv (2), CYBER_CPT/blackhills (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
