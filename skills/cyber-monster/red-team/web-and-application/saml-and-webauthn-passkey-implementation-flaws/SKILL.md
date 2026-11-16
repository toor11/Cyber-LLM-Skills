---
name: saml-and-webauthn-passkey-implementation-flaws
description: "Audits WebAuthn / FIDO2 Passkey relying-party implementations: missing `rpIdHash` or `origin` verification, challenge replay/non-binding, `signCount` rollback handling, and backup-eligibility downgrade paths. Use when reviewing passwordless or FIDO2 MFA flows."
family: web-and-application
tier: leaf
triggers: ["webauthn vulnerability", "passkey implementation flaw", "fido2 origin check", "rpidhash verification"]
cwe: [CWE-287, CWE-347]
owasp: [A07:2021]
attack: []
capec: []
related: [sql-injection, cross-site-scripting, csrf, ssrf]
corpus_sparse: true
---

# SAML and Webauthn Passkey Implementation Flaws - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A WebAuthn relying party receives an assertion made of authenticatorData, clientDataJSON, and a signature, and the security decision lives entirely in how the server verifies them. The server must confirm clientDataJSON.type is webauthn.get, that clientDataJSON.challenge equals the one-time challenge it issued, that clientDataJSON.origin is on an allowlist, that the leading 32 bytes of authenticatorData equal SHA-256 of the RP ID, that the user-presence and user-verification flags satisfy policy, that the signature validates against the stored public key, and that signCount has not rolled back. It must also keep the discoverable (resident-key) and non-discoverable credential flows distinct through userHandle. When any of these checks is skipped or performed only in browser JavaScript, a captured, cross-origin, or wrong-flow assertion is accepted and the attacker is bound to the victim account.

- **Precondition chain:** the relying party accepts a WebAuthn assertion, at least one of challenge binding, origin or rpIdHash comparison, signature verification, signCount monotonicity, or credential-flow distinction is missing or client-side, and the attacker can submit an assertion the server maps to a victim account.
- **Readable differential:** the same ceremony replayed with a stale challenge or a mismatched clientDataJSON.origin versus a fresh same-origin ceremony; acceptance of the stale or foreign one proves the binding is absent, and it reverts to rejection once the server compares the stored challenge and the origin allowlist.
- **Empirical grounding:** CVE-2025-26788 (StrongKey FIDO Server) shows a passkey bypass where the non-discoverable credential flow was not distinguished from the discoverable one; CWE-287 and CWE-347 fall under OWASP Top 10:2025 A07:2025 Authentication Failures.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the rpIdHash in authenticatorData is never recomputed as SHA-256 of the RP ID **THEN** treat the RP ID binding as the primary finding and test a cross-rpId assertion before anything else
2. **IF** clientDataJSON.origin is parsed and logged but never compared server-side **THEN** confirm the origin check with a foreign-origin ceremony, since a missing comparison is phishing-exploitable
3. **IF** the server-issued challenge is accepted more than once or is not deleted after use **THEN** test challenge replay on its own, because a single-use challenge store is a separate control from origin
4. **IF** signCount is returned but never checked for a monotonic increase **THEN** record cloned-authenticator rollback as the finding, noting that many platform authenticators legitimately send 0
5. **IF** the login accepts a non-discoverable credential where a resident key was mandated **THEN** focus on credential-flow confusion as in CVE-2025-26788 and bind userHandle per flow
6. **IF** a bearer session is minted after the ceremony rather than trusting the assertion **THEN** treat that session binding and revocation as separate; see [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) (1 hop)
7. **IF** the ceremony is a second factor layered on a password with an OTP fallback **THEN** assess the fallback factor with [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) (1 hop)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the server verifies type, challenge, origin, rpIdHash, signature, and signCount and keeps the credential flows distinct **THEN** STOP and classify as a verified non-finding for CWE-287 rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The relying party trusts a bearer token minted after the ceremony rather than the assertion itself | [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) | The failure moves to session binding and revocation, a lifecycle invariant rather than a public-key one |
| The weakness is on the SAML side of a mixed single-sign-on stack | [`saml-assertion-attacks`](../saml-assertion-attacks/SKILL.md) | SAML assertion verification is an XML-signature invariant separate from WebAuthn assertion verification |
| Step-up relies on an OTP fallback the attacker can target instead | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | Fallback-factor bypass is a rate-limit invariant, not a credential-binding one |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the verification routine and classify every check.** Find where authenticatorData, clientDataJSON, and the signature are parsed, and mark each required check (type, challenge, origin, rpIdHash, UP/UV flags, signature, signCount, userHandle) as enforced server-side, enforced in browser only, or absent.
2. **Choose the branch from what the parsed bytes show.** If clientDataJSON.origin is read but never compared, the origin branch is live; if rpIdHash is never recomputed, the RP ID branch is live; let the code, not a guess, decide which binding to probe.
3. **Record a baseline ceremony.** Complete one legitimate registration and assertion against the real origin and capture the exact challenge, origin, rpIdHash, and signCount the server accepted.
4. **Define the baseline-versus-probe differential.** Resubmit the same assertion altering exactly one bound field at a time, a stale challenge, a foreign clientDataJSON.origin, or a decremented signCount, and compare acceptance against the baseline.
5. **Separate challenge replay from origin and flow confusion.** Test each in isolation so the report names whether the one-time challenge store, the origin comparison, or the discoverable-versus-non-discoverable distinction is the broken control.
6. **Stop condition.** Halt when (a) a probe with one altered bound field is accepted while the baseline was rejected, confirming the missing check, (b) every altered field is rejected identically, a non-finding, or (c) advancing would require registering a credential against another real user's account, which is out of scope.
7. **State what counts as proof.** Proof is an assertion the server maps to the victim account while one verification invariant is demonstrably skipped, a replayed challenge accepted twice, a foreign origin accepted, or a non-discoverable credential accepted where resident-key was mandated, plus the source line that omits the comparison. A successful login alone is not proof.
8. **Close with the structural fix.** Verify type, compare the stored one-time challenge in constant time and delete it after use, compare origin against an allowlist, recompute and compare rpIdHash, require UV when policy demands it, enforce monotonic signCount, and bind userHandle per credential flow; verify by replaying each probe against the patched relying party.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| clientDataJSON.origin read into a variable but never compared to an allowlist | Proves the origin binding is absent on the relying party, so a phished ceremony from any site is accepted; WebAuthn and FIDO2 verifier code |
| authenticatorData rpIdHash not recomputed as SHA-256 of the configured RP ID | Proves the RP ID binding is missing, so an assertion scoped to another rpId is accepted; any WebAuthn relying party |
| The server-issued challenge is not stored single-use or not deleted after the ceremony | Proves challenge replay is possible because the one-time nonce is reusable; FIDO2 assertion flows |
| signCount accepted without a monotonic-increase comparison against the stored value | Proves authenticator-cloning rollback goes undetected, relevant only where the authenticator actually reports a counter |
| Verification of type, challenge, or origin performed in browser JavaScript rather than on the server | Proves the decision is client-side and bypassable by crafting the POST directly; single-page-app WebAuthn backends |
| A non-discoverable credential accepted where a resident key was required | Proves discoverable-versus-non-discoverable flow confusion as in CVE-2025-26788; FIDO servers that branch on userHandle |
| The UV flag unchecked while policy advertises userVerification as required | Proves a presence-only assertion satisfies a verification-required policy; passkey step-up flows |

## Worked Contrast

**Vulnerable pattern:**

```python
def verify_assertion(cred, stored):
    client = json.loads(b64url_decode(cred["clientDataJSON"]))
    # Only the type is checked; origin and challenge are read but never compared,
    # so any captured or cross-origin assertion with a valid signature is accepted.
    if client["type"] != "webauthn.get":
        raise ValueError("wrong ceremony type")
    origin = client["origin"]        # trusted, not compared
    challenge = client["challenge"]  # trusted, not compared
    pubkey = stored[cred["id"]]["public_key"]
    return verify_signature(pubkey, cred["authenticatorData"], cred["clientDataJSON"])
```

**Hardened pattern:**

```python
ALLOWED_ORIGINS = {"https://login.example"}
RP_ID_HASH = hashlib.sha256(b"login.example").digest()

def verify_assertion(cred, stored, expected_challenge):
    client = json.loads(b64url_decode(cred["clientDataJSON"]))
    if client["type"] != "webauthn.get":
        raise ValueError("wrong ceremony type")
    if not hmac.compare_digest(client["challenge"], expected_challenge):
        raise ValueError("challenge mismatch or replayed")
    if client["origin"] not in ALLOWED_ORIGINS:
        raise ValueError("origin not allowed")
    auth_data = b64url_decode(cred["authenticatorData"])
    if auth_data[:32] != RP_ID_HASH:
        raise ValueError("rpIdHash mismatch")
    record = stored[cred["id"]]
    new_count = int.from_bytes(auth_data[33:37], "big")
    if new_count and new_count <= record["sign_count"]:
        raise ValueError("signCount rollback")
    record["sign_count"] = new_count
    consume_challenge(expected_challenge)
    return verify_signature(record["public_key"], auth_data, cred["clientDataJSON"])
```

**Why this matters:** The hardened verifier compares the one-time challenge in constant time, restricts origin to an allowlist, recomputes and compares rpIdHash, rejects a non-increasing signCount, and consumes the challenge so it cannot be replayed. The decision moves from the browser to the server and binds the assertion to this ceremony and this relying party.

## When It Is NOT This Issue

- **Platform authenticator reports signCount 0:** many passkey providers always return 0, so a non-incrementing counter is expected and is not a rollback finding on its own.
- **Origin and challenge checked inside the framework helper:** if the WebAuthn library compares them internally and the call passes the expected values, a missing manual check in application code is not a defect.
- **Self-registered credential only:** replaying your own assertion against your own account proves nothing; impact requires binding an assertion to a different user's account.
- **Synced passkey appearing on a second device:** a credential showing up on another device is normal passkey sync, not credential cloning.
- **Test relying party with verification disabled:** a staging deployment configured to skip UV is a configuration artefact, not a production authentication bypass.
- **Bearer token issued after a valid ceremony:** a weakness in how that session token is stored or revoked belongs to session lifecycle, not to assertion verification.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `saml-and-webauthn-passkey-implementation-flaws` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `saml-and-webauthn-passkey-implementation-flaws` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: saml-and-webauthn-passkey-implementation-flaws
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287, CWE-347 | Mapping: A07:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `saml-and-webauthn-passkey-implementation-flaws` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, CWE-347`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
