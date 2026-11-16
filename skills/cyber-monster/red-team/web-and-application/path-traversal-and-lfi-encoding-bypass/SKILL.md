---
name: path-traversal-and-lfi-encoding-bypass
description: Traversal encoding and normalization bypass. Covers double and triple encoding, overlong UTF-8, unicode normalization, null-byte truncation, and platform-specific path parsing differences. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["traversal bypass", "encoded traversal", "dotdot bypass", "null byte", "unicode traversal"]
cwe: [CWE-22, CWE-98]
owasp: [A01:2021, A03:2021]
attack: [T1005]
capec: [CAPEC-126]
related: [path-traversal-and-lfi, path-traversal-and-lfi-php-wrappers, path-traversal-and-lfi-lfi-to-rce, path-traversal-and-lfi-log-and-cache-poisoning]
parent: path-traversal-and-lfi
---

# Path Traversal and LFI Encoding Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)

## Mechanism and Preconditions

A traversal filter exists but inspects the input in the wrong representation or at the wrong stage, so an encoded sequence that looks safe at check time decodes back into a traversal before the file is opened. Single percent-encoding (..%2f), double encoding (..%252f), overlong UTF-8 (%c0%ae), backslash variants (..%5c), Unicode normalisation, and null-byte truncation each exploit a mismatch between the layer that validates and the layer that resolves. The defining defect is ordering: the application checks for `..` or a leading slash on the still-encoded value and then decodes, or it decodes once while the platform decodes again. The attacker reaches the same out-of-root read as the parent class by passing the check in one encoding and resolving in another. Confirmation is that an encoded form reads a file while the literal form is blocked, and that decoding-then-canonicalising rejects both.

- **Precondition chain:** A traversal filter is present, validation runs on an encoded value or decodes a different number of times than the resolver, and a surviving encoded sequence reconstructs a traversal before the file open.
- **Readable differential:** A literal traversal that the filter blocks versus an encoded form of the same path that it accepts; a finding exists when the encoded form reads out of root, and it stops once the value is fully decoded and canonicalised before the containment check.
- **Empirical grounding:** CWE-22 under OWASP Top 10:2025 A01 Broken Access Control; CVE-2025-64446 (FortiWeb relative path traversal, chained with CVE-2025-58034 and flagged by CISA in November 2025) and GHSA-9p3p-w5jf-8xxg (Kirby router path traversal) show validation defeated by encoded sequences and a validate-before-canonicalise ordering bug.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to involve encoding evasion **THEN** start at parent class [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) for general triage
2. **IF** the literal traversal is filtered but a single-encoded form may pass **THEN** test ..%2f against the blocked ../ to expose a validate-before-decode gap
3. **IF** a reverse proxy or framework decodes before the app does **THEN** test double encoding ..%252f that survives one decode and resolves after another
4. **IF** the platform accepts overlong or alternate UTF-8 **THEN** test %c0%ae forms that normalise to a dot after the check
5. **IF** the target is Windows and backslashes are relevant **THEN** test ..%5c forms that resolve as separators the filter missed
6. **IF** the decoded path opens a wrapper scheme such as php://filter **THEN** route to [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md)
7. **IF** a confirmed read is leveraged into code execution **THEN** route to [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md)
9. **IF** every encoded form is decoded and canonicalised before the check so none reads out of root **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The decoded path opens a wrapper scheme such as php://filter | [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) | The sink is a stream wrapper, not a plain filesystem path |
| The confirmed read is leveraged into code execution | [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) | Impact escalates from disclosure to execution |
| The normalisation gap is at a WAF rather than the application | [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) | The differential is proxy decoding versus origin decoding |
| Need parent class methodology | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the filter and the decode points.** Read where the application checks for `..` or a leading slash and count how many times the value is decoded between the edge and the file open. The ordering and decode count are the whole game.
2. **Confirm the literal form is blocked.** Establish that a plain ../ traversal is rejected, so any encoded form that succeeds demonstrates an encoding-specific bypass rather than a general traversal.
3. **Record an in-root encoded baseline.** Request a known in-root file using a harmless encoded path to confirm the endpoint decodes at all and to anchor the differential.
4. **Select the encoding against the observed stack.** Choose single-encoding for a validate-before-decode check, double-encoding when a proxy decodes first, overlong UTF-8 for lax decoders, and backslash forms on Windows, matching the probe to the architecture.
5. **Apply the encoded out-of-root differential.** Compare the blocked literal traversal against the encoded equivalent reaching a benign out-of-root file; content from the encoded form confirms the ordering or multi-decode gap.
6. **Stop condition.** Halt when an encoded probe either (a) reads out of root while the literal is blocked and both fail once decode-then-canonicalise is enforced, (b) returns not-found or rejection in every encoding, or (c) would require reading real secrets to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an encoded path returning out-of-root content that the literal form could not, tied to one changed parameter, plus the source showing the check runs before full decoding or that two layers decode. A single-decode block alone is not proof of safety.
8. **Close with the structural fix and verify it.** Decode the value completely once, canonicalise to the real path, then verify it stays under the root, rejecting residual encoded separators and null bytes; re-run each encoding form to confirm none now escapes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A single-encoded ..%2f accepted where literal ../ is blocked | Proves a validate-before-decode ordering bug on the filtering layer, the defining encoding gap |
| A double-encoded ..%252f that resolves after a proxy and app each decode once | Proves a multi-layer decode mismatch between the edge and the origin |
| An overlong UTF-8 %c0%ae normalising to a dot past the check | Proves a lax decoder accepts non-canonical byte forms that reconstruct traversal |
| A backslash ..%5c form resolving as a separator on Windows | Proves platform path parsing the filter did not account for |
| A %00 null byte truncating an appended extension | Proves legacy truncation that strips a forced suffix before the open on affected runtimes |
| The literal traversal blocked while an encoded sibling reads out of root | Proves the bypass is in encoding handling, not an absent filter, on this endpoint |

## Worked Contrast

**Vulnerable pattern:**

```python
import os
from urllib.parse import unquote
from flask import request

BASE = "/srv/files"

def read_file():
    raw = request.args["path"]
    # Check runs on the still-encoded value, then decoding reintroduces the traversal
    if ".." in raw or raw.startswith("/"):
        raise ValueError("rejected")
    decoded = unquote(raw)
    return open(os.path.join(BASE, decoded), "rb").read()
```

**Hardened pattern:**

```python
import os
from urllib.parse import unquote
from flask import request

BASE = os.path.realpath("/srv/files")

def read_file():
    # Decode fully first, then canonicalise, then confirm the result stays under BASE
    decoded = unquote(request.args["path"])
    resolved = os.path.realpath(os.path.join(BASE, decoded))
    if not (resolved == BASE or resolved.startswith(BASE + os.sep)):
        raise ValueError("outside base directory")
    return open(resolved, "rb").read()
```

**Why this matters:** The vulnerable version validates the encoded string and then decodes, so ..%2f slips past the check; the fix decodes first, resolves the real path, and enforces containment on the canonical result, so no encoding reintroduces a traversal after the decision is made.

## When It Is NOT This Issue

- **Decode-then-canonicalise enforced:** the value is fully decoded and resolved before the containment check, so encoded forms gain nothing.
- **Single decode end to end:** when exactly one decode happens and it precedes the check, double-encoding resolves to a literal that is then blocked.
- **Literal form also reads out of root:** if the plain ../ already works, this is the parent traversal finding, not an encoding-specific bypass.
- **Encoded form rejected everywhere:** an encoded path that returns not-found at every depth and variant shows the resolver is confined.
- **Null-byte truncation patched:** modern runtimes reject embedded null bytes, so %00 suffix tricks do not apply.
- **WAF decodes but origin confines:** a decode difference at the WAF that the origin then canonicalises away is a layered-parsing note, not an origin read.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `path-traversal-and-lfi-encoding-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `path-traversal-and-lfi-encoding-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: path-traversal-and-lfi-encoding-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-22, CWE-98 | Mapping: T1005]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-app-incident-access-log-exploitation-analysis`](../../../blue-team/incident-response/web-app-incident-access-log-exploitation-analysis/SKILL.md) - Blue Detection/Defense Counterpart
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)
- [`path-traversal-and-lfi-php-wrappers`](../path-traversal-and-lfi-php-wrappers/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-lfi-to-rce`](../path-traversal-and-lfi-lfi-to-rce/SKILL.md) - Web and Application (leaf)
- [`path-traversal-and-lfi-log-and-cache-poisoning`](../path-traversal-and-lfi-log-and-cache-poisoning/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `path-traversal-and-lfi-encoding-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-22, CWE-98, T1005`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 7 |
| Top sources | OffsecCyber (6), CYBER_CPT/awesome_list (1), CYBER_CPT/ctf_search (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
