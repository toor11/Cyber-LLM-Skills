---
name: email-header-injection
description: Injects SMTP headers through contact forms and mail-sending features to add recipients, change the sender, or smuggle a body, including newline encoding bypasses. Use when an application sends mail built from user input.
family: web-and-application
tier: leaf
triggers: ["email header injection", "smtp injection", "mail injection", "header injection email"]
cwe: [CWE-93]
owasp: [A03:2021]
attack: []
capec: [CAPEC-105]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Email Header Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Email header injection occurs when an application builds a message from user input and places a user-controlled value into a header field (From, Subject, Reply-To, recipient) without stripping CR and LF. A newline in that value terminates the current header and lets the attacker inject additional headers (Bcc, Cc, Content-Type) or, with a blank line, start a new body, because SMTP and MIME use CRLF as the record separator. The security decision is the mail-building layer's neutralisation of line terminators in header-bound fields. The attacker gains extra recipients, a spoofed sender, or a smuggled body sent with the application's authority. Confirmation shows an injected newline producing a new header or body in the composed message that a sanitised field would not.

- **Precondition chain:** user input is concatenated into an email header field, the mail-building code does not reject or strip CR and LF (and encoded forms) in that field, and the message is handed to an MTA that honours the injected separators.
- **Readable differential:** a benign single-line field value versus the same value with an embedded CR/LF and an extra header; a finding exists when the composed message gains the injected header or body, and it closes when the builder rejects or encodes the line terminators.
- **Empirical grounding:** CWE-93 Improper Neutralization of CRLF Sequences. The 2025 anchors are the USENIX Security 2025 measurement 'Email Spoofing with SMTP Smuggling', which found MTAs and a gateway still parsing ambiguous end-of-data sequences, and CVE-2025-59419 (Netty SMTP codec CRLF injection), where unescaped CR/LF in SMTP commands allowed header and command injection.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a contact, feedback, or invite form builds mail from user fields **THEN** this is the primary case; test CR and LF in each header-bound field
2. **IF** the smuggling happens at the SMTP data-termination boundary between relays **THEN** route the end-of-data CRLF ambiguity to [`enterprise-appliance-n-day-mail-collaboration`](../enterprise-appliance-n-day-mail-collaboration/SKILL.md)
3. **IF** the injection is into an HTTP response header, not a mail header **THEN** route to [`crlf-and-header-injection`](../crlf-and-header-injection/SKILL.md)
4. **IF** the value sets the envelope recipient via the MAIL FROM or RCPT path **THEN** distinguish envelope injection from header injection, since the MTA treats them differently
5. **IF** the field is encoded (RFC 2047) but decoded before send **THEN** test encoded-word and percent or Unicode newline forms
6. **IF** the links or Host in the mail are the real concern **THEN** route to [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md)
7. **IF** the sink is a templating engine building the body only **THEN** confirm whether any header field is user-derived before claiming injection
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`email-security-monitoring`](../../../blue-team/detection-and-monitoring/email-security-monitoring/SKILL.md)
9. **IF** every header-bound field rejects or strips CR/LF and encoded newline forms **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Injection target is an HTTP response header | [`crlf-and-header-injection`](../crlf-and-header-injection/SKILL.md) | Same CRLF class but the sink is HTTP, with response-splitting impact not mail |
| Ambiguity is at the SMTP end-of-data boundary between relays | [`enterprise-appliance-n-day-mail-collaboration`](../enterprise-appliance-n-day-mail-collaboration/SKILL.md) | Invariant is MTA data-termination parsing, a relay-level smuggling issue |
| Links or Host in the mail body drive the impact | [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) | Invariant is Host or URL trust, not header-field line termination |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find the mail-building sink and which fields are user-derived.** Locate the send call (SMTP library, sendmail pipe, API) and map which header fields (From, Reply-To, Subject, recipient list) take request input; the builder is the decision point.
2. **Classify the field's handling of line terminators.** Determine whether the code rejects, strips, or passes CR, LF, and their encoded forms, and whether a library assembles headers safely or by string concatenation.
3. **Record a benign single-line baseline.** Submit a normal value, send the mail to a controlled mailbox, and capture the composed headers so the clean message shape is known.
4. **Submit a paired probe adding one injected header via an embedded newline.** Change only the field under test by appending a CR/LF plus a benign extra header, keeping the rest identical.
5. **Compare the received message.** The probe message should contain the injected header or a new body segment as a distinct line while the baseline does not; test encoded newline forms if the literal is stripped.
6. **Attribute the split to the builder, not the MTA alone.** Confirm whether the application forwarded the raw CR/LF or whether an intermediate relay introduced the smuggling, since the fix location differs.
7. **Stop condition.** Stop when the probe either (a) yields an injected header or body that disappears once CR/LF is rejected or encoded, (b) is neutralised for literal and encoded newlines across the baseline, or (c) would require sending spoofed mail to real third parties to show impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a received message carrying an attacker-injected header or body produced by an embedded newline in a user field, plus the builder line that concatenates that field without stripping CR/LF. A newline accepted in the input box but absent from the composed message is not proof.
9. **Close with the structural fix.** Reject or strip CR and LF (and decoded encoded-word, percent, and Unicode newline equivalents) in every header-bound field, and use a mail API that separates envelope, headers, and body rather than string concatenation, then replay the newline probe and inspect the composed message.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A user field concatenated into a From, Reply-To, or Subject header | Proves a header-bound sink on the mail builder where a newline splits the record |
| An embedded CR/LF in a field producing an extra header in the sent message | Proves CRLF neutralisation is absent at the mail-building layer, the core CWE-93 defect |
| Encoded newline forms (RFC 2047 word, %0a, Unicode) surviving decode before send | Proves a filter that blocks literal CR/LF but misses encoded equivalents on this stack |
| A blank line injected into a header field that starts a new body | Proves body smuggling, where the attacker controls message content beyond headers |
| A mail builder assembling headers by string concatenation rather than an API | Proves the structural root cause, with no envelope or header separation on the send path |
| Ambiguous end-of-data (CRLF-dot-CRLF variants) accepted between relays | Proves SMTP smuggling at the MTA boundary, distinct from form-field header injection |

## Worked Contrast

**Vulnerable pattern:**

```python
import smtplib

def send_contact(name, reply_to, body):
    # reply_to is user-controlled and concatenated straight into the header block
    msg = (
        "From: site@example.com\r\n"
        "Reply-To: " + reply_to + "\r\n"
        "Subject: Contact from " + name + "\r\n"
        "\r\n" + body
    )
    with smtplib.SMTP("localhost") as s:
        s.sendmail("site@example.com", ["team@example.com"], msg)
```

**Hardened pattern:**

```python
import smtplib
from email.message import EmailMessage

def send_contact(name, reply_to, body):
    if any(c in reply_to for c in "\r\n") or any(c in name for c in "\r\n"):
        raise ValueError("line terminators not allowed in header fields")
    msg = EmailMessage()                     # API separates headers from body
    msg["From"] = "site@example.com"
    msg["Reply-To"] = reply_to               # set as a structured header, not concatenated
    msg["Subject"] = "Contact from " + name
    msg["To"] = "team@example.com"
    msg.set_content(body)
    with smtplib.SMTP("localhost") as s:
        s.send_message(msg)
```

**Why this matters:** The defective sender concatenates the user Reply-To into the header block, so an embedded newline injects Bcc or Cc headers or a new body; the fixed sender rejects CR and LF in header-bound fields and builds the message with EmailMessage, which keeps headers and body separate. The control is line-terminator rejection plus a structured mail API, not keyword blocklisting.

## When It Is NOT This Issue

- **Newline stripped before send:** the input box accepts a newline but the builder removes or encodes it, so the composed message has no injected header.
- **Field is body-only:** a value that only lands in the message body cannot add headers; multi-recipient or spoof impact needs a header-bound field.
- **Structured mail API in use:** a library that sets headers as typed fields and rejects embedded CR/LF gives no concatenation point to split.
- **Self-only delivery:** a form that mails only the submitter's own address with no attacker-added recipients has no third-party impact.
- **MTA rejects the injected header:** a downstream mail server that drops malformed or duplicate headers may neutralise the injection before delivery.
- **Encoded form never decoded:** an encoded newline the pipeline keeps encoded end-to-end never becomes a real separator.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `email-header-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `email-header-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: email-header-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-93 | Mapping: A03:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `email-header-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-93`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/osv (4), SecEval/owasp_wstg (2), CYBER_CPT/expku (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
