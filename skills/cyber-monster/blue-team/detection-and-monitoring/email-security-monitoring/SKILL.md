---
name: email-security-monitoring
description: "Monitors email for threats: authentication results, sender reputation, attachment and link analysis, and BEC indicators. Use when defending against phishing and business email compromise."
family: detection-and-monitoring
tier: core
triggers: ["email security monitoring", "phishing detection", "bec detection", "spf dkim dmarc"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-163]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# Email Security Monitoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`initial-access-via-phishing`](../../../red-team/network-ad-and-endpoint/initial-access-via-phishing/SKILL.md)

## Mechanism and Preconditions

Email authentication is an alignment property, not a trust score, and the distinction decides most triage. SPF validates the envelope sender's sending IP against the domain's published record; DKIM validates a signature over selected headers and body against a key published at a selector under the signing domain; DMARC passes if *either* SPF or DKIM passes **and** aligns with the `From` header domain. That means a message can show `spf=pass` while being a forgery of the display domain, and it can show `dkim=pass` with a signature under a look-alike domain that has nothing to do with the `From` address. The three results must be read together with the *aligned* domains, which is why a rule matching `"dmarc=fail"` is only as good as its ability to distinguish envelope failure from display-name forgery. Two further structural points govern detection quality. First, the header chain is attacker-influenced: `Received` order, `Return-Path`, `Reply-To`, and display names are all set by the sender, so only the top-most `Received` added by your own edge is trustworthy. Second, business email compromise usually authenticates perfectly — it is sent from a real, compromised or newly created mailbox — so BEC detection does not live in authentication results at all; it lives in behaviour: first contact between an internal sender and an external recipient, a reply chain that changes the `Reply-To`, a sudden change in payment instructions, mailbox rule creation, or an outbound volume spike from one account.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is "was this message forged" **THEN** read SPF, DKIM, DMARC together with the aligned domains and the top-most `Received` header added by your edge; **IF** the question is "was this message malicious" **THEN** authentication contributes only when it fails on the display domain, and content, link, and attachment evidence must carry the verdict.
2. **IF** DMARC fails on a domain you own **THEN** it is a spoof of your brand and the enforcement action depends on your published policy; **IF** DMARC passes and the sender is internal **THEN** authentication is uninformative, and the case is a BEC or account-takeover hypothesis that reads mailbox behaviour instead.
3. **IF** the message came from an external sender whose display name matches an internal executive or supplier **THEN** take the impersonation branch and compare the `From` domain against the real one character by character rather than by eye.
4. **IF** the `Reply-To` differs from `From` **THEN** treat that as a designed redirect and check whether the reply-to domain is first-seen for the recipient; **IF** the two match **THEN** the redirect hypothesis is closed and the analysis moves to link or attachment content.
5. **IF** a link is the primary artifact **THEN** evaluate the redirect chain and the final landing host, not the visible text; **IF** the message carries an attachment **THEN** classify by type and structure before any sandbox detonation, and prefer static structure extraction for documents.
6. **IF** telemetry source covering `SPF`/`DKIM`/`DMARC` or the mail-flow log is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** the tenant's DMARC record is at `p=none` **THEN** a failing message can legitimately be delivered, so delivery is not evidence of legitimacy; say which policy was in force at the time of delivery.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`initial-access-via-phishing`](../../../red-team/network-ad-and-endpoint/initial-access-via-phishing/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Authentication decomposition, first-contact, mailbox-rule and outbound-spike queries |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Header extraction, authentication verification, URL expansion, message trace |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The mailbox itself is suspected compromised | [`identity-and-authentication-monitoring`](../identity-and-authentication-monitoring/SKILL.md) | Sign-in and token evidence decides takeover |
| The payload is a document or executable attachment | [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) | Structural matching rather than name-based rules |

## Procedure

1. **Decompose the authentication header into its four facts.** For each message, extract the SPF result with its envelope domain, the DKIM result with its `d=` signing domain, the DMARC result, and whether SPF/DKIM *aligned* with the `From` domain. A single composite "authentication failed" field erases exactly the distinction the analysis needs.
2. **Fix the trusted header boundary.** Only the top-most `Received` header added by your own edge is trustworthy; every header below it was supplied by the sender. Record the client IP from that boundary for every subsequent reputation or geo comparison.
3. **Classify the case as spoof, impersonation, or compromise before querying further.** A spoof has a failing alignment on your own domain; an impersonation has a passing or absent authentication with a look-alike `From` domain and a matching display name; a compromise has full authentication from a real internal mailbox. The three take different evidence and different containment.
4. **For spoof and impersonation, evaluate the payload.** Expand every link through the redirect chain to the final host and compare the registrable domain against the display text; for attachments, extract type, structure, and embedded URLs before any execution.
5. **For compromise, ignore authentication and read behaviour.** Query mailbox rule creation, forwarding changes, outbound volume per recipient domain, first-time external recipients, and sign-in anomalies for the sending account inside the same window.
6. **Name the stop condition.** Stop and declare `Inconclusive` when the message headers were rewritten by a gateway so the original `Received` chain is unavailable, when the tenant policy is `p=none` and delivery therefore says nothing, when the link's final host cannot be resolved safely, or when mailbox audit logs for the sending account are not retained for the window.
7. **State what counts as proof.** Proof of a forgery is a failing DMARC alignment on a domain you own, with the aligned-domain mismatch shown. Proof of impersonation is a look-alike `From` domain with a display name matching a real internal identity and a first-seen destination for the recipient. Proof of compromise is a mailbox event (rule, forwarding, or deletion) or an outbound behavioural change by a fully authenticated account. One message with "suspicious" content is none of the three.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| SPF result with envelope domain, DKIM result with `d=` domain, DMARC result, and alignment flag per message | authentication decomposition | Whether a failure is an envelope failure, a signature failure, or an alignment failure, which are three different findings |
| Top-most `Received` client IP and its ASN, compared against the sender domain's usual sending infrastructure | header boundary | The only sender address the edge actually observed, and whether it matches the domain's history |
| `From` domain compared against the display name's real owner domain by exact string | impersonation check | Homoglyph and subdomain-trick forgeries that a substring match would miss and a human eye certainly would |
| First-ever message between an internal sender and an external recipient domain | BEC behaviour | A new relationship that bypassed authentication entirely, which is the normal BEC shape |
| Mailbox rule creation, forwarding enablement, or inbox-rule deletion for the sending account | compromise indicator | That the mailbox, not the message, is the compromised asset |
| Outbound recipient-domain count per account per hour against that account's baseline | exfiltration or spam behaviour | A compromised account's change in sending pattern, visible even when every message authenticates |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```kusto
EmailEvents
| where Timestamp > ago(1d)
| where AuthenticationDetails contains "fail"
| project Timestamp, SenderFromAddress, Subject
// One composite string, no aligned domain, no direction filter.
// Fails on every mailing list that breaks SPF on forward, every
// third-party sender with a misconfigured DKIM selector, and every
// look-alike domain that passes SPF for its own domain and forges
// only the display name — which is the case that matters.
```

**High-Signal Grounded Artifact:**

```kusto
let own = dynamic(["contoso.com","contoso-mail.com"]);
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection in ("Inbound","Intra-org")
| extend auth = parse_json(AuthenticationDetails)
| extend spf = tostring(auth.SPF), dkim = tostring(auth.DKIM),
         dmarc = tostring(auth.DMARC), comp = tostring(auth.CompAuth)
| extend from_domain = tostring(split(SenderFromAddress, "@")[1])
| where from_domain in (own) and (spf == "fail" or dmarc == "fail")
| summarize attempts=count(), senders=make_set(SenderFromAddress, 5),
            first=min(Timestamp), last=max(Timestamp)
            by from_domain, SenderIPv4, bin(Timestamp, 1h)
| where attempts >= 3
| order by attempts desc
// Own-domain forgery: the display domain is ours, authentication failed on it.
// A look-alike domain would not appear here at all, which is why the
// impersonation branch is a separate query with a domain-similarity join.
```

**Why this matters:** the strong form parses the authentication results into the components that decide a verdict and scopes to messages claiming to be a domain you own, so a returned row is a brand forgery with a sender address the edge actually observed; the weak form matches one composite string, which flags forwarded mailing lists and misconfigured legitimate senders while missing the look-alike-domain impersonation that carries most business impact.

## When It Is NOT This Issue

- **Forwarding breaks SPF by design:** a mailing list or an internal forward rewrites the envelope, so SPF fails while DKIM may still pass. Read the alignment flag rather than the SPF result alone, and check whether the message arrived through a forwarder listed in `Received`.
- **Third-party sender with a broken selector:** a legitimate SaaS sender whose DKIM selector rotated without the DNS record being updated produces DKIM failures at volume. The pattern is confined to one sender domain and one selector, and the fix is the sender's, not a block.
- **DMARC at `p=none`:** with a monitoring-only policy, a failing message is delivered and the delivery is not evidence that the message was legitimate. State the policy in force; enforcement posture is a separate decision from the verdict.
- **Display-name collision with no domain similarity:** an external sender legitimately shares a display name with an internal person (a common surname). Domain dissimilarity plus an established prior relationship makes this benign, and the first-contact query is what distinguishes it.
- **Outbound volume spike from a legitimate bulk action:** a sales campaign, a ticket-system migration, or a password-reset wave drives outbound volume far above baseline. Correlate with a change record or the sending application's identity before treating the spike as compromise.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a mailbox is clean when mail-flow, mailbox-audit, or sign-in telemetry covering it was disabled, rotated out, or uncollected.**
- **NEVER report a message as forged on the strength of a raw authentication string without showing the aligned domain that failed.**
- **NEVER recommend destructive containment (disabling a mailbox, blocking a sender domain fleet-wide, or purging mail tenant-wide) before preserving the message, its headers, and the mailbox audit trail.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** mail-flow records, the message's own header set, mailbox audit, and sign-in telemetry were each located for the window, and the tenant DMARC policy in force was recorded.
- [ ] **Differential defined:** the sender domain and sending infrastructure were compared against their own history, and for BEC the recipient relationship was tested for first contact rather than assumed.
- [ ] **Stop condition stated:** rewritten header chain, monitoring-only policy, unresolvable redirect, or missing mailbox audit is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** for forgery, failing alignment on an owned domain with the mismatch shown; for impersonation, look-alike domain plus identity match plus first contact; for compromise, a mailbox event or outbound behavioural change.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: email-security-monitoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Mail-flow and message records, header boundary used, authentication components with aligned domains, mailbox audit window, tenant DMARC policy]
- **Behavioral Analysis**: [Case class (spoof, impersonation, compromise), payload observations, first-contact result, outbound baseline comparison; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Redirect chain and final landing host, attachment structure extraction, sign-in and mailbox-rule evidence for the sending account]
- **Containment / Detection / Hardening Action**: [Purge or quarantine scope, sender-domain block with blast radius, mailbox containment and credential reset, DMARC enforcement step with owner]
```

## Related Sub-Skills

- [`initial-access-via-phishing`](../../../red-team/network-ad-and-endpoint/initial-access-via-phishing/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Alignment, not verdict:** the single most common email triage error is treating `spf=pass` as legitimacy. Always report the aligned domain that decided the DMARC result.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); the phishing technique family is the mapping target and BEC maps to internal-spearphishing variants.
- **Safety & authorization:** Message content is personal data; handle it under the organisation's monitoring policy, share only the headers and indicators needed for the decision, and never detonate an attachment outside an isolated sandbox.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/nuclei_templates (3), CYBER_CPT/blackhills (3), cyber-security/CyberSec-Dataset (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
