---
name: business-email-compromise-response
description: "Responds to business email compromise: mailbox rule and token review, session revocation, payment fraud containment and downstream victim notification. Use when account takeover relates to email fraud."
family: incident-response
tier: core
triggers: ["bec response", "business email compromise", "mailbox takeover", "payment fraud"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-163]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Business Email Compromise Response - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

BEC is an identity incident whose payload is a trusted conversation. The actor obtains a valid session — via password spray, device-code or token phishing, adversary-in-the-middle proxying, or helpdesk-assisted MFA reset — and then does almost nothing that looks like intrusion: they read threads, create a mailbox rule that hides replies and forwards to an external address, and reply in-thread to a real counterparty from the real mailbox. Because the mail is genuinely sent by the mailbox, SPF, DKIM and DMARC pass and the receiving side has no technical reason to distrust it. Two preconditions decide whether the incident is recoverable. First, mailbox audit logging and unified audit log retention must be on and cover the actor's dwell time; without them the rule creation, the consent grant and the send events are simply absent, and the case becomes an argument rather than an investigation. Second, the response must invalidate tokens rather than only reset the password: forwarding and suppression rules survive a credential change, and refresh tokens issued before the reset keep working until explicitly revoked or until continuous access evaluation propagates the critical event. This is why a "password reset, case closed" closure is the characteristic BEC failure — the actor still has a live token and still has the rule.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a payment has already left the organisation **THEN** run the fraud-recall track in parallel with containment: contact the sending bank and the receiving bank's fraud line with the wire reference inside the first hour, because recall probability decays by the hour while mailbox forensics can wait.
2. **IF** the actor added a forwarding rule or an inbox rule **THEN** disable the rule before deleting it, capture its full definition and the target address, and treat every message that traversed the rule as disclosed — the rule is both evidence and an ongoing exfiltration channel.
3. **IF** an OAuth application or a service principal was consented **THEN** revoke the consent grant and the refresh tokens before the password reset; a password reset never invalidates an app-issued token, and the actor re-enters through the grant.
4. **IF** the actor registered a new MFA method or changed authentication methods **THEN** remove the method and re-register out of band with the user, and only then restore sign-in — otherwise the reset returns the account to the actor.
5. **IF** the mailbox resides in a hybrid or third-party-filtered environment **THEN** verify that revocation reached every authentication surface (cloud, on-premises Exchange, legacy protocol endpoints, third-party filter with cached credentials), because the visible tenant console is not the whole estate.
6. **IF** telemetry source covering `inbox rule` / `token revoke` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `business-email-compromise-response` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for rule, token, consent and send attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Graph and Exchange Online read/verify entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm which audit sources actually cover the actor's dwell window.** Enumerate mailbox audit configuration, unified audit log availability and retention, sign-in log retention, and whether legacy protocol logging is on. A BEC case built on a 90-day unified audit log when the actor entered 120 days ago has no rule-creation event and no consent event — say so before reading any timeline.
2. **Choose the branch by what the actor touched.** Mailbox-only (rules and sends) branches to rule forensics and downstream recall; token-and-consent branches to grant revocation and CAE propagation; identity-and-MFA branches to method removal and re-enrolment. Most real cases touch two branches, and the order matters: consent and MFA before password reset, always.
3. **Define the baseline before calling a rule malicious.** Legitimate rules in a tenant are numerous, have descriptive names, and act on sender or subject. Establish the tenant's rule-name and rule-action distribution, the normal set of forwarding destinations, and the normal send volume per user-hour. The differential that matters is a rule with a one-character name, a move-to-RSS-or-Archive action, and an external forward — against a population where none of those occur.
4. **State the stop condition.** Stop when every rule created or modified in the window has been captured and removed, every consent grant and refresh token has been revoked with an audit event confirming it, every MFA method change has been reverted, and every downstream recipient of actor-sent mail has been notified. Stop conditions are per-surface: revocation on one surface while another still accepts the token is not containment.
5. **Require an audit event for each claim.** "Sessions revoked" is proven by the revocation event in the sign-in or audit log plus the absence of new successful sign-ins for that principal from the actor's infrastructure after the revocation timestamp. "Rule deleted" is proven by the rule-management event and by a subsequent mailbox read showing the rule absent. A command that returned success without a corresponding event is unverified.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| `New-InboxRule` or `Set-InboxRule` event with `ForwardTo` or `RedirectTo` in the parameters | Unified audit log operation record | The rule existed at that moment with that action; paired with the rule id it proves the specific rule and its target address |
| `Add service principal` or `Consent to application` with `Mail.Read` or `offline_access` scope | Unified audit log or Entra audit `Consent` record | An app-issued token path exists that a password reset will not close |
| Sign-in success for the principal with an unfamiliar ASN or a non-interactive client after the revocation timestamp | Sign-in log `UserLoggedIn` with `authenticationRequirement` | Revocation did not take effect on that surface; the actor still holds a usable session |
| `Send` events from the mailbox to external recipients inside the incident window, with internet message id | Unified audit log `Send` record | The exact messages that must be recalled or disclosed, and the counterparties to notify |
| `Update user` with `StrongAuthenticationMethod` change, or `User registered security info` | Entra audit or authentication-method log | The actor enrolled their own MFA factor; containment must remove it before restoring access |
| Rule name distribution across the tenant versus the suspect rule name length and character set | Rule inventory aggregation | Whether the rule is an outlier in a population that never uses such names, which is the differential that separates abuse from user configuration |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`inbox rule`):**

```text
# ANTI-PATTERN: keyword match on the word "forward" in a rule description,
# close the case on "password reset completed".
# Two silent failures: rules named "." or ";" never contain the keyword,
# and the reset returns success while the refresh token and the rule survive.
```

**Behavior-Anchored Detection & Guarded Triage (`inbox rule` — CWE-778):**

```kusto
let suspect_rules = CloudAppEvents
  | where TimeGenerated between (ago(30d) .. now())
  | where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
  | extend raw = tostring(RawEventData)
  | where raw has_any ("ForwardTo", "RedirectTo", "MoveToFolder")
  | extend dest = extract(@'"ForwardTo"\s*:\s*\[?"?([^"\],]+)', 1, raw)
  | where isnotempty(dest) and dest !endswith "@contoso.com"
  | project TimeGenerated, AccountUpn, dest, RuleName = tostring(RawEventData.Parameters)
  | summarize first_seen = min(TimeGenerated), last_seen = max(TimeGenerated) by AccountUpn, dest;
suspect_rules
| join kind=leftouter (
    IdentityLogonEvents
    | where TimeGenerated between (ago(30d) .. now())
    | summarize first_seen = min(TimeGenerated) by AccountUpn) on AccountUpn
// A forwarding rule created after the first unfamiliar sign-in is the finding;
// a rule predating the sign-in window is usually user configuration.
```

**Why this matters:** Pairs `inbox rule` with `token revoke` context, filters documented admin baselines, and enforces telemetry-presence verification.

## When It Is NOT This Issue

- **Helpdesk-driven MFA reset:** a legitimate reset after a lost device produces the same method-change events the actor's reset does. Correlate with the ticket id and the verifying caller, and check whether the ticket was opened from the user's normal geography and channel.
- **Travel or VPN egress change:** an impossible-travel alert with a successful MFA challenge and continuous ordinary activity is usually the user behind a new egress. Compare device identity and user-agent continuity, not just geography.
- **Mailbox rule created by a mail-flow or retention integration:** journaling rules, archive rules and ticketing connectors create rules with external destinations and non-descriptive names by design. They are documented in the mail-flow configuration and have no corresponding risky sign-in.
- **Dual-write or migration artefact:** during an Exchange migration, rules replicate and temporarily duplicate, and external forwarding set years ago reappears. Check the migration change record before treating a rule as new.
- **Marketing or CRM platform sending on the user's behalf:** delegated send-as with a legacy client produces send events and tokens that look anomalous but are scheduled automation. Confirm the connector registration and the sending cadence.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `inbox rule` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Audit coverage proven:** mailbox audit, unified audit log retention and sign-in log retention were each confirmed to span the actor's dwell window, and any surface without coverage is named as a gap.
- [ ] **Rules captured before removal:** every rule created or modified in the window was exported with its id, name, action and destination, and the destination address is preserved in the case record.
- [ ] **Token and consent revocation precedes credential reset:** consent grants and refresh tokens were revoked, and the ordering relative to password reset is documented.
- [ ] **MFA state reconciled:** actor-added methods were removed and user re-enrolment completed out of band before sign-in was restored.
- [ ] **Downstream disclosure enumerated:** every external recipient of actor-sent messages inside the window is listed with message id and notification status, including any payment instruction.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: business-email-compromise-response
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`web-application-incident-response`](../web-application-incident-response/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `business-email-compromise-response` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/blackhills (2), OffsecCyber (1), SecEval/attck (1), CYBER_CPT/pentest_partners (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
