---
name: identity-and-authentication-monitoring
description: "Monitors identity systems for attack patterns: impossible travel, MFA fatigue, token replay, password spray and privilege changes. Use when identity is the primary attack surface."
family: detection-and-monitoring
tier: core
triggers: ["identity monitoring", "authentication monitoring", "impossible travel", "mfa fatigue detection"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# Identity and Authentication Monitoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`oauth-oidc-misconfiguration`](../../../red-team/web-and-application/oauth-oidc-misconfiguration/SKILL.md)

## Mechanism and Preconditions

Modern identity providers emit three distinct event families that are routinely conflated, and the conflation produces both false positives and missed detections. *Interactive* sign-ins are those where a human supplied a factor; their failure codes carry the reason (bad password, MFA challenge timeout, MFA denied) and a burst of them against one account from one address is the spray or fatigue signature. *Non-interactive* sign-ins are token refreshes performed on behalf of a user with no factor supplied; they are the primary evidence of token replay, because a stolen refresh token produces successful non-interactive sign-ins from an unfamiliar address while every interactive check still looks clean. *Directory and application audit* events record the changes an authenticated principal made: credential additions, MFA method registration, role assignment, consent grants. Attack patterns cross all three: password spray shows as failures then a success; MFA fatigue shows as repeated challenges followed by an approval; token theft shows as a successful non-interactive sign-in from a new location with no interactive sign-in before it; privilege escalation shows as a directory change on an account that never made one. Geographic "impossible travel" is the weakest of these signals because IP geolocation is a best-effort inference and mobile carriers, VPNs, and cloud egress pools routinely place one user in two countries within an hour. Per-user baselining of address, ASN, device, and client application is what makes the travel signal usable at all.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is a failed-then-succeeded sign-in pair for one account from one address **THEN** evaluate it as spray or fatigue and read the failure reason codes; **IF** the evidence is a successful sign-in with no interactive event preceding it **THEN** evaluate it as token replay and pivot to refresh-token and device evidence.
2. **IF** the suspicious event is non-interactive **THEN** it is a token-use event, so location and device are the discriminators and the user could not have responded to a prompt; **IF** it is interactive **THEN** the factor and the failure reason decide the case.
3. **IF** the account shows new MFA method registration, credential addition, or consent grant inside the window **THEN** treat persistence as established regardless of how the sign-in looked; **IF** no such change exists **THEN** the case is still access-only and the containment differs.
4. **IF** the location signal is the only anomaly **THEN** check the address's ASN and whether it belongs to a mobile carrier, VPN, or cloud provider before calling it impossible travel; **IF** the address also appears in the user's own history **THEN** the travel signal is closed.
5. **IF** the tenant has a conditional-access policy that should have blocked the sign-in **THEN** the policy's non-application is itself a finding, separate from the intrusion; **IF** the policy applied and failed open **THEN** record the misconfiguration.
6. **IF** the account is a service principal or managed identity **THEN** baseline on the credential and the calling workload, not on a person's travel; **IF** it is a human account **THEN** baseline on address, device, and client application.
7. **IF** telemetry source covering `sign-in log` or audit events is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`oauth-oidc-misconfiguration`](../../../red-team/web-and-application/oauth-oidc-misconfiguration/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Failure-reason decomposition, spray, token replay, MFA registration, privilege change |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Sign-in log query, audit log export, identity risk inspection |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The mailbox is the observable target rather than the account | [`email-security-monitoring`](../email-security-monitoring/SKILL.md) | Mailbox rules, forwarding, and outbound behaviour |
| The identity is a cloud workload principal rather than a person | [`cloud-detection-and-logging`](../cloud-detection-and-logging/SKILL.md) | Role chains and audit-plane semantics |

## Procedure

1. **Separate the three event families before querying.** Pull interactive sign-ins, non-interactive sign-ins, and directory audit events into distinct result sets with their own failure and result codes. A blended query on "sign-in events" makes a token refresh indistinguishable from a password attempt.
2. **Fix the account's baseline for address, ASN, device, and client application.** Compute it over a trailing 30 days per account. A human's pattern is narrow; a service principal's pattern is narrower still, which is why a single new address for a workload identity is significant.
3. **Read the failure reason, not just the failure.** Bad password, MFA challenge timeout, MFA denied, and blocked-by-policy are four different attacks or non-attacks. A spray produces bad-password failures; fatigue produces challenge timeouts followed by an approval; policy blocks are a control working.
4. **For a successful sign-in, establish what preceded it.** An interactive success preceded by many failures from the same address is a spray success. A non-interactive success with no interactive event and a new address is token replay. The predecessor event is the classification.
5. **Check for persistence in the audit plane.** New authentication method, new credential, new role assignment, new consent grant, or a changed mailbox or application permission inside the window converts an access case into a persistence case with a different containment.
6. **Name the stop condition.** Stop and declare `Inconclusive` when the provider retains sign-in data for less than the window, when non-interactive events are not collected (a common gap), when the tenant's audit log is off for the relevant workload, or when the address's geolocation cannot be corroborated with ASN data.
7. **State what counts as proof.** Proof is a sequence in one window: the initiating event with its reason code, the successful event for the same account with the address and device that differ from the account's baseline, and either a persistence artifact in the audit plane or a confirmed resource access from the new session. A single location anomaly is none of these.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Failure reason code distribution per account and source address | failure decomposition | Whether the pattern is bad passwords (spray), challenge timeouts (fatigue), or policy blocks (control working) |
| Non-interactive success from an address absent from the account's 30-day baseline | token replay | Use of a stolen refresh token, which produces no interactive event at all |
| Interactive success immediately following a failure burst from the same address | spray success | That the guessing worked, which converts a noise pattern into a compromise |
| Authentication-method registration or credential addition for an account inside the window | persistence | That the actor established durable access, independent of how the session was obtained |
| Role assignment or application-consent grant by an account that never performs them | privilege change | Escalation or backdoor creation in the directory, visible only in the audit plane |
| Conditional-access result alongside the sign-in result | control efficacy | Whether the policy that should have blocked the session applied, and whether it failed open |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```kusto
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != "0"
| summarize failures = count() by UserPrincipalName, IPAddress
| where failures > 10
// Counts failures with no reason code, no success correlation.
// A user with a stale password in a sync client generates this every morning.
// A spray from a residential proxy pool spreads across many addresses and
// never reaches the threshold on any single one, so it is invisible here.
```

**High-Signal Grounded Artifact:**

```kusto
let window = 24h;
let baseline = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(1d))
| where ResultType == "0"
| summarize known_ips = make_set(IPAddress, 200) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(window)
| where ResultType == "0"
| where AppDisplayName !in ("Windows Sign In", "Microsoft Office")
| join kind=inner baseline on UserPrincipalName
| where IPAddress !in (known_ips)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName,
          DeviceDetail, AuthenticationRequirement, ConditionalAccessStatus
| order by TimeGenerated desc
// New address for an account, successful, against its own 30-day baseline.
// The next question is whether an interactive event preceded it (spray success)
// or not (token replay) — that classification comes from the paired query.
```

**Why this matters:** the strong form baselines each account's own successful addresses and reports only successes from new ones, so the output is a session that needs classification rather than a failure count that needs interpretation; the weak form counts failures without their reason, which is dominated by misconfigured clients and blind to a distributed spray.

## When It Is NOT This Issue

- **Mobile carrier and VPN egress pools:** a user's address changes country within minutes as the carrier routes traffic through a different gateway, and a corporate VPN concentrator places the whole estate in one datacentre region. ASN and the account's own address history resolve this; raw geolocation does not.
- **Non-interactive events not collected:** many estates ingest only interactive sign-ins, so a token-replay case has no evidence at all and looks like a clean account. Confirm the non-interactive stream is onboarded before concluding anything about token use.
- **Conditional-access evaluation appearing as a failure:** a policy that blocks a session produces a non-zero result that is a control working, not an intrusion. Read `ConditionalAccessStatus` alongside `ResultType`.
- **Legitimate MFA re-registration:** a user replacing a phone registers a new authentication method, and the event is identical to an attacker adding one. Correlate with a helpdesk ticket or the device's own enrolment record.
- **Service-account password rotation:** an automated rotation produces a burst of failures then successes for one account on a schedule. The cadence and the absence of new addresses distinguish it from a spray.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude an account is uncompromised when non-interactive sign-ins, audit logs, or risk detections covering it were disabled, uncollected, or outside retention.**
- **NEVER present an IP geolocation inference as established fact; report the ASN and the account's own address history alongside it.**
- **NEVER recommend destructive containment (disabling a break-glass account, revoking all tenant sessions, or resetting every credential) before preserving sign-in and audit evidence and checking the blast radius across dependent applications.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** interactive sign-ins, non-interactive sign-ins, and directory audit events were each confirmed as collected for the window, and the retention boundary was recorded.
- [ ] **Differential defined:** the account's 30-day baseline of address, ASN, device, and client application was computed and the probe-window session compared against it.
- [ ] **Stop condition stated:** short retention, uncollected non-interactive events, disabled audit logging, or uncorroborated geolocation is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** initiating event with reason code, successful event with baseline deviation, and either a persistence artifact or confirmed resource access from the new session.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: identity-and-authentication-monitoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Interactive and non-interactive sign-in streams, audit log, risk detections, retention, UTC baseline and probe windows, conditional-access results]
- **Behavioral Analysis**: [Failure reason distribution, predecessor event for the success, baseline deviation in address/ASN/device/app; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Refresh-token and device evidence, mailbox or application activity from the new session, MFA method registration history]
- **Containment / Detection / Hardening Action**: [Session revocation and credential reset, persistence artifacts to remove, conditional-access or CAE policy gap, owner and review date]
```

## Related Sub-Skills

- [`oauth-oidc-misconfiguration`](../../../red-team/web-and-application/oauth-oidc-misconfiguration/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Three streams, three questions:** interactive answers "did someone authenticate", non-interactive answers "was a token used", audit answers "what did they change". Any case that reads only one is incomplete.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); token theft maps to the stealth family after the ATT&CK v19 split, and the technique identifiers for defense evasion moved accordingly.
- **Safety & authorization:** Read-only analysis of sign-in and audit data; revocation and credential reset are approved actions performed after evidence capture, and employee monitoring rules govern how much personal detail is recorded in the case.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/osv (2), CYBER_CPT/sigmahq (2), cyber-security/security-code (1), CYBER_CPT/gh_security_lab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
