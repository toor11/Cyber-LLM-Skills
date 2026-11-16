---
name: cloud-detection-and-logging
description: "Detects malicious cloud activity: audit log coverage, control plane versus data plane events, identity-based detections and multi-cloud log normalization. Use when monitoring cloud environments."
family: detection-and-monitoring
tier: core
triggers: ["cloud detection", "cloudtrail detection", "azure activity log", "gcp audit log"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# Cloud Detection and Logging - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`ssrf`](../../../red-team/web-and-application/ssrf/SKILL.md)

## Mechanism and Preconditions

Cloud detection reads an audit plane, and the audit plane has a shape that decides what a query can even see. Control-plane events (create, modify, delete, permission change, policy attach) are recorded by default in every major provider because they describe resource state transitions. Data-plane events (object reads, queue receives, secret retrievals, function invocations) are charged per event, opt-in, and frequently off — so their absence from a query means nothing unless the selector was verified. The two planes use different event names, different principal fields, and different failure semantics. Layer onto that the identity model: a cloud action's actor is an assumed-role session whose `roleSessionName` and source identity may be attacker-influenced, so the trustworthy attribution is the role ARN plus the source IP/ASN plus the session chain, not the display name. On top of the provider audit plane sit the provider's own finding stream (GuardDuty, Defender for Cloud, Security Command Center) which consumes a duplicated copy of the management events and therefore stays useful even when your trail is misconfigured — but the two are not interchangeable, and detector latency means a clean finding stream is not evidence that no action occurred.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is about a read of stored data (object GET, secret retrieval, blob download) **THEN** first prove the data-plane selector exists for that bucket/queue/store; **IF** no data-event selector covers it **THEN** report `Inconclusive (Data-Plane Gap)` and name the resource, because the query cannot see the action at all.
2. **IF** the scope is a single account or a single region **THEN** query the trail for that scope; **IF** the question spans accounts or regions **THEN** query the organization-level destination (organization trail or organization event data store) and state that a member-account trail cannot answer it.
3. **IF** the provider's event history is the only accessible source **THEN** constrain the answer to management events inside its retention window and say so; **IF** the provider exposes a queryable lake or warehouse table **THEN** use it for data-plane and long-window questions and record the retention actually configured.
4. **IF** the actor is an assumed role **THEN** attribute on role ARN plus session context and source IP; **IF** the actor is a long-lived access key **THEN** treat the key ID as the durable identifier and pivot on its last-used and rotation record.
5. **IF** AWS and Azure and GCP evidence must be combined **THEN** normalise into one schema (OCSF `class_uid` 6003 API Activity for audit calls, 3002 Authentication for sign-in) before writing a rule; **IF** the rule stays provider-native **THEN** keep it provider-native and say which provider it belongs to.
6. **IF** a detector finding is the sole evidence **THEN** look for the underlying audit event that triggered it; **IF** no audit event can be located **THEN** the finding is unconfirmed and must not be reported as observed activity.
7. **IF** telemetry source covering the specific resource or selector is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`ssrf`](../../../red-team/web-and-application/ssrf/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Coverage assertion, selector proof, identity pivot, cross-account scope |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Trail status, event data store queries, activity-log export, principal lookup |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The rule must be authored for multiple backends from one source | [`sigma-rule-authoring-cloud-and-network-rules`](../sigma-rule-authoring-cloud-and-network-rules/SKILL.md) | Cloud logsource categories and pipeline conversion |
| The activity is credential misuse rather than cloud misconfiguration | [`identity-and-authentication-monitoring`](../identity-and-authentication-monitoring/SKILL.md) | Token and sign-in semantics live there |

## Procedure

1. **Prove the audit plane before reading any event.** For each provider under question, enumerate which destinations exist (trail and its selector, organization trail, event data store, diagnostic setting, audit log sink), which event classes each covers, and their retention. A query written before this step answers a question about a different log than the one that exists.
2. **Classify the question as control plane or data plane, then choose the source.** Control-plane questions can be answered from the default audit stream; data-plane questions must be answered from a destination whose selector was explicitly verified to include that resource class. Record which one you used in the output.
3. **Fix identity attribution before aggregating.** Resolve the actor to role ARN or access key ID plus source IP and, where present, the session chain or `roleSessionName`. Aggregating on a display name lets a rename or a shared role make unrelated principals look like one actor.
4. **Define the baseline-versus-probe differential.** Build a per-principal, per-action baseline from a quiet window of the same length as the probe window, then compare action sets rather than volumes: new action names for an existing principal, new principals for an existing action, and new source networks for either.
5. **Branch on the evidence shape.** A first-seen action by a known principal is a discovery hypothesis; a known action by a first-seen principal is a persistence hypothesis; a role chain that terminates in a credential or policy change is a privilege-escalation hypothesis. Each branch reads different fields and neither substitutes for the other.
6. **Name the stop condition.** Stop and declare `Inconclusive` when the resource's data events were never selected, when the organization scope cannot be queried from the account you can reach, when the window exceeds the destination's retention, or when the provider's event history is the only source and the window exceeds its 90-day management-event limit.
7. **State what counts as proof.** Proof is the audit event itself — event name, acting identity with its full assumed-role chain, source address, resource identifier, request parameters — corroborated by either the resulting resource state (the policy now attached, the key now created) or the provider finding that cites the same request. A finding alone is a lead; a state difference without an audit event is a gap, not an attribution.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Trail or diagnostic-setting status per region and account, including selector content | coverage assertion | Whether management and data events are actually delivered for the resources in scope; the precondition for every later claim |
| CloudTrail `eventName` first-seen per `userIdentity.arn` over a 30-day baseline | action novelty | A principal doing something it has never done, which is the highest-yield control-plane signal and survives renaming |
| Object-level `GetObject` or `GetSecretValue` events joined to the requesting role session | data-plane access | Who read the specific object or secret, only possible when the data-event selector was proven in step 1 |
| Role-assumption chain from `AssumeRole` to the action that follows within one session | session chain | Whether the action came from a federated identity, a CI role, or an instance role being abused off-host |
| Provider finding (GuardDuty, Defender for Cloud, SCC) matched back to its source audit event | corroboration | That the finding is grounded in a real request rather than a heuristic on unrelated telemetry |
| Azure Activity Log operation name compared across subscriptions for one principal | multi-scope differential | Whether a principal that is quiet in one subscription is performing the same action in another, which a per-subscription view hides |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```sql
-- Fires on any identity change, in every account, with no scope or baseline.
SELECT eventTime, userIdentity.arn, eventName
FROM cloudtrail_events
WHERE eventName LIKE '%Policy%' OR eventName LIKE '%Key%' OR eventName LIKE '%Role%'
-- Reads management events only, so a data-plane exfiltration is invisible.
-- No account or region scope, no retention check, and the LIKE terms
-- match routine automation on every scheduled run.
```

**High-Signal Grounded Artifact:**

```sql
-- First-seen action per principal against a 30-day baseline, management events only,
-- scoped to the accounts and region whose trail selector was verified in step 1.
WITH base AS (
  SELECT useridentity.arn AS principal, eventname, COUNT(*) AS n
  FROM cloudtrail_events
  WHERE eventtime BETWEEN TIMESTAMP '2026-10-14 00:00:00' AND TIMESTAMP '2026-11-13 00:00:00'
    AND awsregion = 'eu-west-1'
  GROUP BY 1, 2
),
probe AS (
  SELECT useridentity.arn AS principal, eventname, COUNT(*) AS n, MIN(eventtime) AS first_seen
  FROM cloudtrail_events
  WHERE eventtime >= TIMESTAMP '2026-11-13 00:00:00'
    AND awsregion = 'eu-west-1'
  GROUP BY 1, 2
)
SELECT p.principal, p.eventname, p.n, p.first_seen
FROM probe p LEFT JOIN base b USING (principal, eventname)
WHERE b.principal IS NULL AND p.n >= 1
ORDER BY p.first_seen DESC
```

**Why this matters:** the strong form answers a scoped question — first-seen action inside a region whose selector was verified, against a same-length baseline — so each returned row is a principal doing something new and reviewable; the weak form matches substrings across an unscoped window, cannot see data-plane activity at all, and returns the automation it was always going to return.

## When It Is NOT This Issue

- **Data events never selected:** a bucket, queue, or secret store without a data-event selector produces a query result that is identical to "nobody read it". Assert the selector before interpreting any empty result on a data-plane question.
- **Member account looking for organization events:** a member account cannot see an organization trail or organization event data store; running the query there returns nothing regardless of what happened. Confirm the query runs from the management or delegated-administrator scope.
- **Event-history window mistaken for retention:** the provider's built-in event history holds a bounded window of management events per region and is not a substitute for a trail into durable storage. A clean result over a longer window is a retention artefact.
- **Detector latency or a suppressed finding:** the managed detector consumes a duplicated management-event stream and reports on its own schedule; a finding that has not appeared yet is not absence, and a suppressed or archived finding is not a clean result.
- **Infrastructure-as-code applying on a schedule:** a deployment pipeline that reconciles IAM, key policy, and network configuration hourly will produce a steady stream of policy and role events that look like escalation. Correlate the principal to the pipeline's role and the change to the repository commit before escalating.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude an account, subscription, or project is 'clean' when the audit destination, selector, or detector covering it was disabled, misconfigured, or outside its retention.**
- **NEVER present an empty data-plane result as evidence of no access without naming the selector that was verified to include that resource.**
- **NEVER recommend destructive containment (deleting roles, disabling accounts, or revoking all sessions tenant-wide) before preserving the audit evidence and checking the blast radius across dependent workloads.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** every audit destination in scope was enumerated with its selector and retention, and the plane (control versus data) was matched to a destination that actually carries it.
- [ ] **Differential defined:** a same-length quiet window was compared against the probe window on action sets per principal, not on raw volume, and the comparison basis is stated.
- [ ] **Stop condition stated:** unselected data events, member-account scope, retention ceiling, or provider event-history limit is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** the audit event with its full identity chain and resource identifier is quoted, and corroborated by resulting resource state or a grounded finding that cites the same request.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: cloud-detection-and-logging
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Provider and destination, selector content, event class, accounts and regions, UTC baseline and probe windows, retention]
- **Behavioral Analysis**: [Action novelty, principal novelty, source-network novelty per principal; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Resource state after the action, provider finding and the audit event it cites, sibling subscription or project checked]
- **Containment / Detection / Hardening Action**: [Selector or onboarding fix, exact rule or query to deploy, session or key revocation step sequenced after evidence capture]
```

## Related Sub-Skills

- [`ssrf`](../../../red-team/web-and-application/ssrf/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Plane first, query second:** the most common wrong cloud conclusion is a data-plane question answered from the control-plane stream. State the plane and the selector in every answer.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); OCSF 1.6 class 6003 (API Activity) and 3002 (Authentication) are the portable shape for cross-provider rules.
- **Safety & authorization:** Perform only read-only inventory and query operations; never disable a trail, detector, or diagnostic setting to "reduce noise" inside an investigation, and never revoke sessions before volatile evidence is captured.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (7), CYBER_CPT/hacktricks_cloud (2), CYBER_CPT/wiz_research (2), bug-bounty-pentest-en (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
