---
name: ir-triage-and-timeline
description: "Triages an incident and builds a defensible timeline: scoping the blast radius, collecting initial evidence and sequencing events. Use at the start of any suspected incident."
family: incident-response
tier: core
triggers: ["incident triage", "ir timeline", "scope incident", "initial triage"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, containment-and-eradication, ransomware-response, business-email-compromise-response]
---

# IR Triage and Timeline - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Triage exists because the first report of an incident is always wrong about scope. A helpdesk ticket, an EDR alert, or a threat-intelligence tip names one host or one account, while the intrusion behind it usually spans a credential, a host and a data store in that order. Triage turns a single observation into a defensible sequence by anchoring on the earliest event that can be corroborated, then extending forward and backward from that anchor on one clock. The precondition that makes an incident scoped and containable is unglamorous and non-negotiable: a single authoritative time base with measured per-host offset, retention that still covers the intrusion window, and a preserved copy of volatile state taken before anyone reboots, isolates or cleans the anchor host. Miss any of the three and every later step inherits an unbounded scope and an unprovable order.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the report names a host but no principal **THEN** take the endpoint-first branch (process lineage, file creation, local logons) and treat the account as a derived artifact; **IF** it names a principal but no host **THEN** take the identity-first branch (sign-in, token issuance, MFA and mailbox policy) and let the audit trail name the host.
2. **IF** neither a host nor a principal is named **THEN** start from the signal that raised the alert — egress volume, failed-then-succeeded authentication, or an availability change — and use it as the anchor until a host or principal appears.
3. **IF** a legal hold, insurer engagement or regulatory clock may attach to this incident **THEN** preserve and log first, and brief counsel before any containment action changes state; a reboot or wipe destroys the artifact that establishes the clock.
4. **IF** the anchor host's clock offset against the reference source exceeds a few seconds **THEN** normalise before ordering, and state the corrected offset; do not publish a sequence built on drifted timestamps.
5. **IF** the window contains an event-log clear, an audit-policy change or an EDR service stop **THEN** treat post-event absence as `INCONCLUSIVE`, not as inactivity.
6. **IF** telemetry covering the anchor host or principal is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** the incident is confirmed encryption or extortion **THEN** hand off to [`ransomware-response`](../ransomware-response/SKILL.md); triage stops at the handoff, it does not duplicate the recovery method.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the evidence classes and their attestation queries | [`QUERIES.md`](QUERIES.md) | Clock-integrity, first-seen and convergence queries |
| Need exact `log2timeline`/`psort`/`Velociraptor` flags | [`TOOLS.md`](TOOLS.md) | Collection and slicing without re-parsing the estate |
| Need the triage-to-containment handoff | [`PLAYBOOK.md`](PLAYBOOK.md) | Decision matrix and sequencing gates |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Incident has reached encryption or extortion | [`ransomware-response`](../ransomware-response/SKILL.md) | Different evidence and decision set |
| Principal-only report, mailbox or SaaS | [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) | Mailbox rule and token evidence live there |
| Confirmed scope, ready to isolate | [`containment-and-eradication`](../containment-and-eradication/SKILL.md) | Containment order and re-entry validation |

## Procedure

1. **Confirm the evidence source before believing the alert.** Enumerate which sources actually exist for the anchor host and principal — endpoint telemetry, security event log, identity-provider audit, proxy and DNS, cloud control plane — and measure each host's clock offset against a reference. A source that is absent, or a host minutes off true time, cannot support an ordering built on it.
2. **Choose the branch from what the first report names.** Endpoint-first builds process lineage and file-creation sequence around a named host. Identity-first builds sign-in, token-issuance and policy-change sequence around a named principal. Asset-unknown starts from the detection signal and is upgraded to one of the other two the moment a host or principal appears.
3. **Define a baseline-versus-probe differential.** For every host and principal inside the slice, compare hourly event counts and first-seen process, file and destination values against that host's own prior 14 days and against its peer cohort. A value that is new to the estate outranks any volume spike; volume mostly tracks ingest.
4. **Anchor, then extend by a bounded window.** Pick the earliest event corroborated by two independent sources, export a slice around it rather than a full-day dump, and record the anchor's source and whether it is confirmed or inferred.
5. **Name the stop condition.** Stop and declare `Inconclusive` when the anchor window falls outside retention, when the decisive channel was disabled for part of the window, when clock offset exceeds the tolerance that would reorder events, or when the only support is one low-fidelity feed. Do not soften these into "low confidence clean".
6. **State what counts as proof.** Proof is two independently onboarded sources agreeing on the same host and principal inside one UTC minute, or an audit or configuration event confirming the effect — a session actually issued, a service actually installed, a share actually written. A command that was merely issued is a lead, and the output must say which one you have.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| First-seen process under a web, office or archive parent | endpoint execution | A binary ran with no prior estate history under that parent; lineage localises the delivery |
| Network logon to a new host by an existing account | authentication | The account reached a host it has never used, which is movement rather than a typo |
| Sign-in success followed within the hour by a new mailbox rule or OAuth grant | identity control plane | The session was used to persist, which separates access from post-access |
| Event log clear, audit-policy change or sensor stop inside the window | telemetry integrity | Coverage of the window is partial; nothing after that point is provable from this host |
| File created in a served directory and a request to the same path | convergence | One event seen from the artifact plane and the request plane at once |
| Proxy or DNS record for a destination absent from the prior 14 days | network egress | Something new was contacted from this host regardless of what ran locally |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
index=* earliest=-24h "suspicious" | stats count by host
# No anchor, no clock check, no per-host baseline, no window bound.
# Returns a number that cannot be ordered, scoped or defended.
```

**High-Signal Grounded Artifact:**

```spl
index=edr sourcetype="edr:process" host=WKSTN-0417 earliest=-6h@h latest=+2h@h
| eval actor=coalesce(Account_Name,user_name), obj=coalesce(NewProcessName,process_path)
| eval baseline_key=strcat(host,"|",lower(obj))
| lookup firstseen_baseline baseline_key OUTPUT prior_hits
| where isnull(prior_hits)
| table _time, host, actor, obj, parent_process
# Bounded anchor window, one host, first-seen lookup populated from the host's own 14-day history.
# If the lookup was never populated for this host -> INCONCLUSIVE (baseline gap), not clean.
```

**Why this matters:** the strong form anchors on a named host and a bounded window and reports first-seen values against that host's own history, so each row carries the baseline it was measured against; the weak form counts a keyword across every index and produces a figure with no order, no scope and no defensible meaning.

## When It Is NOT This Issue

- **Sanctioned scanner or patch cycle:** an authenticated vulnerability scan or a maintenance window produces the same first-seen process and new-destination pattern from a known management host. Check the source host and the change record before you scope anything.
- **Clock drift reordering:** a host whose time service has been failing writes true events outside the anchor slice and then looks quiet. Verify time synchronisation before reading absence as inactivity.
- **Late or replayed ingest:** events indexed hours after their own timestamp fall outside a window filtered on event time. Widen on index time before declaring a gap.
- **Agent re-registration or host rename:** an EDR reinstall, a reimaged machine or a renamed asset creates a device record with no history and mimics a brand-new asset appearing in the estate.
- **Double ingestion of one channel:** a forwarder plus an API collector of the same log doubles every count inside the slice and manufactures a spike that no adversary caused.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is clean when endpoint, identity or network telemetry covering the anchor window was disabled, rotated out, or uncollected.**
- **NEVER present an inferred timestamp, a single-source ordering or a drifted clock as a confirmed sequence** — label every timeline row confirmed or inferred.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the sources used were enumerated for the anchor host and principal, not assumed from naming convention.
- [ ] **Clock normalised:** per-host offset against the reference was measured and stated, and any slice built on drifted hosts is labelled as such.
- [ ] **Differential defined:** a 14-day baseline or peer cohort was run for the same key, and the finding is the delta rather than an absolute count.
- [ ] **Stop condition stated:** retention, channel disablement and clock tolerance were each cleared or declared as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: ir-triage-and-timeline
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)
- [`web-application-incident-response`](../web-application-incident-response/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ir-triage-and-timeline` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 8 |
| Top sources | cyber-security/CyberSec-Dataset (2), CYBER_CPT/expku (2), CYBER_CPT/oxdf (2), CYBER_CPT/ctf_search (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
