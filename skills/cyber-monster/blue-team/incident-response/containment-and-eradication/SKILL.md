---
name: containment-and-eradication
description: Contains and eradicates threats without destroying evidence or tipping off the adversary, including isolation choices and re-entry validation. Use once an incident is confirmed.
family: incident-response
tier: core
triggers: ["containment", "eradication", "isolate host", "remediation incident"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, ir-triage-and-timeline, ransomware-response, business-email-compromise-response]
---

# Containment and Eradication - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Containment is the phase where an incident response most often creates a second incident. The actor's persistence is not usually on the host you isolate; it is in the credential the host used, the service account the application ran under, the scheduled task that re-creates the implant, or the trust relationship that lets a new host join. Isolation therefore has two simultaneous effects: it removes the actor's access to that asset, and it tells the actor they have been noticed, which in an extortion or ransomware case typically accelerates destructive action elsewhere. The technical preconditions for a containable incident are that scope is bounded before isolation begins — which assets, which identities, which data — and that each containment action is reversible or at least non-destructive to evidence. The organisational precondition is authority: NIST SP 800-61r3 (April 2025) makes explicit that an incident response plan must name which roles have the authority to confiscate, disconnect, or shut down technology assets, precisely because the moment of containment is not the moment to negotiate it. Eradication is a separate step with a separate proof standard: removing the implant is not eradication if the initial-access vector, the persistence mechanism and the credential that authorised it remain. A host rebuilt and returned to the network while the service account is still valid is a re-entry, not a recovery.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** scope is not yet bounded **THEN** contain narrowly and reversibly (network isolation of the specific host, session revocation of the specific principal) rather than broadly; **IF** the actor is already conducting destructive action **THEN** prefer broad containment and accept service impact, because the destructive clock outranks the scoping clock.
2. **IF** containment would remove the responder's own administrative path or the last domain controller **THEN** stage the replacement and verify it before acting; **IF** no replacement exists **THEN** record the dependency and contain by credential rather than by host.
3. **IF** the actor's persistence is unknown **THEN** treat every credential used on the contained asset as compromised, because isolating the host leaves the credential live and the actor re-enters from elsewhere.
4. **IF** a legal hold, insurer requirement or regulatory clock applies **THEN** preserve before containment changes state; volatile memory and the current log set cannot be reconstructed after a rebuild.
5. **IF** the asset is a safety system, a clinical device, or a control-system component **THEN** the containment decision escalates to the asset owner, and the technical plan must state what the asset does without network connectivity.
6. **IF** telemetry source covering `isolation` / `network block` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `containment-and-eradication` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for isolation and re-entry attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Verification entry points for containment state |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Bound the scope on paper before touching the estate.** List the assets, identities, data stores and trust relationships the actor has demonstrably touched, the ones they could have touched from those, and the ones you cannot rule out. Write the criteria used for each classification; that list is what makes the containment proportionate and later defensible.
2. **Choose the containment primitive per asset class.** Network isolation for endpoints, session and credential revocation for identities, policy or key rotation for cloud principals, mail-flow restriction for mailboxes, and segmentation for network segments. Name the primitive and its collateral for each, because isolation, revocation and blocking differ in what they break and in how they are proven.
3. **Establish the pre-containment baseline for the contained assets.** Record their normal process tree, authentication pattern, network peers and telemetry channels. After containment, this is how a genuine re-entry is told from an agent that is merely retrying or a management console that keeps polling.
4. **State the stop condition.** Containment stops when every in-scope asset reports the containment state from the enforcing layer, the actor's known credentials are revoked, and no in-scope asset shows actor-attributable activity. Eradication stops when the initial-access vector is closed, every identified persistence mechanism is removed, and a defined monitoring window passes with no recurrence on the same vector.
5. **Prove it from the enforcing layer, not from the console that issued it.** An isolation is proven by the agent or network policy reporting the contained state on the asset and by a failed attempt to reach it; a revocation is proven by the issuer's audit event plus a failed re-use. The command that returned success proves only that the request was accepted.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| EDR network-isolation state reported by the agent on the asset, with the policy version | Endpoint agent status record | The containment is enforced at the endpoint and survives a management-plane change, as opposed to a firewall rule that may not cover the path |
| Failed connection attempts from the contained asset to its historic C2 or peer set after isolation | Network telemetry or firewall deny log | Isolation actually blocks egress rather than only blocking inbound management |
| New authentication from a credential used on the contained asset, from a different asset | Identity or directory authentication log | The credential was not revoked, so containment of the host did not contain the actor |
| Re-created service, scheduled task, or run key with a creation time after eradication | Endpoint process and persistence artifact | Eradication was incomplete: a persistence mechanism survived and re-established the implant |
| Asset re-join or re-enrolment event for a host that was rebuilt | Directory or MDM enrolment record | Whether the rebuilt host was returned to the estate under a new identity, which is the re-entry question |
| Monitoring window with zero recurrences on the same initial-access vector | Detection telemetry over the declared window | The specific vector is closed, which is narrower and more honest than declaring the actor gone |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK CONTAINMENT:
isolate the host, reimage it, return it to the network.
# The service account it ran under is untouched and still valid.
# The scheduled task that re-created the implant lived in a GPO.
# Three days later the same implant is back on the same host, and the
# team concludes the actor "has another way in" rather than that
# eradication never covered the persistence and credential layers.
```

**High-Signal Grounded Artifact:**

```yaml
containment_plan:
  asset: FS-01
  primitives:
    - network_isolation_by_agent
    - credential_revocation_for_service_account_svc_fs
  scope_criteria:
    confirmed_touched: [FS-01, svc_fs]
    could_have_touched: [file share cluster, backup target]
    cannot_rule_out: [domain admin group membership]
  baseline_before:
    process_tree_parents: [services.exe, svchost.exe]
    auth_peers: [DC01, DC02, BACKUP01]
    telemetry_channels: [edr, winlogbeat, sysmon]
  stop_condition:
    isolation_state_reported_by_agent: true
    svc_fs_revoked_with_issuer_event: true
    no_actor_activity_after: "<timestamp>"
  proof_standard:
    - agent status shows contained with policy version
    - egress attempt to historic peer fails at the enforcing layer
    - issuer audit event for each revoked credential plus failed re-use
```

**Why this matters:** Non-destructive verification check; compare against baseline.

## When It Is NOT This Issue

- **Planned DR test or failover:** isolation-like network states and mass re-registration are exactly what a failover exercise produces. Check the exercise calendar and the change record before treating the pattern as containment.
- **EDR or agent upgrade during the window:** agents report a contained or degraded state while updating, and their telemetry gaps look like evasion. Correlate with the agent version rollout schedule.
- **A management console that keeps polling an isolated host:** the repeated connection attempts after isolation are the console retrying, not the actor. Attribute by source address and user-agent before calling it re-entry.
- **Legitimate service-account automation on a rebuilt host:** a rebuild changes the host identity, and automation re-authenticating with a documented account is expected. Confirm the account is in the dependant map.
- **An asset owner's own maintenance:** a host that reboots, re-joins and picks up new tasks inside the window may be under scheduled maintenance. Verify with the owner rather than from telemetry alone.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `isolation` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Scope bounded with stated criteria:** confirmed, possible and cannot-rule-out assets are listed with the basis for each classification, and the containment is proportionate to that list.
- [ ] **Primitive chosen per asset class:** each in-scope asset has a named containment primitive with its collateral effects documented, rather than one action applied uniformly.
- [ ] **Pre-containment baseline captured:** process, authentication and network baselines plus volatile evidence were recorded before state changed.
- [ ] **Credentials treated as compromised:** every credential used on a contained asset was revoked or explicitly risk-accepted with an owner and a date.
- [ ] **Enforcement attested:** containment state is proven from the enforcing layer plus a failed attempt, and eradication is proven by a monitored window with no recurrence on the same vector.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: containment-and-eradication
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
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)
- [`web-application-incident-response`](../web-application-incident-response/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `containment-and-eradication` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/ctf_search (5), cyber-security/CyberSec-Dataset (3), CYBER_CPT/gh_advisories (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
