# Operational Triage and Response Playbook

> Sub-skill: [`raas-extortion-and-negotiation-triage`](SKILL.md) | Family: **Incident Response**

Structured runbook for `raas-extortion-and-negotiation-triage`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

This playbook is victim-side decision support and escalation routing. It contains no negotiation tactic, no payment or cryptocurrency guidance, no actor contact path, and no ransom-amount reasoning. Those questions route to counsel, the cyber insurer and law enforcement, and their record is held outside this library.

## Triggers

- A note, portal or email asserts that data was copied as well as encrypted.
- Egress monitoring, DLP or a cloud audit review surfaces a large transfer to an unsanctioned destination before encryption was detected.
- A leak site lists the organisation, or a third party — customer, partner, journalist, regulator — reports that data attributed to the organisation is circulating.
- Encryption is contained and the next decision is whether a disclosure obligation exists.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Completed transfer to an unsanctioned destination, matched by classification to regulated data | Confirmed Exfiltration - Obligation Likely | Freeze the evidence, brief counsel with the classification join, start the obligation clock analysis |
| Completed transfer, classification unknown or catalogue incomplete | Confirmed Transfer - Obligation Open | Preserve, then resolve classification with the data owner; do not answer the obligation question from absence of a record |
| Staging artifacts but no egress plane for the window | Inconclusive - Telemetry Gap | Record the gap in the disclosure record; escalate to counsel as unresolved, not as negative |
| Actor claim with no transfer, no staging and no data-plane read | Unverified Claim | Route to counsel as an unverified assertion; keep containment and recovery moving independently |
| Transfer to a sanctioned bulk-egress endpoint | Benign Baseline | Record the endpoint and its owner; refresh the sanctioned list if it was missing |
| Data-plane read by an external principal | Confirmed Exfiltration - Data Plane | Treat as exfiltration regardless of whether egress telemetry agrees |
| Leak site references a dataset name present in internal inventory | Claim Corroborated Structurally | Scope the referenced dataset only; never access the site from corporate infrastructure |

## Containment and Recovery

1. **Separate the three questions and give each an owner.** What left is a technical question owned by the SOC. What obligation it creates is a legal question owned by counsel. Who decides the response is an executive question with a named authority. Collapsing them produces disclosure decisions made on unproven claims.
2. **Preserve egress evidence before touching the perimeter.** Changing firewall policy, rotating an egress proxy or rebuilding a host under investigation can remove the completion records that are the only proof either way. Export and hash first.
3. **Record law-enforcement engagement as a timestamped decision.** It is a documented mitigating factor in sanctions guidance, it may unlock decryption or attribution support, and its absence later is hard to explain. Name who decided and when.
4. **Treat sanctions screening as counsel's documented step, not a SOC analysis.** Preserve any actor identifier, wallet address or infrastructure indicator as an artifact and hand it over. Do not perform, interpret or record the screening outcome as a technical finding.
5. **Give counsel three answers, not one.** "Transferred and sensitive", "transferred, sensitivity unresolved", "unresolvable from available telemetry" are all legitimate outputs and each leads to a different decision. The one output never permitted is "no exfiltration" derived from a missing plane.
