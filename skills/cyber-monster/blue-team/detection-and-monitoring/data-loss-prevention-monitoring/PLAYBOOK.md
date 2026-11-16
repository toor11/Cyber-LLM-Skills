# Operational Triage and Response Playbook

> Sub-skill: [`data-loss-prevention-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `data-loss-prevention-monitoring`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- A DLP verdict of high or critical severity names a data class and a destination outside the sanctioned set.
- An identity's outbound volume to an unrecognised destination exceeds its own baseline by a large margin.
- A user account begins contacting a personal-storage or paste domain that is new to the fleet.
- A departing or role-changing employee's egress pattern shifts while their device still has repository access.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Verdict names a data class, the transfer record reaches an unsanctioned destination, and the endpoint shows the same principal reading that file | Confirmed Malicious / Gap | Preserve the transfer record and file hash, notify the data owner for classification, then block the destination for that identity only |
| Large transfer to a sanctioned tenant with a verdict naming an internal document the user owns | Benign Baseline (Policy Scope) | Route to tuning; the content class and the destination set are misaligned, so the rule needs a destination condition, not the user an investigation |
| Volume spike attributable to a backup or sync agent under a service identity | Benign Baseline (Automation) | Record the agent process and destination pair, add them as a named exclusion on that destination class only, and re-check after the next agent upgrade |
| Verdict exists but the channel has no transfer record and no endpoint read | Inconclusive (Join Failure) | State which leg is missing, attempt the join on message identifier, and name the logging gap in the ticket rather than closing as benign |
| Transfer to an external destination with no DLP inspection point on that channel | Inconclusive (Channel Not Inspected) | Escalate as a coverage gap with the destination and volume; the content classification is unknown and cannot be inferred |
| First-seen destination with modest volume and no verdict | Lead (Novelty Only) | Enrich the destination reputation, check whether the identity has a business reason, and observe before containing |
| Proxy logs sampled during the transfer window | Inconclusive (Sampling Gap) | Size the transfer from firewall or capture data; never report a sampled total as the volume |

## Containment and Recovery

1. **Preserve before mutating:** capture the DLP verdict, the transfer record with its identifier, the endpoint file-read event, and the file hash; a blocked destination removes the ability to re-measure the transfer.
2. **Scope the destination before blocking it:** determine whether other identities legitimately use the same domain; block per identity or per URL path rather than at the domain, which may be a shared CDN.
3. **Engage the data owner before the manager:** classification authority and notification obligations belong to the data owner and the privacy function, not to the SOC analyst.
4. **Close the coverage gap in the same change:** a channel that produced no verdict is an onboarding ticket with an owner and a date; without it the next transfer takes the same blind path.
