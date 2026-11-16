# Incident Response

> Tree: `blue-team/incident-response` | **25 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`incident-response-playbooks`](incident-response-playbooks/SKILL.md) | **flagship** | Builds and runs incident response playbooks: severity definition, roles, phases from detection through closure, and playbook maintenance |
| [`ransomware-response`](ransomware-response/SKILL.md) | **flagship** | Responds to ransomware: early containment, identifying the strain and entry vector, backup and recovery assessment, negotiation and regulatory co |
| [`botnet-and-application-ddos-mitigation`](botnet-and-application-ddos-mitigation/SKILL.md) | **core** | Responds to L3/L4 volumetric floods and L7 HTTP/2 Rapid-Reset or cache-bypass DDoS attacks: BGP Anycast/RTBH upstream scrubbing, JA3/JA4 + ASN/ra |
| [`business-email-compromise-response`](business-email-compromise-response/SKILL.md) | **core** | Responds to business email compromise: mailbox rule and token review, session revocation, payment fraud containment and downstream victim notific |
| [`cloud-incident-response`](cloud-incident-response/SKILL.md) | **core** | Responds to cloud incidents: identity-based containment, audit log reconstruction, snapshot acquisition and service-specific evidence sources |
| [`compromised-credentials-and-token-revocation-playbook`](compromised-credentials-and-token-revocation-playbook/SKILL.md) | **core** | Executes enterprise-wide credential, OAuth refresh-token, PRT, Kerberos `krbtgt` (double-reset spacing), and cloud STS session revocation without |
| [`containment-and-eradication`](containment-and-eradication/SKILL.md) | **core** | Contains and eradicates threats without destroying evidence or tipping off the adversary, including isolation choices and re-entry validation |
| [`evidence-handling-and-chain-of-custody`](evidence-handling-and-chain-of-custody/SKILL.md) | **core** | Preserves evidence defensibly: acquisition order (volatile first), hashing, custody documentation and storage integrity |
| [`insider-threat-investigation`](insider-threat-investigation/SKILL.md) | **core** | Investigates insider threat: behavioural indicators, data access patterns, evidence handling constraints and coordination with HR and legal |
| [`ir-triage-and-timeline`](ir-triage-and-timeline/SKILL.md) | **core** | Triages an incident and builds a defensible timeline: scoping the blast radius, collecting initial evidence and sequencing events |
| [`post-incident-review-and-lessons`](post-incident-review-and-lessons/SKILL.md) | **core** | Runs a blameless post-incident review: reconstructing what happened, identifying control and process gaps, and tracking remediation to closure |
| [`raas-extortion-and-negotiation-triage`](raas-extortion-and-negotiation-triage/SKILL.md) | **core** | Handles double/triple-extortion Ransomware-as-a-Service (RaaS) incidents: data-exfiltration volume confirmation from egress/cloud logs, OFAC/sanc |
| [`web-application-incident-response`](web-application-incident-response/SKILL.md) | **core** | Responds to web application compromise: web shell discovery, access log analysis, source integrity checks and identifying the exploited vulnerabi |
| [`cloud-incident-response-audit-reconstruction`](cloud-incident-response-audit-reconstruction/SKILL.md) | **leaf** | Cloud audit log reconstruction |
| [`cloud-incident-response-identity-containment`](cloud-incident-response-identity-containment/SKILL.md) | **leaf** | Cloud identity containment |
| [`crisis-communication-and-escalation`](crisis-communication-and-escalation/SKILL.md) | **leaf** | Manages incident communication: escalation paths, stakeholder updates, external notification coordination and message discipline |
| [`denial-of-service-response`](denial-of-service-response/SKILL.md) | **leaf** | Responds to denial of service: distinguishing volumetric from application-layer, mitigation options, provider coordination and business continuit |
| [`legal-and-regulatory-notification`](legal-and-regulatory-notification/SKILL.md) | **leaf** | Handles legal and regulatory obligations after an incident: breach notification thresholds, timelines, regulator and customer communication, and |
| [`ransomware-response-containment-and-scoping`](ransomware-response-containment-and-scoping/SKILL.md) | **leaf** | Ransomware containment and scoping |
| [`ransomware-response-recovery-and-restore`](ransomware-response-recovery-and-restore/SKILL.md) | **leaf** | Ransomware recovery and restore |
| [`ransomware-response-strain-and-actor-identification`](ransomware-response-strain-and-actor-identification/SKILL.md) | **leaf** | Ransomware strain and actor identification |
| [`supply-chain-incident-response`](supply-chain-incident-response/SKILL.md) | **leaf** | Responds to supply chain compromise: identifying affected versions, blast radius across consumers, coordinated disclosure and rebuild strategy |
| [`tabletop-exercise-design`](tabletop-exercise-design/SKILL.md) | **leaf** | Designs and runs tabletop exercises: scenario construction, inject design, participant roles and after-action improvement |
| [`web-app-incident-access-log-exploitation-analysis`](web-app-incident-access-log-exploitation-analysis/SKILL.md) | **leaf** | Access log and exploitation analysis |
| [`web-application-incident-response-webshell-discovery`](web-application-incident-response-webshell-discovery/SKILL.md) | **leaf** | Web shell discovery and analysis |
