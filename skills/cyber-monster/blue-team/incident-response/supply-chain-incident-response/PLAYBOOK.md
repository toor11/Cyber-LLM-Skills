# Operational Triage and Response Playbook

> Sub-skill: [`supply-chain-incident-response`](SKILL.md) | Family: **Incident Response**

Structured runbook for `supply-chain-incident-response`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Triggers

- A public advisory names a package, version range or registry artifact that appears anywhere in the dependency corpus.
- A registry, vendor or researcher reports that a maintainer account, publish token or build pipeline was compromised.
- A build or deploy unexpectedly changes artifact hash, image digest or dependency set with no change record.
- A downstream customer reports suspicious content attributed to an artifact this organisation published.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Affected version executed an install hook on a runner with reachable cloud roles | Confirmed Compromise - Identity Exposed | Rotate from a clean machine first, rebuild after; the runner's identity is the blast radius |
| Affected artifact fetched by a runner with install scripts disabled | Confirmed Exposure - No Execution | Pin a clean version, record the exposure, no credential rotation required on that runner |
| Lockfile pins the affected version, proxy shows no fetch in the window | Resolved Only | Correct the pin, document that no artifact was fetched, close without rotation |
| Manifest range permits the version but no lockfile resolves it | Not Exposed | Record the reasoning; verify the next install cannot resolve it |
| Proxy or CI history starts after the campaign window | Inconclusive - Coverage Gap | Report the gap explicitly; do not report a clean estate |
| Persistence artifact found in an IDE or agent config path | Confirmed Compromise - Persistence | Rotate, remove the persistence, rebuild; package removal alone is insufficient |
| Affected artifact baked into a published image or release | Confirmed Exposure - Downstream | Notify consumers and route the obligation question to legal |

## Containment and Recovery

1. **Rotate before rebuilding, and rotate from a machine that never ran the artifact.** A rebuilt runner that re-authenticates with a stolen token is compromised on its first job. The clean machine requirement is not ceremony; it is the difference between rotating a secret and re-leaking it.
2. **Order the rotation set by reach, not by convenience.** Registry publish tokens first — they allow propagation through your own identity — then cloud federated roles, then Vault paths and SSH keys, then package-manager and IDE tokens. Each tier enables the next.
3. **Remove persistence before returning the environment to service.** An IDE or coding-agent configuration that re-executes the payload on session start will reintroduce the compromise after a successful rebuild, and the second occurrence is always harder to explain.
4. **Pin the clean version by hash from a source you read.** Not the latest version, not the previous version, but the last one published before the campaign window with its integrity hash verified against a second source.
5. **Report exposure and compromise as separate counts.** Stakeholders and regulators need to know how many environments resolved the bad version, how many fetched it, and how many executed it. Collapsing the three produces an overstated incident and a credibility problem when the numbers are revised.
