# Operational Triage and Response Playbook

> Sub-skill: [`web-application-incident-response`](SKILL.md) | Family: **Incident Response**

Structured runbook for `web-application-incident-response`. Paired offensive/mechanics reference: [`cross-site-scripting`](../../../red-team/web-and-application/cross-site-scripting/SKILL.md).

## Triggers

- A web tier shows file-integrity alerts, unfamiliar worker child processes or unexpected outbound connections.
- The application returns content it should not, or serves a path nobody deployed.
- A WAF, CDN or vulnerability scanner reports an exploitation attempt that may have reached the origin.
- An application owner reports unexpected data volumes, unfamiliar administrative actions or records in the wrong place.
- A customer or external party reports content attributed to this application.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Worker spawned a shell or downloader and the request is in the log | Confirmed Malicious - Compromise | Preserve the tier, isolate it, enumerate and rotate the application identity's credentials |
| File hash differs from the release record, no child process, no request | Confirmed Malicious - Capability | Preserve and hash; find the placement vector before rebuilding |
| Appliance configuration or session changed inside the window | Confirmed Malicious - Edge Entry | Preserve appliance state before any firmware or config change |
| Application identity read data outside its baseline | Confirmed Malicious - Data Access | Quantify the read range and route the disclosure question to legal |
| 5xx burst with a matching deployment and no artifact change | Benign Baseline | Record the release identifier and close the tuning item |
| File integrity or access logging absent for the window | Inconclusive - Telemetry Gap | Do not close; onboard coverage and state the unprovable interval |
| Scanner traffic against a patched endpoint returning 403 | Benign Baseline | Confirm the origin rejected it; record the scanner range |

## Containment and Recovery

1. **Preserve the tier before touching it.** Archive the served tree, the effective configuration, the worker process tree and the open sockets, then hash the archive. A restart destroys the process tree, and the process tree is what distinguishes capability from execution.
2. **Choose the branch before choosing the action.** Edge entry means the appliance's configuration and credentials are the containment target; application entry means the identity and the code path are; identity entry means session revocation precedes everything. Acting on the tier when the entry was at the edge wastes the window.
3. **Treat the application identity as compromised, not just the host.** Enumerate its database logins, object-storage rights, cloud role and any cached token before deciding what to rebuild. A rebuilt host that reuses the identity reproduces the exposure.
4. **Identify the vulnerable code path from the reconstructed request, not from the file.** The placement artifact shows what arrived; only the request shows how. Hand the specific path, method and parameter to the application owner, or the rebuild reinstates the same flaw.
5. **Rebuild rather than clean, then re-run the differential.** Cleaning removes what you found and leaves what you did not. Rebuilding from the release record and re-running the integrity check is the only way to state that the tier matches what was shipped.
