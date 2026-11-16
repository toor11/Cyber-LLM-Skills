# Operational Triage and Response Playbook

> Sub-skill: [`web-application-incident-response-webshell-discovery`](SKILL.md) | Family: **Incident Response**

Structured runbook for `web-application-incident-response-webshell-discovery`. Paired offensive/mechanics reference: [`file-upload-and-webshell`](../../../red-team/web-and-application/file-upload-and-webshell/SKILL.md).

## Triggers

- File-integrity monitoring alarms on a new or changed file in a served directory.
- A worker process spawns a shell, a downloader or a scripting host on a web tier.
- Access logs show repeated small responses to one client on an unexpected script path.
- An external party reports a shell URL, or a vulnerability scanner flags a known shell path.
- The parent web compromise skill has established an entry vector and needs the artifact found.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Untracked executable file plus a request to its path plus a worker child process | Confirmed Malicious - Executed | Preserve, then isolate the tier; rotate the application identity's credentials |
| Untracked executable file plus requests, no child process | Confirmed Malicious - Addressed | Preserve; treat as executed capability, because eval-only shells spawn nothing |
| Untracked executable file with no request history | Staged Capability | Preserve and hash; scope how it arrived; do not report as compromise |
| Manifest hash mismatch on a legitimate framework file | Confirmed Malicious - Concealed | Diff against the released file and preserve both; a listing would have missed it |
| Candidate file only in a runtime-writable directory with a matching content type | Benign Baseline | Record the application path that writes there; narrow the FIM exclusion |
| FIM disabled or access logging absent for the window | Inconclusive - Telemetry Gap | Do not close; onboard coverage and state the unprovable interval |
| Same file hash found on multiple hosts | Confirmed - Same Artifact, Multiple Hosts | Scope all hosts by hash first, then by path; one shell deployed widely implies one access path |

## Containment and Recovery

1. **Preserve before removing, and preserve the request history with the file.** The artifact explains capability; the log explains dwell time and what was done. Removing the file first destroys the second half of the evidence and is the single most common avoidable loss in this class.
2. **Assume the application identity is compromised, not just the host.** The shell ran as the service account; its database connection strings, file share access, cloud role and any cached credentials are all in scope. Rotating the host without rotating those leaves the access path open.
3. **Find the placement vector before rebuilding.** A shell placed by an upload flaw, a vulnerable plugin or a stolen admin session will return to a rebuilt host that keeps the same flaw. The access-log reconstruction answers this and is not optional.
4. **Hunt the hash before hunting the behaviour.** The same artifact on multiple hosts is fast to find; behaviour varies with what the operator did next and is slow to enumerate. Use the hash to bound the host set, then examine behaviour on each.
5. **Rebuild rather than clean, and verify the rebuild against the manifest.** Editing a compromised file leaves whatever else the operator placed; rebuilding from the release artifact and re-running the differential is the only way to state that the tier matches what was shipped.
