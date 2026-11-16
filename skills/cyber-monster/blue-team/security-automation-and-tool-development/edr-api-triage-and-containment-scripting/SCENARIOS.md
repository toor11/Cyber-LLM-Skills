# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`edr-api-triage-and-containment-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative EDR scripting failures, each with the artifact that proves the diagnosis.

## Case 1: Containment targeted the wrong identifier

- **Surface & Preconditions:** a script substitutes a hostname where the API expects its own machine id.
- **Root cause & impact:** the request either 404s (host not found) or, worse, resolves to an unintended record if the vendor accepts an alias. The analyst believes the host is contained while it keeps communicating.
- **Verification & fix:** resolve the hostname through the API's own query endpoint first, log the resolved id in the plan, and require the id in the write call.

## Case 2: A domain controller was contained

- **Surface & Preconditions:** a batch triage script contains everything flagged with a high risk score, and the protected list lives only in a runbook.
- **Root cause & impact:** authentication across the estate fails within minutes. Containing a DC is a self-inflicted outage, and the isolation may prevent the very access needed to remediate.
- **Verification & fix:** enforce the protected list in code against tags and name patterns, refuse with a recorded reason, and test the refusal with a fixture.

## Case 3: "Host not found" during a mass event

- **Surface & Preconditions:** a triage loop queries hundreds of hosts and the API returns 429 partway through.
- **Root cause & impact:** the script treats non-2xx as "unknown host", produces a list of apparently missing endpoints, and the response plan loses exactly the hosts in the busiest part of the incident.
- **Verification & fix:** distinguish 429/5xx from 4xx, retry with exponential backoff inside a bounded budget, and report unreached hosts separately from unresolved ones.

## Case 4: Two isolation actions for one host

- **Surface & Preconditions:** the first isolation succeeded but the HTTP response timed out; the operator re-ran the command.
- **Root cause & impact:** a second action is submitted against an already-isolated host, the vendor audit log shows two entries, and the release step now has an ambiguous count.
- **Verification & fix:** read `isIsolated` before acting and report `no_change` when the requested state already holds.
