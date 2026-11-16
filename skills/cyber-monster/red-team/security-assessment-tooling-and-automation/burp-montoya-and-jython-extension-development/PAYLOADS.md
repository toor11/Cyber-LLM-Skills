# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`burp-montoya-and-jython-extension-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `burp-montoya-and-jython-extension-development`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Passive differential on one response

Baseline: the response as received. Probe: the same response inspected for the marker the check keys on. Differential: the marker present with a stable offset across two responses of the same endpoint.

```text
GET /account HTTP/2
Host: target.example
-> inspect: response body contains reflected parameter value in an executable context
```

## Header normalisation check

Baseline: request with the header as captured. Probe: the same request after the extension's normalisation. Differential: exactly the targeted header changes and nothing else.

```text
GET /api/v1/items HTTP/2
Host: target.example
X-Trace: audit-canary-001
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
