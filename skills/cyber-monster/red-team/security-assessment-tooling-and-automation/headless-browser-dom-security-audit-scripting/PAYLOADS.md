# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`headless-browser-dom-security-audit-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `headless-browser-dom-security-audit-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Violation baseline vs probe

Baseline: clean load, zero violations. Probe: load with the one injected attribute. Differential: a violation naming the specific directive and the injected URI.

```python
page.on('console', lambda m: print(m.type, m.text))
page.goto('https://target.example/?q=canary', wait_until='domcontentloaded')
```

## Script origin inventory

Baseline: the document's own origin. Probe: every script request origin. Differential: an origin outside the declared allowlist is the finding, not merely a third-party host.

```python
page.on('request', lambda r: print(r.resource_type, r.url) if r.resource_type == 'script' else None)
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
