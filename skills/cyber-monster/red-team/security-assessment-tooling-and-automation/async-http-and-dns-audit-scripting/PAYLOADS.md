# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`async-http-and-dns-audit-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `async-http-and-dns-audit-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Single-host baseline then probe

Baseline: two HEAD requests to the same URL. Probe: the same request with the header under test. Differential: status or body hash changes while the control pair stays identical.

```bash
curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' -I https://target.example/
curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' -I -H 'X-Forwarded-Host: canary.example' https://target.example/
```

## Resolver pinning check

Baseline: query through the system resolver. Probe: query the authoritative NS directly. Differential: a different answer set means a middlebox or search-domain rewrite is in play.

```python
python -c "import dns.resolver; r=dns.resolver.Resolver(configure=False); r.nameservers=['198.51.100.53']; print(r.resolve('target.example','A').response.answer)"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
