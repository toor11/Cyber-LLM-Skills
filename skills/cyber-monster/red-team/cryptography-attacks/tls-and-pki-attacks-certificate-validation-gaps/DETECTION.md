# Detection Signals and Blue-Team Handoff

> Sub-skill: [`tls-and-pki-attacks-certificate-validation-gaps`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Application log: TLS verification failures by `verify_message`, where a sudden absence of failures on a client indicates verification was disabled.
- Configuration audit: a verification flag set to a permissive value in any non-test manifest.
- Metrics: outbound TLS connections per client identity, compared with the expected set of destinations, which surfaces a disabled-verification path accepting a hostile host.
- Code-scanning rule: an overridden trust manager or hostname verifier, or a pin compared against a subject or serial.
- Trust-store audit: the CA bundle contents per application image, alerted on any addition.
- Certificate transparency signal: a certificate for an estate hostname issued by a CA outside the approved set, which is the substitution attempt.
- Dependency signal: an SDK version whose default verification changed, which can silently alter behaviour.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
