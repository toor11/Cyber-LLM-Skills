# Detection Signals and Blue-Team Handoff

> Sub-skill: [`classical-and-covert-encoding`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Upload event: stored object size exceeding the decoded pixel or document size by more than a few hundred bytes — the appended-region signature.
- MIME validation log: `Content-Type` accepted while the decoded format differs from the declared one.
- Text-field content scan: count of Unicode category `Cf` characters per submitted comment, name, or bio, alerted on runs rather than single occurrences.
- Egress field: `Content-Length` on a download that exceeds the stored artefact's indexed size.
- DNS or HTTP log: base64-looking labels or paths with length above 60 and no dictionary words, which is the encoded-payload shape.
- WAF event: a rule that decodes and inspects a parameter firing while a raw-inspection rule does not, which shows the decoding gap.
- Object-store audit: a single object written with a size delta over the previous version while its metadata hash is unchanged.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
