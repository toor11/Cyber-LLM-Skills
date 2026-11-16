# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`social-engineering-and-pretexting-email-and-credential-phishing`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `social-engineering-and-pretexting-email-and-credential-phishing`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Cohort outcome tally

Baseline: recipients in the cohort. Probe: recipients who performed the forbidden step. Differential: the ratio measures the control, and each acting recipient needs a debrief.

```bash
sqlite3 phish.db "SELECT cohort, COUNT(*) FROM recipient GROUP BY cohort;"
sqlite3 phish.db "SELECT COUNT(*) FROM event WHERE action='submitted' AND debriefed_at IS NULL;"
```

## Sending domain verification

Baseline: the authorised domain. Probe: the domain in the message headers. Differential: a mismatch means the campaign used unauthorised infrastructure.

```bash
python -c "import yaml, email; d=yaml.safe_load(open('phish-scope.yaml')); print(d['sending_domain'])"
python -c "import email; m=email.message_from_bytes(open('sample.eml','rb').read()); print(m['From'], m['Return-Path'])"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
