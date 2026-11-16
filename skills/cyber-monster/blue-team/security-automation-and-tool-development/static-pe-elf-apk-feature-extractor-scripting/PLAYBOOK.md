# Operational Triage and Response Playbook

> Sub-skill: [`static-pe-elf-apk-feature-extractor-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a sample-analysis incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- An extraction run stops partway through a corpus.
- A classifier's decisions shift without a model change.
- A sample produces an implausible vector (empty imports, impossible entropy).
- A packed sample yields no capabilities.

## Triage Decision Matrix

| Observation | Next verdict | Immediate action |
|---|---|---|
| Run stopped at one sample | Parser exception | Catch per sample, record hash and error, resume from the failure point |
| Feature drift after an image rebuild | Parser version change | Pin the version, re-extract the reference set, compare vectors |
| Empty import table on a large binary | Packed or heavily obfuscated | Record as statically unanalyzable; escalate to dynamic analysis |
| Memory spike on one sample | Declared-size trust | Apply the cap, skip and record, re-run |
| Capa returns nothing | Unrecoverable features | Do not treat as benign; state the limitation in the report |

## Containment and Recovery

1. **Preserve before mutating:** keep the sample hash, the parser name and version, and the raw extraction output. The sample is executable content; handle it in a non-executable analysis location.
2. **Check blast radius:** determine whether the defect affects one sample or an entire corpus run, and how many samples were silently skipped.
3. **Eradicate the root cause:** fix the cap or per-sample guard, re-extract the full corpus, and compare against the reference pair of known-good and known-bad samples before publishing vectors.
