# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`social-engineering-and-pretexting-voice-and-message-based`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `social-engineering-and-pretexting-voice-and-message-based`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Callback control tally

Baseline: calls where the process requires a callback. Probe: calls where the agent performed one. Differential: the proportion is the control's effectiveness, and each non-callback is a finding.

```bash
sqlite3 vishing.db "SELECT step_tested, COUNT(*) FROM call GROUP BY step_tested;"
sqlite3 vishing.db "SELECT COUNT(*) FROM call WHERE callback_performed=0;"
```

## Disclosure and debrief coverage

Baseline: contacts logged. Probe: contacts with a disclosure or debrief recorded. Differential: an interaction that ended without either is an open obligation.

```bash
sqlite3 vishing.db "SELECT COUNT(*) FROM call WHERE disclosure_given=0 AND debriefed_at IS NULL;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
