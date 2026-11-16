# Operational Triage and Response Playbook

> Sub-skill: [`windows-evtx-and-powershell-audit-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for an event-log parsing incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A PowerShell execution report shows script stubs rather than full script text.
- Parser record counts disagree with `Get-WinEvent` on the same file.
- An evidence `.evtx` fails to parse past a specific offset.
- A collection job returns zero records for a log known to be active.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| 4104 blocks emitted with 1 fragment each | Unknown-total defect | Stop defaulting `MessageTotal` to 1; key on Computer + ScriptBlockId and flush at EOF |
| Two scripts interleaved in one block | Key collision | Add the Computer component to the key and re-parse from the original file |
| Parse stops at a fixed offset | Corrupt chunk | Guard per-record parsing, count corrupt records, continue past them |
| Zero records from a live channel | Collection method | Use `Get-WinEvent` against the channel; do not read the service-held file |
| Counts differ by exactly the corrupt count | Expected | Document the corrupt count in the evidence notes; do not "fix" the parser |

## Containment and Recovery

1. **Preserve before mutating:** hash the `.evtx` before parsing and keep the hash in the report; the parsed JSONL is derived evidence and must be attributable to one immutable input.
2. **Check blast radius:** establish whether the defect affects one host's log or an entire collection run before re-running anything, since re-parsing can overwrite derived artifacts.
3. **Eradicate the root cause:** fix the reassembly or guard, re-parse the original file, and reconcile counts before the derived output is used in a report.
