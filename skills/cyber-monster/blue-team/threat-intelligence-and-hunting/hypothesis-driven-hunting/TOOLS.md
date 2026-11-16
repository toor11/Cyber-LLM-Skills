# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`hypothesis-driven-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sigma` | `sigma list rules/ --filter 'logsource.product=windows'` equivalent over the rule repository | Duplication check against existing coverage | Cross-platform |
| `jupyter`/`pandas` | `pd.read_json('baseline.jsonl').groupby('host').size()` | Baseline noise estimation before committing the window | Cross-platform |
| `mitreattack-python` | `d.get_object_by_attack_id('T1218', 'attack-pattern')` | Confirm the technique id and its current tactic placement | Cross-platform |
| `git` | `git log -- hunts/` | History of hypotheses and their outcomes | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```text
<!-- hunts/H-2026-42.md -->
# H-2026-42 Signed interpreter proxy from Office parentage

- mechanism: signed binary -> script host -> outbound fetch, avoiding unsigned blocks
- technique: T1218 (System Binary Proxy Execution)
- population: 240 finance workstations, business hours, 2026-10-01..2026-11-12
- baseline: 2026-08-01..2026-09-30, expect 0
- falsification: zero qualifying connections with EID 1 and 3 coverage verified
- ranking: high impact, low baseline noise, data adequate
- outcome: (filled at closure)
```

## Verification

- The falsification line is written before the outcome, which the template enforces by ordering.
- The baseline window precedes the probe window, so the comparison is temporal rather than post-hoc.
- The outcome field stays empty until closure, so a hypothesis cannot be retro-fitted to its result.
