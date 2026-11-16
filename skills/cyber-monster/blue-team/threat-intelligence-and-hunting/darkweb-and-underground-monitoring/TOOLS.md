# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`darkweb-and-underground-monitoring`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `hibp`-style API | `curl -s -H "hibp-api-key: $KEY" https://haveibeenpwned.com/api/v3/breacheddomain/$DOMAIN` | Domain-level breach exposure without retrieving passwords | Cross-platform |
| `paste monitor` | vendor query for the domain and brand strings | Paste exposure with retrieval timestamps | Cross-platform |
| `whois`/`rdap` | `curl -s https://rdap.org/domain/example.com` | Confirm a lookalike is unrelated before escalation | Cross-platform |
| `jq` | `jq '.findings' findings.json` | Enumerate findings with their verification status | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Scoped exposure check: domain-level only, no credential testing, control comparison included.
set -uo pipefail
dom=${1:?domain}; control=${2:?control domain}
printf '== breach exposure (domain level) ==\n'
curl -s -H "hibp-api-key: $HIBP_KEY" "https://haveibeenpwned.com/api/v3/breacheddomain/$dom" |
  python -c "import json,sys; d=json.load(sys.stdin); print('accounts exposed:', sum(len(v) for v in d.values()))" || true
printf '== control comparison ==\n'
curl -s -H "hibp-api-key: $HIBP_KEY" "https://haveibeenpwned.com/api/v3/breacheddomain/$control" |
  python -c "import json,sys; d=json.load(sys.stdin); print('control exposed:', sum(len(v) for v in d.values()))" || true
printf 'retention: raw artefacts expire in 90d; only counts and domain retained\n'
```

## Verification

- The control domain result shows whether the finding is distinctive or simply the base rate for any domain.
- Only counts are printed, so no individual entries are retained by the workflow.
- No password or hash is retrieved or tested, which keeps the collection within the programme's basis.
