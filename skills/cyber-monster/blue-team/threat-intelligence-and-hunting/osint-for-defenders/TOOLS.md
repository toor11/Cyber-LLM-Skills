# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`osint-for-defenders`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `crt.sh` | `curl -s 'https://crt.sh/?q=%25.example.com&output=json'` | Certificate transparency for naming exposure | Cross-platform |
| `github search` | `gh search code 'example.com password' --limit 50` | Public code mentions with a rate-limited, authenticated query | Cross-platform |
| `whois`/`rdap` | `curl -s https://rdap.org/domain/examp1e-login.com` | Lookalike registration context | Cross-platform |
| `dig` | `dig +short MX examp1e-login.com` | Mail capability of a lookalike, which indicates intent | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Passive defender OSINT: naming exposure and lookalike mail capability.
set -uo pipefail
dom=${1:?registrable domain}
printf '== certificate naming exposure ==\n'
curl -s "https://crt.sh/?q=%25.$dom&output=json" |
  python -c "import json,sys; rows=json.load(sys.stdin); names={n.strip() for r in rows for n in (r.get('name_value') or '').splitlines()}; print('\n'.join(sorted(n for n in names if 'internal' in n or n.count('.')>3)))"
printf '== lookalike mail capability ==\n'
for cand in "${dom/e/3}" "${dom/example/examp1e}"; do
  [ "$cand" = "$dom" ] && continue
  printf '%s MX: ' "$cand"; dig +short MX "$cand" | head -1 || echo none
done
```

## Verification

- Internal-looking names in CT output are the naming exposure; their absence is a valid negative.
- A lookalike with an MX record is a stronger signal than one without, and the probe distinguishes them.
- No request goes to the lookalike's web service, which keeps the collection passive.
