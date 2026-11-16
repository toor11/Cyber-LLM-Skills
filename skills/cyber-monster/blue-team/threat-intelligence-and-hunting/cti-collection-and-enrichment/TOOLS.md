# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cti-collection-and-enrichment`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `taxii2-client` | `python -m taxii2client.collections --server $URL --user $U --password $P` | Enumerate collections before polling them | Cross-platform |
| `stix2` | `python -c "import stix2; print(stix2.v21.Indicator(pattern=\"[ipv4-addr:value = '203.0.113.44']\"))"` | Construct validated indicators rather than hand-written JSON | Cross-platform |
| `misp` | `curl -s -H "Authorization: $KEY" $MISP/attributes/restSearch -d '{"type":"ip-dst"}'` | Pull stored attributes with context | Cross-platform |
| `jq` | `jq 'group_by(.value)' indicators.json` | Find duplicates and source disagreement | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, collections

recs = [json.loads(l) for l in open("indicators.jsonl")]
by_value = collections.defaultdict(list)
for r in recs:
    by_value[r["value"]].append(r)

multi = {v: rs for v, rs in by_value.items() if len({r["source"] for r in rs}) > 1}
print("records:", len(recs), "observables:", len(by_value), "multi-source:", len(multi))
for v, rs in list(multi.items())[:5]:
    firsts = sorted(r["first_seen"] for r in rs)
    print(v, "sources:", [r["source"] for r in rs], "earliest:", firsts[0])

unobserved = [r for r in recs if "observed_in_estate" not in r]
print("records missing the observation join:", len(unobserved))
```

## Verification

- Multi-source observables show their earliest first-seen, which is the decay input.
- Records missing the observation join are enumerated, so enrichment gaps are visible rather than silent zeros.
- Grouping by value never merges campaigns, because the grouping key is the observable and the relationships stay attached.
