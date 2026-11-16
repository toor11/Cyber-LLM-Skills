# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-hunting-hunt-execution-and-triage`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `jq` | `jq -s 'group_by(.host)' events.json` | Cluster raw output by host before reading | Cross-platform |
| `siem` | `index=win EventCode=1` with `stats count by host, parent_image` | Parent-level clustering at query time | Cross-platform |
| `velociraptor` | `velociraptor query --format json 'SELECT Pid, Ppid, Name, CommandLine FROM pslist()'` | Endpoint process tree for an escalating cluster | Cross-platform |
| `sigma` | `sigma convert -t splunk rule.yml` | Re-run the candidate rule against the window to confirm it reproduces | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, collections

events = [json.loads(l) for l in open("hunt-hits.jsonl")]
def key(e):
    return (e.get("host"), e.get("parent_image"))

clusters = collections.defaultdict(list)
for e in events:
    clusters[key(e)].append(e)

base = collections.Counter()
for line in open("baseline-hits.jsonl"):
    e = json.loads(line)
    base[key(e)] += 1

print("clusters:", len(clusters))
for k, rows in sorted(clusters.items(), key=lambda kv: -len(kv[1]))[:8]:
    hosts = {r["host"] for r in rows}
    print(f"{k[0]:28} parent={k[1]:24} events={len(rows):5} hosts={len(hosts):4} baseline={base[k]}")
```

## Verification

- Every cluster prints its baseline count, which is the number that decides benign versus new.
- Host counts are shown alongside event counts, so a single noisy host is distinguishable from an estate-wide artefact.
- Re-running with the exclusion list applied removes the patch-manager cluster, proving the baseline extension works.
