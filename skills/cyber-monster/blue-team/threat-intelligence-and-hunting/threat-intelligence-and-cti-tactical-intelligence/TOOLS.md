# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-intelligence-and-cti-tactical-intelligence`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mitreattack-python` | `d.get_object_by_attack_id('T1218.011', 'attack-pattern')` | Confirm the sub-technique and its current tactics | Cross-platform |
| `siem` | `index=sysmon EventCode=1 Image=*rundll32.exe` with `stats count by ParentImage` | Baseline frequency for a proxy-execution observable | Cross-platform |
| `sigma` | `sigma list rules/ --filter 'tags=T1218.011'` | Existing coverage for the technique before writing a new rule | Cross-platform |
| `jq` | `jq '.objects[]' enterprise-attack.json` | Offline ATT&CK queries when the API is unavailable | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, collections

# Baseline frequency for a tactical observable before recommending a detection.
rows = [json.loads(l) for l in open("sysmon-proc.jsonl")]
proxy = [r for r in rows if r["image"].lower().endswith("\\rundll32.exe")]
by_parent = collections.Counter(r["parent_image"].lower().rsplit("\\", 1)[-1] for r in proxy)
print("rundll32 executions:", len(proxy))
for parent, n in by_parent.most_common(8):
    print(f"  parent={parent:20} count={n}")

office = [r for r in proxy if r["parent_image"].lower().rsplit("\\", 1)[-1] in
          ("excel.exe", "winword.exe")]
print("office-parent rundll32 (tactical observable):", len(office))
print("verdict:", "detectable" if not office else "review existing benign instances")
```

## Verification

- The parent histogram shows whether the observable is ubiquitous, which decides detectability.
- Office-parent hits are counted separately, matching the TTP's scope rather than the whole binary.
- A technique with zero baseline instances prints `detectable`, which is the recommendation the product carries.
