# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`idapython-automation-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `idapython-automation-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Call-site inventory

Baseline: xrefs to the symbol in the reference database. Probe: the same in the shipped database. Differential: a new call site present only in shipped.

```python
ida_auto.auto_wait()
target = idc.get_name_ea_simple('memcpy')
print([hex(x.frm) for x in idautils.XrefsTo(target, 0)][:20])
```

## Global writer triage

Baseline: writers to the global before the patch. Probe: writers after. Differential: a new writer outside the module that owns the global.

```python
g = idc.get_name_ea_simple('g_state')
print([hex(x.frm) for x in idautils.XrefsTo(g, 0) if idc.get_segm_name(x.frm) == '.text'])
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
