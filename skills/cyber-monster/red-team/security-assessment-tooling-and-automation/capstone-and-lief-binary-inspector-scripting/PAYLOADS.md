# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`capstone-and-lief-binary-inspector-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `capstone-and-lief-binary-inspector-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Mitigation inventory

Baseline: the reference build's flags. Probe: the shipped build's flags. Differential: a flag present in reference and absent here is the reportable gap.

```python
import lief
b = lief.parse("app.exe")
print(b.header.machine_type, hex(b.optional_header.imagebase))
print("nx", b.has_nx, "pie", b.is_pie)
```

## Import triage for a dangerous symbol

Baseline: imports of the reference build. Probe: imports of the shipped build. Differential: a new dangerous import that no reference build has.

```python
import lief
syms = {f.name for f in lief.parse("shipped.exe").imported_functions}
ref = {f.name for f in lief.parse("reference.exe").imported_functions}
print(sorted(syms - ref))
```

## Bounded disassembly of one symbol

Baseline: the symbol size from the table. Probe: the decoded instructions inside that range. Differential: any instruction outside the stated range means the bound was wrong.

```python
import capstone, lief
b = lief.parse("app.exe")
f = next(s for s in b.symbols if s.name == "parse_record")
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
print(len(list(md.disasm(bytes(b.get_content_from_virtual_address(f.value, f.size)), f.value))))
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
