# Verification Probes and Expected Differentials

> Sub-skill: [`container-escape-privileged-and-capabilities`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Effective capability read

```text
# What does the process actually hold?
capsh --print 2>/dev/null | rg -A2 "Current:"
awk '/CapEff|CapBnd|CapPrm/ {print}' /proc/self/status
getcap -r / 2>/dev/null | head -20
```

Expected differential: `CapEff: 0000000000000000` with an empty `getcap` list is the control; a non-zero `CapEff` decoding to `cap_sys_admin` or `cap_dac_read_search` is the finding, and `getcap` output names the binary that carries it.

## Class 2 — Capability-to-operation probe

```text
# Does the capability enable a host read? Read-only, lab container only.
head -c 64 /etc/shadow 2>&1 | head -1
mount | rg -c "^/dev" 2>/dev/null
```

Expected differential: `Permission denied` proves DAC still applies, so `DAC_READ_SEARCH` is absent and the finding is weaker; a successful read or a mount listing means the capability is operative.

## Class 3 — Re-addition audit

```text
kubectl get pods -A -o json | jq -r '  # container-escape-privileged-and-capabilities: class 3 readdition audit
  .items[] | select([.spec.containers[]?.securityContext.capabilities.add[]?] | length > 0)
  | "\(.metadata.namespace)/\(.metadata.name) adds=\([.spec.containers[].securityContext.capabilities.add[]?]|join(","))"'
```

Expected differential: an empty result means no manifest adds capabilities; `add=SYS_ADMIN` or `add=SYS_PTRACE` is the finding, and a container with no additions can still carry file capabilities from the image, so Class 1 remains necessary.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
