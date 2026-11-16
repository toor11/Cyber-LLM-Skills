# Verification Probes and Expected Differentials

> Sub-skill: [`matter-protocol-commissioning-and-fabric-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Attestation path inventory

```text
rg -n --no-heading "DeviceAttestationVerifier|testAllowAll|prodDacVerifier|DclRoots|CertificationDeclaration" src/ | head -20
rg -n --no-heading "cdVendorIdCheck|vid|pid" src/commissioner/ | head -10
```

Expected differential: a production verifier with DCL roots and a CD VID/PID check is the control; `testAllowAllAttestationVerifier` is the finding, and the line is the citation.

## Class 2 — ACL review

```text
# Dump the ACL entries with privilege and auth mode.
chip-tool accesscontrol read acl 1 0 0x0000
# And the group key mappings in use.
chip-tool groupkeymanagement read group-keys 1 0
```

Expected differential: a `kAdminister` entry with `kGroup` auth is the escalation; `kOperate` with `kCase` is the control, and the endpoint number tells you the scope.

## Class 3 — Window duration

```text
# Open a window with the documented timeout and confirm it closes.
chip-tool pairing open-commissioning-window <node> 1 300 1000 3840
sleep 320
chip-tool pairing code-wifi <node> <ssid> <pw> 20202021   # should be refused
```

Expected differential: a refused commission after the timeout is the control; an accepted commission means the window does not expire, which is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
