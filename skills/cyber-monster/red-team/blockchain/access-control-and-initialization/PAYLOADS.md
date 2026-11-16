# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`access-control-and-initialization`](SKILL.md) | Family: **Blockchain**

Probes for `access-control-and-initialization`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Unauthorised call per privileged function

Baseline: the privileged call from the authorised address must succeed. Probe: the same call from an unauthorised address must revert. Differential: a success in the probe is the finding.

```solidity
vm.prank(unauthorised);
vm.expectRevert();
vault.setFee(1);
```

## Initialiser state

Baseline: the implementation's initialiser, which must revert. Probe: the proxy's initialiser after deployment, which must also revert. Differential: a success in either is the finding.

```bash
cast call $IMPL 'initialize(address)' $ATTACKER --rpc-url $RPC
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
