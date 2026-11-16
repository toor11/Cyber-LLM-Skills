# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`bridge-and-cross-chain`](SKILL.md) | Family: **Blockchain**

Probes for `bridge-and-cross-chain`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Replay attempt

Baseline: the first submission succeeds. Probe: the identical submission again. Differential: a second success means no processed record is checked.

```bash
cast send $BRIDGE 'release(bytes32,address,uint256,bytes[])' $ID $TO 1ether "[$SIG]" --rpc-url $RPC
cast send $BRIDGE 'release(bytes32,address,uint256,bytes[])' $ID $TO 1ether "[$SIG]" --rpc-url $RPC
```

## Wrong source domain

Baseline: a message signed for this source chain. Probe: the same signature with the source chain id changed. Differential: acceptance means the digest does not cover the source domain.

```bash
cast call $BRIDGE 'sourceChainId()(uint256)' --rpc-url $RPC
cast keccak $(cast abi-encode 'f(uint256,address,bytes32,address,uint256)' 1 $BRIDGE $ID $TO 1)
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
