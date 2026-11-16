# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`eip712-signature-replay-and-account-abstraction`](SKILL.md) | Family: **Blockchain**

Probes for `eip712-signature-replay-and-account-abstraction`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Replay attempt

Baseline: the signature used once, which must succeed. Probe: the identical calldata again. Differential: a second success means the nonce is not consumed.

```bash
cast send $FORWARDER 'execute(address,uint256,uint256,bytes)' $TO 1 $NONCE $SIG --rpc-url $RPC
cast send $FORWARDER 'execute(address,uint256,uint256,bytes)' $TO 1 $NONCE $SIG --rpc-url $RPC
```

## Relayer-controlled field

Baseline: the signed recipient. Probe: a different recipient with the same signature. Differential: acceptance means the recipient is outside the digest.

```bash
cast call $FORWARDER 'DOMAIN_SEPARATOR()(bytes32)' --rpc-url $RPC
cast send $FORWARDER 'execute(address,uint256,uint256,bytes)' $OTHER 1 $NONCE $SIG --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
