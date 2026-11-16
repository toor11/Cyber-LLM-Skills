# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cryptocurrency-and-onchain-tracing-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `cryptocurrency-and-onchain-tracing-osint`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Transaction read with block height

Baseline: the transaction hash. Probe: the receipt and its logs. Differential: a log entry naming the recipient is the evidence for the next hop.

```bash
cast receipt 0xaaa --rpc-url $RPC
cast logs --address 0xBRIDGE --from-block 19000000 --to-block 19000100 --rpc-url $RPC
```

## Co-spend input listing

Baseline: one input address. Probe: all input addresses of the same transaction. Differential: inputs co-spent in one transaction indicate common control at signing time.

```bash
cast tx 0xaaa --rpc-url $RPC | head -40
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
