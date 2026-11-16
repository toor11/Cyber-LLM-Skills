# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web3-infrastructure-and-rpc`](SKILL.md) | Family: **Blockchain**

Probes for `web3-infrastructure-and-rpc`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Namespace probe without state change

Baseline: `eth_chainId`, which any endpoint answers. Probe: `eth_accounts` and `admin_nodeInfo`. Differential: a non-empty account list or a successful admin call is the exposure.

```bash
cast rpc eth_chainId --rpc-url $RPC
cast rpc eth_accounts --rpc-url $RPC
cast rpc admin_nodeInfo --rpc-url $RPC
```

## Front-end dependency origin

Baseline: first-party script origins. Probe: third-party origins and integrity attributes. Differential: a mutable third-party script without integrity is the finding.

```bash
curl -sS https://dapp.example/ | grep -oE '<script[^>]+src="[^"]+"' | head -10
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
