# Detection Signals and Blue-Team Handoff

> Sub-skill: [`foundry-and-echidna-invariant-harness-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Forge/Anvil RPC traffic on a local port with no corresponding deployed environment, indicating a local fork campaign.
- Long-lived `forge test` processes with high CPU and repeated state snapshots on a developer host.
- Corpus directory creation under a repository working tree, which is a committed-artefact risk in CI.
- Invariant failure artefacts (`.failures`) written outside the CI artefact path.
- Anvil `eth_sendTransaction` bursts from a single account with sequential nonces and no user-facing session.
- CI jobs invoking `forge test --match-contract Invariant` on a fork URL pointing at a production RPC endpoint.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md) | Query authoring, triage, and hardening |
